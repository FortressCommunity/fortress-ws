package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/fortress-ws/fortress-ws/pkg/proto/gen"
)

var version = "v0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:   "fortress-ctl",
		Short: "Fortress WebSocket Security Toolkit CLI",
	}

	rootCmd.AddCommand(newConnectCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newBenchCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("command error: %v", err)
	}
}

func newConnectCmd() *cobra.Command {
	var addr, token string

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Open a WebSocket connection and print incoming frames",
		Run: func(cmd *cobra.Command, args []string) {
			header := make(map[string][]string)
			if token != "" {
				header["Authorization"] = []string{"Bearer " + token}
			}

			dialer := &websocket.Dialer{
				HandshakeTimeout: 10 * time.Second,
			}
			conn, _, err := dialer.Dial(addr, header)
			if err != nil {
				log.Fatalf("dial error: %v", err)
			}
			defer conn.Close()

			fmt.Printf("connected to %s\n", addr)

			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					_, msg, err := conn.ReadMessage()
					if err != nil {
						return
					}
					fmt.Printf("frame: %s\n", string(msg))
				}
			}()

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			<-done
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "ws://localhost:8443/ws", "WebSocket server address")
	cmd.Flags().StringVar(&token, "token", "", "JWT bearer token")
	return cmd
}

func newScanCmd() *cobra.Command {
	var file, grpcAddr string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Replay frames from a WS capture file through the scanner gRPC",
		Run: func(cmd *cobra.Command, args []string) {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				log.Fatalf("read file error: %v", err)
			}

			var frames []struct {
				Payload string `json:"payload"`
				Opcode  uint32 `json:"opcode"`
			}
			if err := json.Unmarshal(data, &frames); err != nil {
				log.Fatalf("parse frames error: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := grpc.DialContext(ctx, grpcAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				log.Fatalf("gRPC dial error: %v", err)
			}
			defer conn.Close()

			client := pb.NewScannerServiceClient(conn)

			for i, f := range frames {
				resp, err := client.ScanFrame(ctx, &pb.ScanRequest{
					Payload:  []byte(f.Payload),
					Opcode:   f.Opcode,
					IsMasked: false,
				})
				if err != nil {
					log.Printf("frame %d scan error: %v", i, err)
					continue
				}
				fmt.Printf("frame %d: threat=%v type=%q confidence=%.2f\n",
					i, resp.IsThreat, resp.ThreatType, resp.Confidence)
			}
		},
	}

	cmd.Flags().StringVar(&file, "file", "", "Path to WS capture JSON file")
	cmd.Flags().StringVar(&grpcAddr, "grpc-addr", "localhost:50051", "Scanner gRPC address")
	cmd.MarkFlagRequired("file")
	return cmd
}

func newBenchCmd() *cobra.Command {
	var addr, token string
	var rate int
	var duration time.Duration

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Run a simple throughput benchmark against a WebSocket server",
		Run: func(cmd *cobra.Command, args []string) {
			header := make(map[string][]string)
			if token != "" {
				header["Authorization"] = []string{"Bearer " + token}
			}

			conn, _, err := websocket.DefaultDialer.Dial(addr, header)
			if err != nil {
				log.Fatalf("dial error: %v", err)
			}
			defer conn.Close()

			fmt.Printf("benchmarking %s (rate=%d/s, duration=%v)\n", addr, rate, duration)

			var sent int64
			ticker := time.NewTicker(time.Second / time.Duration(rate))
			timeout := time.After(duration)
			done := make(chan struct{})

			go func() {
				for {
					_, _, err := conn.ReadMessage()
					if err != nil {
						return
					}
				}
			}()

			go func() {
				for range ticker.C {
					msg := []byte("benchmark-payload")
					if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
						return
					}
					atomic.AddInt64(&sent, 1)
				}
			}()

			<-timeout
			ticker.Stop()
			close(done)

			total := atomic.LoadInt64(&sent)
			elapsed := duration.Seconds()
			fmt.Printf("sent %d messages in %.2fs (%.1f msg/s)\n", total, elapsed, float64(total)/elapsed)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "ws://localhost:8443/ws", "WebSocket server address")
	cmd.Flags().StringVar(&token, "token", "", "JWT bearer token")
	cmd.Flags().IntVar(&rate, "rate", 100, "Messages per second")
	cmd.Flags().DurationVar(&duration, "duration", 10*time.Second, "Benchmark duration")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fortress-ctl %s\n", version)
		},
	}
}
