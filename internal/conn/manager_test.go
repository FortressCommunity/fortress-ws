package conn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newTestConn(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := &websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.Close()
	}))
	clientConn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http"),
		nil,
	)
	if err != nil {
		server.Close()
		t.Fatalf("Dial() error = %v", err)
	}
	return clientConn, nil, server.Close
}

func TestRegisterAndCount(t *testing.T) {
	mgr := NewConnectionManager(10, 30*time.Second)
	if mgr.Count() != 0 {
		t.Errorf("initial count = %d, want 0", mgr.Count())
	}

	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	if err := mgr.Register("conn-1", conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}
}

func TestUnregister(t *testing.T) {
	mgr := NewConnectionManager(10, 30*time.Second)
	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	mgr.Register("conn-1", conn)
	mgr.Unregister("conn-1")
	if mgr.Count() != 0 {
		t.Errorf("count = %d, want 0 after unregister", mgr.Count())
	}
}

func TestMaxConnsReached(t *testing.T) {
	mgr := NewConnectionManager(1, 30*time.Second)

	conn1, _, cleanup1 := newTestConn(t)
	defer cleanup1()

	conn2, _, cleanup2 := newTestConn(t)
	defer cleanup2()

	if err := mgr.Register("conn-1", conn1); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := mgr.Register("conn-2", conn2); err != ErrMaxConnsReached {
		t.Errorf("Register() error = %v, want %v", err, ErrMaxConnsReached)
	}
}

func TestGet(t *testing.T) {
	mgr := NewConnectionManager(10, 30*time.Second)
	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	mgr.Register("conn-1", conn)
	mc := mgr.Get("conn-1")
	if mc == nil {
		t.Fatal("Get() returned nil")
	}
	if mc.ID != "conn-1" {
		t.Errorf("Get() ID = %q, want %q", mc.ID, "conn-1")
	}

	mc2 := mgr.Get("nonexistent")
	if mc2 != nil {
		t.Errorf("Get() for nonexistent returned non-nil")
	}
}

func TestShutdown(t *testing.T) {
	mgr := NewConnectionManager(10, 30*time.Second)
	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	mgr.Register("conn-1", conn)
	ctx := context.Background()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
	if mgr.Count() != 0 {
		t.Errorf("count after shutdown = %d, want 0", mgr.Count())
	}
}

func TestCloseIdle(t *testing.T) {
	mgr := NewConnectionManager(10, 1*time.Millisecond)
	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	mgr.Register("conn-1", conn)
	time.Sleep(10 * time.Millisecond)
	mgr.CloseIdle(context.Background())
	if mgr.Count() != 0 {
		t.Errorf("count after CloseIdle = %d, want 0", mgr.Count())
	}
}

func TestList(t *testing.T) {
	mgr := NewConnectionManager(10, 30*time.Second)
	conn, _, cleanup := newTestConn(t)
	defer cleanup()

	mgr.Register("conn-1", conn)
	list := mgr.List()
	if len(list) != 1 {
		t.Errorf("List() len = %d, want 1", len(list))
	}
	if list[0].ID != "conn-1" {
		t.Errorf("List()[0].ID = %q, want %q", list[0].ID, "conn-1")
	}
}
