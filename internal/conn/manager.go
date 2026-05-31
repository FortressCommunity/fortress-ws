package conn

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var ErrMaxConnsReached = errors.New("maximum connections reached")

// ManagedConn wraps a WebSocket connection with metadata.
type ManagedConn struct {
	ID       string
	Conn     *websocket.Conn
	LastSeen time.Time
	addr     string
}

// ConnectionManager manages active WebSocket connections with concurrency safety.
type ConnectionManager struct {
	mu          sync.RWMutex
	conns       map[string]*ManagedConn
	maxConns    int
	idleTimeout time.Duration
}

// NewConnectionManager creates a new connection manager with the given limits.
func NewConnectionManager(maxConns int, idleTimeout time.Duration) *ConnectionManager {
	return &ConnectionManager{
		conns:       make(map[string]*ManagedConn),
		maxConns:    maxConns,
		idleTimeout: idleTimeout,
	}
}

// Register adds a new connection under the given ID. Returns ErrMaxConnsReached if at capacity.
func (m *ConnectionManager) Register(id string, conn *websocket.Conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.conns) >= m.maxConns {
		return ErrMaxConnsReached
	}

	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}

	m.conns[id] = &ManagedConn{
		ID:       id,
		Conn:     conn,
		LastSeen: time.Now(),
		addr:     remoteAddr,
	}
	return nil
}

// Unregister removes a connection by ID.
func (m *ConnectionManager) Unregister(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns, id)
}

// Count returns the number of active connections.
func (m *ConnectionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.conns)
}

// Get returns a connection by ID, or nil if not found.
func (m *ConnectionManager) Get(id string) *ManagedConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.conns[id]
}

// List returns a snapshot of all active connections.
func (m *ConnectionManager) List() []ManagedConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]ManagedConn, 0, len(m.conns))
	for _, mc := range m.conns {
		list = append(list, *mc)
	}
	return list
}

// Broadcast sends a message to every active connection. Errors on individual connections are logged but not returned.
func (m *ConnectionManager) Broadcast(ctx context.Context, msg []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for id, mc := range m.conns {
		if err := mc.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			errs = append(errs, err)
		}
		mc.LastSeen = time.Now()
		_ = id
	}
	return errors.Join(errs...)
}

// CloseIdle closes connections that have been idle longer than the configured timeout.
func (m *ConnectionManager) CloseIdle(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, mc := range m.conns {
		if now.Sub(mc.LastSeen) > m.idleTimeout {
			mc.Conn.Close()
			delete(m.conns, id)
		}
	}
}

// Shutdown gracefully closes all connections with a deadline from ctx.
func (m *ConnectionManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for id, mc := range m.conns {
		if err := mc.Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(m.conns, id)
	}
	return errors.Join(errs...)
}

// RemoteAddrStr returns the remote address of the websocket connection, or empty string.
func (mc *ManagedConn) RemoteAddrStr() string {
	if mc.Conn != nil && mc.Conn.RemoteAddr() != nil {
		return mc.Conn.RemoteAddr().String()
	}
	return mc.addr
}

// Network implements the net.Addr interface for ManagedConn.
func (mc *ManagedConn) Network() string {
	return "websocket"
}

func (mc *ManagedConn) String() string {
	return mc.RemoteAddrStr()
}

var _ net.Addr = (*ManagedConn)(nil)
