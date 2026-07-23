package wsengine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

const maxFrameBytes = 8 * 1024 * 1024

type EmitFunc func(name string, data any)

type ConnectOptions struct {
	ProjectID         string            `json:"project_id"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Origin            string            `json:"origin"`
	Cookies           string            `json:"cookies"`
	Subprotocols      []string          `json:"subprotocols"`
	TimeoutMS         int               `json:"timeout_ms"`
	ReconnectAttempts int               `json:"reconnect_attempts"`
	TLSSkipVerify     bool              `json:"tls_skip_verify"`
	CustomCAPEM       string            `json:"custom_ca_pem"`
}

type SendOptions struct {
	ConnectionID  string `json:"connection_id"`
	MessageType   string `json:"message_type"`
	Payload       string `json:"payload"`
	PayloadBase64 string `json:"payload_base64"`
}

type managedConnection struct {
	id        string
	projectID string
	options   ConnectOptions
	conn      *websocket.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	writeMu   sync.Mutex
	intercept bool
	inbound   chan inboundFrame
}

type inboundFrame struct {
	messageType websocket.MessageType
	payload     []byte
}

type pendingFrame struct {
	id           string
	connectionID string
	messageType  websocket.MessageType
	payload      []byte
}

type Manager struct {
	store   *store.Store
	emit    EmitFunc
	mu      sync.RWMutex
	items   map[string]*managedConnection
	pending map[string]pendingFrame
	closed  bool
}

func New(database *store.Store, emit EmitFunc) *Manager {
	return &Manager{store: database, emit: emit, items: map[string]*managedConnection{}, pending: map[string]pendingFrame{}}
}

func (m *Manager) Connect(parent context.Context, options ConnectOptions) (map[string]any, error) {
	if m.isClosed() {
		return nil, errors.New("WebSocket manager is closed")
	}
	parsed, err := url.Parse(strings.TrimSpace(options.URL))
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" {
		return nil, errors.New("target must be an absolute ws:// or wss:// URL")
	}
	if options.ProjectID == "" {
		return nil, errors.New("project_id is required")
	}
	timeout := boundedDuration(options.TimeoutMS, 10*time.Second, 1*time.Second, 60*time.Second)
	ctx, cancelDial := context.WithTimeout(parent, timeout)
	defer cancelDial()
	header := make(http.Header)
	for key, value := range options.Headers {
		if !validHeader(key, value) {
			return nil, fmt.Errorf("invalid WebSocket header %q", key)
		}
		header.Set(key, value)
	}
	if options.Origin != "" {
		header.Set("Origin", options.Origin)
	}
	if options.Cookies != "" {
		header.Set("Cookie", options.Cookies)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.TLSSkipVerify} // #nosec G402 -- explicit operator-controlled lab option.
	if options.CustomCAPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(options.CustomCAPEM)) {
			return nil, errors.New("custom_ca_pem contains no valid certificate")
		}
		tlsConfig.RootCAs = pool
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}, Timeout: timeout}
	connection, response, err := websocket.Dial(ctx, options.URL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header, Subprotocols: options.Subprotocols, CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		return nil, fmt.Errorf("WebSocket handshake failed (HTTP %d): %w", status, err)
	}
	connection.SetReadLimit(maxFrameBytes)
	connectionID := newConnectionID()
	readCtx, cancel := context.WithCancel(context.Background())
	managed := &managedConnection{id: connectionID, projectID: options.ProjectID, options: options, conn: connection, ctx: readCtx, cancel: cancel, inbound: make(chan inboundFrame, 64)}
	m.mu.Lock()
	m.items[connectionID] = managed
	m.mu.Unlock()
	metadata := map[string]any{"url": options.URL, "status": "connected", "headers": options.Headers, "origin": options.Origin, "subprotocol": connection.Subprotocol(), "tls_skip_verify": options.TLSSkipVerify}
	_, err = m.store.SaveEntity(context.Background(), "ws_connections", store.Entity{ID: connectionID, ProjectID: options.ProjectID, Name: options.URL, Value: "connected", Metadata: metadata})
	if err != nil {
		cancel()
		connection.CloseNow()
		m.remove(connectionID)
		return nil, err
	}
	result := map[string]any{"connection_id": connectionID, "url": options.URL, "subprotocol": connection.Subprotocol(), "status": "connected"}
	m.emit("ws.connected", result)
	go m.readLoop(managed)
	return result, nil
}

func (m *Manager) Send(ctx context.Context, options SendOptions) (map[string]any, error) {
	connection, err := m.connection(options.ConnectionID)
	if err != nil {
		return nil, err
	}
	messageType, payload, err := decodePayload(options.MessageType, options.Payload, options.PayloadBase64)
	if err != nil {
		return nil, err
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if connection.intercept {
		pending := pendingFrame{id: newConnectionID(), connectionID: connection.id, messageType: messageType, payload: payload}
		m.mu.Lock()
		m.pending[pending.id] = pending
		m.mu.Unlock()
		m.emit("ws.intercepted", frameEvent(pending.id, connection, "outbound", messageType, payload, true))
		return map[string]any{"queued": true, "intercept_id": pending.id}, nil
	}
	if err := connection.conn.Write(ctx, messageType, payload); err != nil {
		return nil, fmt.Errorf("send WebSocket frame: %w", err)
	}
	frame, err := m.recordFrame(connection, "outbound", messageType, payload, false)
	if err == nil {
		m.emit("ws.frame", frame)
	}
	return frame, err
}

func (m *Manager) Replay(ctx context.Context, connectionID, frameID string) (map[string]any, error) {
	entity, err := m.store.GetEntity(ctx, "ws_frames", frameID)
	if err != nil {
		return nil, err
	}
	messageType, _ := entity.Metadata["message_type"].(string)
	options := SendOptions{ConnectionID: connectionID, MessageType: messageType}
	if encoding, _ := entity.Metadata["encoding"].(string); encoding == "base64" {
		options.PayloadBase64 = entity.Value
	} else {
		options.Payload = entity.Value
	}
	return m.Send(ctx, options)
}

func (m *Manager) Probe(ctx context.Context, options SendOptions) (map[string]any, error) {
	connection, err := m.connection(options.ConnectionID)
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-connection.inbound:
			continue
		default:
			goto drained
		}
	}
drained:
	request, err := m.Send(ctx, options)
	if err != nil {
		return nil, err
	}
	select {
	case frame := <-connection.inbound:
		return map[string]any{"request": request, "response": frameEvent("", connection, "inbound", frame.messageType, frame.payload, false)}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for WebSocket response: %w", ctx.Err())
	}
}

func (m *Manager) Race(ctx context.Context, options SendOptions, count int) (map[string]any, error) {
	connection, err := m.connection(options.ConnectionID)
	if err != nil {
		return nil, err
	}
	if count <= 0 {
		count = 5
	}
	if count > 50 {
		count = 50
	}
	for {
		select {
		case <-connection.inbound:
			continue
		default:
			goto drained
		}
	}
drained:
	messageType, payload, err := decodePayload(options.MessageType, options.Payload, options.PayloadBase64)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	var wait sync.WaitGroup
	errorsFound := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if writeErr := connection.conn.Write(ctx, messageType, payload); writeErr != nil {
				errorsFound <- writeErr
				return
			}
			if frame, recordErr := m.recordFrame(connection, "outbound", messageType, payload, false); recordErr != nil {
				errorsFound <- recordErr
			} else {
				m.emit("ws.frame", frame)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for writeErr := range errorsFound {
		if writeErr != nil {
			return nil, writeErr
		}
	}
	responses := make([]map[string]any, 0, count)
	for len(responses) < count {
		select {
		case frame := <-connection.inbound:
			responses = append(responses, frameEvent("", connection, "inbound", frame.messageType, frame.payload, false))
		case <-ctx.Done():
			return map[string]any{"sent": count, "received": len(responses), "responses": responses, "duration_ms": time.Since(started).Milliseconds()}, ctx.Err()
		}
	}
	return map[string]any{"sent": count, "received": len(responses), "responses": responses, "duration_ms": time.Since(started).Milliseconds()}, nil
}

func (m *Manager) SetIntercept(connectionID string, enabled bool) (map[string]any, error) {
	connection, err := m.connection(connectionID)
	if err != nil {
		return nil, err
	}
	connection.writeMu.Lock()
	connection.intercept = enabled
	connection.writeMu.Unlock()
	return map[string]any{"connection_id": connectionID, "enabled": enabled}, nil
}

func (m *Manager) InterceptAction(ctx context.Context, interceptID, action, replacement, replacementBase64 string) (map[string]any, error) {
	m.mu.Lock()
	pending, ok := m.pending[interceptID]
	if ok {
		delete(m.pending, interceptID)
	}
	m.mu.Unlock()
	if !ok {
		return nil, errors.New("intercepted frame was not found")
	}
	if action == "drop" {
		m.emit("ws.intercept.resolved", map[string]any{"intercept_id": interceptID, "action": "drop"})
		return map[string]any{"dropped": true}, nil
	}
	if action != "forward" && action != "modify" {
		return nil, errors.New("action must be forward, modify, or drop")
	}
	payload := pending.payload
	if action == "modify" {
		var err error
		_, payload, err = decodePayload(messageTypeName(pending.messageType), replacement, replacementBase64)
		if err != nil {
			return nil, err
		}
	}
	connection, err := m.connection(pending.connectionID)
	if err != nil {
		return nil, err
	}
	connection.writeMu.Lock()
	err = connection.conn.Write(ctx, pending.messageType, payload)
	connection.writeMu.Unlock()
	if err != nil {
		return nil, err
	}
	frame, err := m.recordFrame(connection, "outbound", pending.messageType, payload, false)
	if err == nil {
		m.emit("ws.frame", frame)
	}
	return frame, err
}

func (m *Manager) Disconnect(connectionID string) error {
	connection, err := m.connection(connectionID)
	if err != nil {
		return err
	}
	connection.cancel()
	_ = connection.conn.Close(websocket.StatusNormalClosure, "operator disconnect")
	m.remove(connectionID)
	m.updateConnection(connection, "disconnected", "")
	m.emit("ws.disconnected", map[string]any{"connection_id": connectionID, "reason": "operator disconnect"})
	return nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	connections := make([]*managedConnection, 0, len(m.items))
	for _, connection := range m.items {
		connections = append(connections, connection)
	}
	m.items = map[string]*managedConnection{}
	m.pending = map[string]pendingFrame{}
	m.mu.Unlock()
	for _, connection := range connections {
		connection.cancel()
		connection.conn.CloseNow()
	}
}

func (m *Manager) readLoop(connection *managedConnection) {
	for {
		messageType, payload, err := connection.conn.Read(connection.ctx)
		if err != nil {
			if connection.ctx.Err() == nil {
				m.emit("ws.error", map[string]any{"connection_id": connection.id, "message": err.Error()})
				m.tryReconnect(connection)
			}
			m.remove(connection.id)
			m.updateConnection(connection, "disconnected", err.Error())
			return
		}
		frame, recordErr := m.recordFrame(connection, "inbound", messageType, payload, false)
		if recordErr != nil {
			m.emit("ws.error", map[string]any{"connection_id": connection.id, "message": recordErr.Error()})
			continue
		}
		copyPayload := append([]byte(nil), payload...)
		select {
		case connection.inbound <- inboundFrame{messageType: messageType, payload: copyPayload}:
		default:
		}
		m.emit("ws.frame", frame)
	}
}

func (m *Manager) tryReconnect(connection *managedConnection) {
	for attempt := 1; attempt <= connection.options.ReconnectAttempts; attempt++ {
		select {
		case <-connection.ctx.Done():
			return
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
		m.emit("ws.reconnecting", map[string]any{"connection_id": connection.id, "attempt": attempt})
		// Reconnection is intentionally surfaced as a new connection so frame provenance remains immutable.
		if _, err := m.Connect(connection.ctx, connection.options); err == nil {
			return
		}
	}
}

func (m *Manager) recordFrame(connection *managedConnection, direction string, messageType websocket.MessageType, payload []byte, intercepted bool) (map[string]any, error) {
	encoding := "utf8"
	value := string(payload)
	if messageType == websocket.MessageBinary {
		encoding = "base64"
		value = base64.StdEncoding.EncodeToString(payload)
	}
	metadata := map[string]any{"connection_id": connection.id, "direction": direction, "message_type": messageTypeName(messageType), "encoding": encoding, "size": len(payload), "intercepted": intercepted}
	entity, err := m.store.SaveEntity(context.Background(), "ws_frames", store.Entity{ProjectID: connection.projectID, Name: direction, Value: value, Metadata: metadata})
	if err != nil {
		return nil, err
	}
	return frameEvent(entity.ID, connection, direction, messageType, payload, intercepted), nil
}

func frameEvent(id string, connection *managedConnection, direction string, messageType websocket.MessageType, payload []byte, intercepted bool) map[string]any {
	result := map[string]any{"id": id, "connection_id": connection.id, "project_id": connection.projectID, "direction": direction, "message_type": messageTypeName(messageType), "size": len(payload), "intercepted": intercepted}
	if messageType == websocket.MessageBinary {
		result["payload_base64"] = base64.StdEncoding.EncodeToString(payload)
		result["encoding"] = "base64"
	} else {
		result["payload"] = string(payload)
		result["encoding"] = "utf8"
	}
	return result
}

func (m *Manager) updateConnection(connection *managedConnection, status, detail string) {
	metadata := map[string]any{"url": connection.options.URL, "status": status, "detail": detail}
	if current, err := m.store.GetEntity(context.Background(), "ws_connections", connection.id); err == nil {
		for key, value := range current.Metadata {
			metadata[key] = value
		}
		metadata["status"] = status
		metadata["detail"] = detail
	}
	_, _ = m.store.SaveEntity(context.Background(), "ws_connections", store.Entity{ID: connection.id, ProjectID: connection.projectID, Name: connection.options.URL, Value: status, Metadata: metadata})
}

func (m *Manager) connection(id string) (*managedConnection, error) {
	m.mu.RLock()
	connection := m.items[id]
	m.mu.RUnlock()
	if connection == nil {
		return nil, errors.New("WebSocket connection was not found")
	}
	return connection, nil
}

func (m *Manager) remove(id string) { m.mu.Lock(); delete(m.items, id); m.mu.Unlock() }
func (m *Manager) isClosed() bool   { m.mu.RLock(); defer m.mu.RUnlock(); return m.closed }

func decodePayload(kind, text, encoded string) (websocket.MessageType, []byte, error) {
	if strings.EqualFold(kind, "binary") {
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return 0, nil, errors.New("binary payload must use payload_base64")
		}
		if len(payload) > maxFrameBytes {
			return 0, nil, errors.New("frame exceeds 8 MiB limit")
		}
		return websocket.MessageBinary, payload, nil
	}
	payload := []byte(text)
	if len(payload) > maxFrameBytes {
		return 0, nil, errors.New("frame exceeds 8 MiB limit")
	}
	return websocket.MessageText, payload, nil
}

func messageTypeName(kind websocket.MessageType) string {
	if kind == websocket.MessageBinary {
		return "binary"
	}
	return "text"
}
func validHeader(key, value string) bool {
	return key != "" && !strings.ContainsAny(key+value, "\r\n\x00")
}
func boundedDuration(ms int, fallback, minimum, maximum time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	value := time.Duration(ms) * time.Millisecond
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
func newConnectionID() string { return fmt.Sprintf("ws_%d", time.Now().UnixNano()) }

func JSONValue(value any) string { encoded, _ := json.Marshal(value); return string(encoded) }
