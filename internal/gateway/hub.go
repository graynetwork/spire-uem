package gateway

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 30 * time.Second
)

// ValidateSameOrigin verifies that the WebSocket request Origin matches the request Host
// or is explicitly permitted via the SPIRE_ALLOWED_ORIGINS environment variable.
func ValidateSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (CLI tools / daemon) do not send Origin
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if strings.EqualFold(u.Host, r.Host) {
		return true
	}

	if allowed := os.Getenv("SPIRE_ALLOWED_ORIGINS"); allowed != "" {
		for _, entry := range strings.Split(allowed, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" && (strings.EqualFold(entry, origin) || strings.EqualFold(entry, u.Host)) {
				return true
			}
		}
	}

	return false
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return ValidateSameOrigin(r)
	},
}

type clientConn struct {
	deviceID  string
	hostname  string
	conn      *websocket.Conn
	writeMu   sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *clientConn) writeFrame(frame types.GatewayFrame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteJSON(frame)
}

func (c *clientConn) writeControlPing() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(writeWait))
}

func (c *clientConn) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

// GatewayHub manages active duplex WebSocket connections from spired endpoints
// and broadcasts real-time command execution updates to admin UI subscribers.
type GatewayHub struct {
	repo       *db.Repository
	mu         sync.RWMutex
	clients    map[string]*clientConn
	uiSubs     map[string]map[chan types.CommandResultPayload]struct{}
	ptyOutSubs map[string]chan string
	ptyStop    map[string]chan string
	raWaiters  map[string]chan types.RemoteAssistResponsePayload
	// sessionOwner maps every PTY and remote-assist session ID to the device it was
	// opened for. Frames that name a session are only routed when they arrive on that
	// device's own stream, so one device cannot write into or end another's session.
	sessionOwner map[string]string
}

// NewGatewayHub creates a new GatewayHub and resets stale ws_connected flags in PostgreSQL.
func NewGatewayHub(repo *db.Repository) *GatewayHub {
	_ = repo.ResetAllWSPresence(context.Background())
	return &GatewayHub{
		repo:       repo,
		clients:    make(map[string]*clientConn),
		uiSubs:     make(map[string]map[chan types.CommandResultPayload]struct{}),
		ptyOutSubs: make(map[string]chan string),
		ptyStop:    make(map[string]chan string),
		raWaiters:  make(map[string]chan types.RemoteAssistResponsePayload),

		sessionOwner: make(map[string]string),
	}
}

// IsConnected returns true if the device currently holds an active duplex WebSocket session.
func (h *GatewayHub) IsConnected(deviceID string) bool {
	h.mu.RLock()
	_, ok := h.clients[deviceID]
	h.mu.RUnlock()
	return ok
}

// ConnectedCount returns the count of active WebSocket-connected endpoints.
func (h *GatewayHub) ConnectedCount() int {
	h.mu.RLock()
	n := len(h.clients)
	h.mu.RUnlock()
	return n
}

// DisconnectDevice forcibly closes any active duplex WebSocket connection for the given device ID.
func (h *GatewayHub) DisconnectDevice(deviceID string) {
	h.mu.Lock()
	c, ok := h.clients[deviceID]
	if ok {
		delete(h.clients, deviceID)
	}
	h.mu.Unlock()
	if ok && c != nil {
		c.close()
		h.updatePresence(deviceID, false)
	}
}

func (h *GatewayHub) updatePresence(deviceID string, connected bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.repo.UpdateDeviceWSPresence(ctx, deviceID, connected); err != nil {
		log.Printf("[gateway] failed to mark ws_connected=%v for device=%s: %v", connected, deviceID, err)
	}
}

// ServeStream handles GET /api/v1/desktop/stream, authenticating the device Bearer token
// and upgrading the HTTP connection to a full-duplex WebSocket stream.
func (h *GatewayHub) ServeStream(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateHandshake(r)
	if dev == nil || dev.Status != types.StatusApproved {
		http.Error(w, "unauthorized or unapproved device", http.StatusForbidden)
		return
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[gateway] websocket upgrade failed for device=%s: %v", dev.ID, err)
		return
	}

	client := &clientConn{
		deviceID: dev.ID,
		hostname: dev.Hostname,
		conn:     wsConn,
		closed:   make(chan struct{}),
	}

	h.registerClient(client)
	defer h.unregisterClient(client)

	log.Printf("[gateway] WebSocket connected device=%s hostname=%s remote=%s", dev.ID, dev.Hostname, r.RemoteAddr)

	// Immediately push any already-QUEUED commands waiting for this device
	if queued, qErr := h.repo.ClaimQueuedCommandsForDevice(r.Context(), dev.ID); qErr == nil && len(queued) > 0 {
		for _, cmd := range queued {
			payloadBytes, _ := json.Marshal(types.CommandPushPayload(cmd))
			_ = client.writeFrame(types.GatewayFrame{
				Type:      types.FrameTypeCommandPush,
				DeviceID:  dev.ID,
				Timestamp: time.Now().UTC(),
				Payload:   payloadBytes,
			})
		}
	}

	go h.heartbeatLoop(client)
	h.readLoop(client)
}

func (h *GatewayHub) registerClient(c *clientConn) {
	h.mu.Lock()
	if prev, exists := h.clients[c.deviceID]; exists && prev != c {
		prev.close()
	}
	h.clients[c.deviceID] = c
	h.mu.Unlock()

	h.updatePresence(c.deviceID, true)
}

func (h *GatewayHub) unregisterClient(c *clientConn) {
	c.close()
	shouldMarkOffline := false

	h.mu.Lock()
	if curr, exists := h.clients[c.deviceID]; exists && curr == c {
		delete(h.clients, c.deviceID)
		shouldMarkOffline = true
	}
	h.mu.Unlock()

	if shouldMarkOffline {
		h.updatePresence(c.deviceID, false)
		log.Printf("[gateway] WebSocket disconnected device=%s hostname=%s", c.deviceID, c.hostname)
	}
}

func (h *GatewayHub) heartbeatLoop(c *clientConn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			if err := c.writeControlPing(); err != nil {
				c.close()
				return
			}
			_ = c.writeFrame(types.GatewayFrame{
				Type:      types.FrameTypePing,
				DeviceID:  c.deviceID,
				Timestamp: time.Now().UTC(),
			})
		}
	}
}

func (h *GatewayHub) readLoop(c *clientConn) {
	c.conn.SetReadLimit(256 * 1024)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		h.updatePresence(c.deviceID, true)
		return nil
	})

	for {
		_, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))

		var frame types.GatewayFrame
		if err := json.Unmarshal(msgBytes, &frame); err != nil {
			continue
		}

		switch frame.Type {
		case types.FrameTypePing:
			h.updatePresence(c.deviceID, true)
			_ = c.writeFrame(types.GatewayFrame{
				Type:      types.FrameTypePong,
				DeviceID:  c.deviceID,
				Timestamp: time.Now().UTC(),
			})

		case types.FrameTypePong:
			h.updatePresence(c.deviceID, true)

		case types.FrameTypeCommandResult:
			var res types.CommandResultPayload
			if err := json.Unmarshal(frame.Payload, &res); err != nil {
				log.Printf("[gateway] invalid TYPE_COMMAND_RESULT payload from device=%s: %v", c.deviceID, err)
				continue
			}
			status := strings.ToUpper(strings.TrimSpace(res.Status))
			if status == "" {
				status = "COMPLETED"
			}
			if err := h.repo.UpdateCommandResult(
				context.Background(),
				c.deviceID,
				res.CommandID,
				status,
				res.ExitCode,
				res.Stdout,
				res.Stderr,
			); err != nil {
				log.Printf("[gateway] failed to persist TYPE_COMMAND_RESULT device=%s cmd=%s: %v", c.deviceID, res.CommandID, err)
			} else {
				log.Printf("[gateway] sub-second WS command result recorded device=%s cmd=%s status=%s exit=%d",
					c.deviceID, res.CommandID, status, res.ExitCode)
			}
			h.notifyUISubscribers(c.deviceID, res)

		case types.FrameTypePTYOutput:
			var out types.PTYDataPayload
			if err := json.Unmarshal(frame.Payload, &out); err != nil {
				continue
			}
			h.mu.RLock()
			ch, ok := h.ptyOutSubs[out.SessionID]
			ok = ok && h.sessionOwner[out.SessionID] == c.deviceID
			h.mu.RUnlock()
			if ok {
				select {
				case ch <- out.Data:
				default:
				}
			}

		case types.FrameTypePTYStop:
			var stop types.PTYStopPayload
			if err := json.Unmarshal(frame.Payload, &stop); err != nil {
				continue
			}
			h.mu.RLock()
			ch, ok := h.ptyStop[stop.SessionID]
			ok = ok && h.sessionOwner[stop.SessionID] == c.deviceID
			h.mu.RUnlock()
			if ok {
				select {
				case ch <- stop.Reason:
				default:
				}
			}

		case types.FrameTypeRemoteAssistResponse:
			var resp types.RemoteAssistResponsePayload
			if err := json.Unmarshal(frame.Payload, &resp); err != nil {
				continue
			}
			h.mu.RLock()
			ch, ok := h.raWaiters[resp.SessionID]
			ok = ok && h.sessionOwner[resp.SessionID] == c.deviceID
			h.mu.RUnlock()
			if ok {
				select {
				case ch <- resp:
				default:
				}
			}
		}
	}
}

// PushCommand immediately transmits a TYPE_COMMAND_PUSH frame over the device's active WebSocket if connected.
func (h *GatewayHub) PushCommand(ctx context.Context, deviceID string, cmd types.CommandDTO) bool {
	h.mu.RLock()
	client, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok || client == nil {
		return false
	}

	_ = h.repo.MarkCommandRunning(ctx, deviceID, cmd.ID)

	payloadBytes, _ := json.Marshal(types.CommandPushPayload(cmd))
	frame := types.GatewayFrame{
		Type:      types.FrameTypeCommandPush,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Payload:   payloadBytes,
	}
	if err := client.writeFrame(frame); err != nil {
		log.Printf("[gateway] PushCommand write error for device=%s cmd=%s: %v", deviceID, cmd.ID, err)
		return false
	}
	log.Printf("[gateway] pushed TYPE_COMMAND_PUSH id=%s to connected device=%s", cmd.ID, deviceID)
	return true
}

// TriggerCheckin sends a TYPE_TRIGGER_CHECKIN signal to a connected device.
func (h *GatewayHub) TriggerCheckin(deviceID string) bool {
	h.mu.RLock()
	client, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok || client == nil {
		return false
	}
	err := client.writeFrame(types.GatewayFrame{
		Type:      types.FrameTypeTriggerCheckin,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
	})
	return err == nil
}

// TriggerPatchRun sends a TYPE_TRIGGER_PATCH_RUN signal to a connected device.
func (h *GatewayHub) TriggerPatchRun(deviceID string) bool {
	h.mu.RLock()
	client, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok || client == nil {
		return false
	}
	err := client.writeFrame(types.GatewayFrame{
		Type:      types.FrameTypeTriggerPatchRun,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
	})
	return err == nil
}

// PushBenchmarkStart sends a TYPE_BENCHMARK_START frame to an active WebSocket connection.
func (h *GatewayHub) PushBenchmarkStart(deviceID string, payload types.BenchmarkStartPayload) bool {
	h.mu.RLock()
	client, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok || client == nil {
		return false
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	frame := types.GatewayFrame{
		Type:      types.FrameTypeBenchmarkStart,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Payload:   payloadBytes,
	}
	if err := client.writeFrame(frame); err != nil {
		log.Printf("[gateway] PushBenchmarkStart write error for device=%s scan=%s: %v", deviceID, payload.ScanID, err)
		return false
	}
	log.Printf("[gateway] pushed TYPE_BENCHMARK_START scan_id=%s profile=%s to device=%s", payload.ScanID, payload.Profile, deviceID)
	return true
}

// SubscribeUI registers a channel to receive live CommandResultPayload updates for a device.
func (h *GatewayHub) SubscribeUI(deviceID string) (chan types.CommandResultPayload, func()) {
	ch := make(chan types.CommandResultPayload, 8)
	h.mu.Lock()
	if h.uiSubs[deviceID] == nil {
		h.uiSubs[deviceID] = make(map[chan types.CommandResultPayload]struct{})
	}
	h.uiSubs[deviceID][ch] = struct{}{}
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if subs, ok := h.uiSubs[deviceID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(h.uiSubs, deviceID)
			}
		}
		h.mu.Unlock()
	}
	return ch, unsubscribe
}

func (h *GatewayHub) notifyUISubscribers(deviceID string, res types.CommandResultPayload) {
	h.mu.RLock()
	subs := h.uiSubs[deviceID]
	for ch := range subs {
		select {
		case ch <- res:
		default:
		}
	}
	h.mu.RUnlock()
}

func (h *GatewayHub) registerPTYSession(sessionID, deviceID string, outCh chan string, stopCh chan string) {
	h.mu.Lock()
	h.ptyOutSubs[sessionID] = outCh
	h.ptyStop[sessionID] = stopCh
	h.sessionOwner[sessionID] = deviceID
	h.mu.Unlock()
}

func (h *GatewayHub) unregisterPTYSession(sessionID string) {
	h.mu.Lock()
	delete(h.ptyOutSubs, sessionID)
	delete(h.ptyStop, sessionID)
	delete(h.sessionOwner, sessionID)
	h.mu.Unlock()
}

func (h *GatewayHub) registerRemoteAssistWaiter(sessionID, deviceID string, ch chan types.RemoteAssistResponsePayload) {
	h.mu.Lock()
	h.raWaiters[sessionID] = ch
	h.sessionOwner[sessionID] = deviceID
	h.mu.Unlock()
}

func (h *GatewayHub) unregisterRemoteAssistWaiter(sessionID string) {
	h.mu.Lock()
	delete(h.raWaiters, sessionID)
	delete(h.sessionOwner, sessionID)
	h.mu.Unlock()
}

func (h *GatewayHub) authenticateHandshake(r *http.Request) *types.Device {
	// The device token is accepted only in the Authorization header. A ?token= query
	// parameter would be written to request logs and proxy access logs.
	rawToken := ""
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		rawToken = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if rawToken == "" {
		return nil
	}
	tokenHash := db.HashToken(rawToken)
	dev, err := h.repo.GetDeviceByTokenHash(r.Context(), tokenHash)
	if err != nil || dev == nil {
		return nil
	}
	return dev
}
