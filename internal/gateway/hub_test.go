package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spire-uem/spire-uem/internal/types"
)

func newTestHub() *GatewayHub {
	return &GatewayHub{
		clients:      make(map[string]*clientConn),
		uiSubs:       make(map[string]map[chan types.CommandResultPayload]struct{}),
		ptyOutSubs:   make(map[string]chan string),
		ptyStop:      make(map[string]chan string),
		raWaiters:    make(map[string]chan types.RemoteAssistResponsePayload),
		sessionOwner: make(map[string]string),
	}
}

// dialAsDevice runs h.readLoop for a stream authenticated as deviceID and returns the
// client end of that stream.
func dialAsDevice(t *testing.T, h *GatewayHub, deviceID string) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &clientConn{deviceID: deviceID, conn: conn, closed: make(chan struct{})}
		h.readLoop(c)
	}))
	t.Cleanup(srv.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendFrame(t *testing.T, conn *websocket.Conn, typ types.GatewayFrameType, payload any) {
	t.Helper()
	b, _ := json.Marshal(payload)
	if err := conn.WriteJSON(types.GatewayFrame{Type: typ, Payload: b}); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func TestReadLoop_PTYFramesRoutedOnlyFromOwningDevice(t *testing.T) {
	h := newTestHub()
	outCh := make(chan string, 4)
	stopCh := make(chan string, 1)
	h.registerPTYSession("sess-a", "device-a", outCh, stopCh)

	other := dialAsDevice(t, h, "device-b")
	sendFrame(t, other, types.FrameTypePTYOutput, types.PTYDataPayload{SessionID: "sess-a", Data: "injected"})
	sendFrame(t, other, types.FrameTypePTYStop, types.PTYStopPayload{SessionID: "sess-a", Reason: "killed"})

	owner := dialAsDevice(t, h, "device-a")
	sendFrame(t, owner, types.FrameTypePTYOutput, types.PTYDataPayload{SessionID: "sess-a", Data: "genuine"})

	select {
	case got := <-outCh:
		if got != "genuine" {
			t.Fatalf("terminal received %q from another device", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owning device's output was not delivered")
	}
	select {
	case got := <-outCh:
		t.Fatalf("unexpected extra output %q", got)
	case reason := <-stopCh:
		t.Fatalf("another device ended the session (%q)", reason)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestReadLoop_RemoteAssistResponseOnlyFromOwningDevice(t *testing.T) {
	h := newTestHub()
	ch := make(chan types.RemoteAssistResponsePayload, 2)
	h.registerRemoteAssistWaiter("ra-1", "device-a", ch)

	other := dialAsDevice(t, h, "device-b")
	sendFrame(t, other, types.FrameTypeRemoteAssistResponse, types.RemoteAssistResponsePayload{SessionID: "ra-1", Status: "ACCEPTED"})
	owner := dialAsDevice(t, h, "device-a")
	sendFrame(t, owner, types.FrameTypeRemoteAssistResponse, types.RemoteAssistResponsePayload{SessionID: "ra-1", Status: "REJECTED_BY_USER"})

	select {
	case got := <-ch:
		if got.Status != "REJECTED_BY_USER" {
			t.Fatalf("remote assist consent came from another device: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owning device's response was not delivered")
	}
}

func TestAuthenticateHandshake_IgnoresQueryToken(t *testing.T) {
	h := newTestHub()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/desktop/stream?token=abc", nil)
	if dev := h.authenticateHandshake(req); dev != nil {
		t.Fatal("query-string token was accepted")
	}
}
