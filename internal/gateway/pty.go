package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// AuditRecorder is an optional interface implemented by audit.Forwarder to record PTY and Remote Assist events.
type AuditRecorder interface {
	Emit(ctx context.Context, actor, action, targetID, ipAddr string, details map[string]any) (*types.SystemAuditEvent, string, error)
}

type ptyResizeControl struct {
	Type string `json:"type"`
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
	Data string `json:"data"`
}

// ServeAdminTerminal bridges an interactive xterm.js / WebSocket terminal session
// from GET /admin/devices/{id}/terminal to the target endpoint's duplex WebSocket stream.
// adminUser is the authenticated admin, resolved by the caller's auth middleware.
func (h *GatewayHub) ServeAdminTerminal(w http.ResponseWriter, r *http.Request, deviceID, adminUser string, auditor AuditRecorder) {
	if strings.TrimSpace(adminUser) == "" {
		http.Error(w, "Unauthorized: admin session required", http.StatusUnauthorized)
		return
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[gateway-pty] browser websocket upgrade rejected or failed for device=%s: %v", deviceID, err)
		return
	}
	defer wsConn.Close()
	wsConn.SetReadLimit(64 * 1024)

	h.mu.RLock()
	deviceClient, connected := h.clients[deviceID]
	h.mu.RUnlock()

	if !connected || deviceClient == nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[SpireUEM] Target device is offline (no active WebSocket stream).\r\n"))
		return
	}

	sessionID, _, err := db.GenerateToken()
	if err != nil {
		// Never fall back to a guessable ID: session IDs route device output to this browser.
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[SpireUEM] Could not create a terminal session.\r\n"))
		return
	}

	outCh := make(chan string, 64)
	stopCh := make(chan string, 1)

	h.registerPTYSession(sessionID, deviceID, outCh, stopCh)
	defer h.unregisterPTYSession(sessionID)

	if auditor != nil {
		_, _, _ = auditor.Emit(r.Context(), adminUser, "PTY_SESSION_START", deviceID, r.RemoteAddr, map[string]any{
			"session_id": sessionID,
			"device_id":  deviceID,
		})
	}
	defer func() {
		if auditor != nil {
			_, _, _ = auditor.Emit(context.Background(), adminUser, "PTY_SESSION_END", deviceID, r.RemoteAddr, map[string]any{
				"session_id": sessionID,
				"device_id":  deviceID,
			})
		}
	}()

	startPayload, _ := json.Marshal(types.PTYStartPayload{
		SessionID: sessionID,
		Rows:      24,
		Cols:      80,
	})
	if err := deviceClient.writeFrame(types.GatewayFrame{
		Type:      types.FrameTypePTYStart,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Payload:   startPayload,
	}); err != nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[SpireUEM] Failed to start remote PTY session.\r\n"))
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, msgBytes, readErr := wsConn.ReadMessage()
			if readErr != nil {
				return
			}

			// Check if the message is a JSON control frame (resize or structured input)
			var ctrl ptyResizeControl
			if len(msgBytes) > 0 && msgBytes[0] == '{' && json.Unmarshal(msgBytes, &ctrl) == nil && ctrl.Type != "" {
				switch strings.ToLower(ctrl.Type) {
				case "resize", "type_pty_resize":
					if ctrl.Rows > 0 && ctrl.Cols > 0 {
						resBytes, _ := json.Marshal(types.PTYResizePayload{
							SessionID: sessionID,
							Rows:      ctrl.Rows,
							Cols:      ctrl.Cols,
						})
						_ = deviceClient.writeFrame(types.GatewayFrame{
							Type:      types.FrameTypePTYResize,
							DeviceID:  deviceID,
							Timestamp: time.Now().UTC(),
							Payload:   resBytes,
						})
					}
					continue
				case "input", "type_pty_input":
					inBytes, _ := json.Marshal(types.PTYDataPayload{
						SessionID: sessionID,
						Data:      ctrl.Data,
					})
					_ = deviceClient.writeFrame(types.GatewayFrame{
						Type:      types.FrameTypePTYInput,
						DeviceID:  deviceID,
						Timestamp: time.Now().UTC(),
						Payload:   inBytes,
					})
					continue
				}
			}

			// Otherwise treat msgBytes as raw terminal keystrokes/stdin
			inBytes, _ := json.Marshal(types.PTYDataPayload{
				SessionID: sessionID,
				Data:      string(msgBytes),
			})
			if wErr := deviceClient.writeFrame(types.GatewayFrame{
				Type:      types.FrameTypePTYInput,
				DeviceID:  deviceID,
				Timestamp: time.Now().UTC(),
				Payload:   inBytes,
			}); wErr != nil {
				return
			}
		}
	}()

	defer func() {
		stopBytes, _ := json.Marshal(types.PTYStopPayload{
			SessionID: sessionID,
			Reason:    "admin_disconnected",
		})
		_ = deviceClient.writeFrame(types.GatewayFrame{
			Type:      types.FrameTypePTYStop,
			DeviceID:  deviceID,
			Timestamp: time.Now().UTC(),
			Payload:   stopBytes,
		})
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-deviceClient.closed:
			_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[SpireUEM] Device disconnected.\r\n"))
			return
		case reason := <-stopCh:
			if reason != "" {
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n[PTY exited: %s]\r\n", reason)))
			}
			return
		case chunk := <-outCh:
			_ = wsConn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := wsConn.WriteMessage(websocket.TextMessage, []byte(chunk)); err != nil {
				return
			}
		}
	}
}

// RequestRemoteAssist sends a TYPE_REMOTE_ASSIST_REQUEST frame to a connected device and awaits user consent.
func (h *GatewayHub) RequestRemoteAssist(ctx context.Context, deviceID, adminActor string) (*types.RemoteAssistResponsePayload, error) {
	h.mu.RLock()
	deviceClient, connected := h.clients[deviceID]
	h.mu.RUnlock()
	if !connected || deviceClient == nil {
		return nil, fmt.Errorf("device is not connected via WebSocket")
	}

	sessionID, _, err := db.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate remote assist session id: %w", err)
	}

	respCh := make(chan types.RemoteAssistResponsePayload, 1)
	h.registerRemoteAssistWaiter(sessionID, deviceID, respCh)
	defer h.unregisterRemoteAssistWaiter(sessionID)

	reqBytes, _ := json.Marshal(types.RemoteAssistRequestPayload{
		SessionID:  sessionID,
		AdminActor: adminActor,
	})
	if err := deviceClient.writeFrame(types.GatewayFrame{
		Type:      types.FrameTypeRemoteAssistRequest,
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Payload:   reqBytes,
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return &types.RemoteAssistResponsePayload{
			SessionID:    sessionID,
			Status:       "REJECTED_BY_USER",
			ErrorMessage: "Remote assist request timed out",
		}, nil
	case resp := <-respCh:
		return &resp, nil
	}
}
