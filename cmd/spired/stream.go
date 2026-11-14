package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

var (
	benchmarkScanRunning atomic.Bool
	commandPushSem       = make(chan struct{}, 4)
)

// runWebSocketStream maintains a persistent outbound duplex WebSocket connection to
// /api/v1/desktop/stream, handling sub-second TYPE_COMMAND_PUSH execution and
// reconnecting with jittered exponential backoff (2s to 30s) on disconnect.
func runWebSocketStream(
	ctx context.Context,
	httpClient *http.Client,
	serverURL string,
	tokenPath string,
	triggerCheckinCh chan<- struct{},
	ipcSrv *ipc.Server,
) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		token := readToken(tokenPath)
		if token == "" {
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
			continue
		}

		wsURL := buildWebSocketURL(serverURL)
		headers := http.Header{}
		headers.Set("Authorization", "Bearer "+token)

		dialer := websocket.Dialer{
			HandshakeTimeout: 8 * time.Second,
		}
		conn, _, err := dialer.DialContext(ctx, wsURL, headers)
		if err != nil {
			if ipcSrv != nil {
				ipcSrv.UpdateWSConnected(false)
			}
			attempt++
			wait := streamBackoffWithJitter(attempt)
			log.Printf("[spired-ws] connect to %s failed: %v (retrying in %s)", wsURL, err, wait)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}

		attempt = 0
		if ipcSrv != nil {
			ipcSrv.UpdateWSConnected(true)
		}
		log.Printf("[spired-ws] connected to real-time duplex gateway %s", wsURL)
		handleStreamSession(ctx, httpClient, serverURL, token, conn, triggerCheckinCh)
		if ipcSrv != nil {
			ipcSrv.UpdateWSConnected(false)
		}

		if !sleepContext(ctx, streamBackoffWithJitter(1)) {
			return
		}
	}
}

func handleStreamSession(
	ctx context.Context,
	httpClient *http.Client,
	serverURL string,
	token string,
	conn *websocket.Conn,
	triggerCheckinCh chan<- struct{},
) {
	var writeMu sync.Mutex
	writeFrame := func(frame types.GatewayFrame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(frame)
	}

	done := make(chan struct{})
	ptyMgr := newPTYManager(writeFrame)
	defer func() {
		ptyMgr.closeAll()
		close(done)
		_ = conn.Close()
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[spired-ws] stream closed: %v", err)
			return
		}

		var frame types.GatewayFrame
		if err := json.Unmarshal(msgBytes, &frame); err != nil {
			continue
		}

		switch frame.Type {
		case types.FrameTypePing:
			_ = writeFrame(types.GatewayFrame{
				Type:      types.FrameTypePong,
				Timestamp: time.Now().UTC(),
			})

		case types.FrameTypeTriggerCheckin:
			log.Printf("[spired-ws] received TYPE_TRIGGER_CHECKIN; waking check-in loop")
			select {
			case triggerCheckinCh <- struct{}{}:
			default:
			}

		case types.FrameTypeTriggerPatchRun:
			log.Printf("[spired-ws] received TYPE_TRIGGER_PATCH_RUN; executing system patch run")
			go func() {
				out, err := engine.ExecutePatchRun(ctx)
				if err != nil {
					log.Printf("[spired-ws] patch run finished with error: %v (output: %s)", err, out)
				} else {
					log.Printf("[spired-ws] patch run succeeded (output: %s)", out)
				}
				select {
				case triggerCheckinCh <- struct{}{}:
				default:
				}
			}()

		case types.FrameTypeCommandPush:
			var push types.CommandPushPayload
			if err := json.Unmarshal(frame.Payload, &push); err != nil || strings.TrimSpace(push.ID) == "" {
				continue
			}
			// Structured lost-device action directives are dispatched by the authoritative
			// HTTP check-in path, which has the device's hardware UUID, pinned wipe key and
			// server KEK in hand. A live push of one simply wakes that path; the command row
			// stays RUNNING until the check-in reports its outcome, so it is never executed
			// twice.
			if IsActionDirective(push.Command) {
				log.Printf("[spired-ws] received action directive id=%s; waking check-in to dispatch", push.ID)
				select {
				case triggerCheckinCh <- struct{}{}:
				default:
				}
				continue
			}
			go func(p types.CommandPushPayload) {
				select {
				case commandPushSem <- struct{}{}:
					defer func() { <-commandPushSem }()
				case <-ctx.Done():
					return
				}
				log.Printf("[spired-ws] received sub-second TYPE_COMMAND_PUSH id=%s cmd=%q", p.ID, p.Command)
				report := engine.ExecuteDiagnosticCommand(ctx, types.CommandDTO(p), 30*time.Second)

				resPayload, _ := json.Marshal(types.CommandResultPayload{
					CommandID: report.CommandID,
					Status:    report.Status,
					ExitCode:  report.ExitCode,
					Stdout:    report.Stdout,
					Stderr:    report.Stderr,
					Final:     true,
				})
				if wErr := writeFrame(types.GatewayFrame{
					Type:      types.FrameTypeCommandResult,
					Timestamp: time.Now().UTC(),
					Payload:   resPayload,
				}); wErr != nil {
					log.Printf("[spired-ws] socket result write failed for cmd=%s (%v); falling back to HTTP report", p.ID, wErr)
					_ = reportCommandResult(ctx, httpClient, serverURL, token, report)
				} else {
					log.Printf("[spired-ws] streamed TYPE_COMMAND_RESULT id=%s status=%s exit=%d",
						report.CommandID, report.Status, report.ExitCode)
				}
			}(push)

		case types.FrameTypePTYStart:
			var start types.PTYStartPayload
			if err := json.Unmarshal(frame.Payload, &start); err == nil {
				ptyMgr.startSession(ctx, start)
			}

		case types.FrameTypePTYInput:
			var input types.PTYDataPayload
			if err := json.Unmarshal(frame.Payload, &input); err == nil {
				ptyMgr.handleInput(input)
			}

		case types.FrameTypePTYResize:
			var resize types.PTYResizePayload
			if err := json.Unmarshal(frame.Payload, &resize); err == nil {
				ptyMgr.handleResize(resize)
			}

		case types.FrameTypePTYStop:
			var stop types.PTYStopPayload
			if err := json.Unmarshal(frame.Payload, &stop); err == nil {
				ptyMgr.stopSession(stop.SessionID)
			}

		case types.FrameTypeRemoteAssistRequest:
			var raReq types.RemoteAssistRequestPayload
			if err := json.Unmarshal(frame.Payload, &raReq); err == nil {
				go func(req types.RemoteAssistRequestPayload) {
					resp := engine.HandleRemoteAssistRequest(ctx, req)
					respBytes, _ := json.Marshal(resp)
					_ = writeFrame(types.GatewayFrame{
						Type:      types.FrameTypeRemoteAssistResponse,
						Timestamp: time.Now().UTC(),
						Payload:   respBytes,
					})
				}(raReq)
			}

		case types.FrameTypeBenchmarkStart:
			var start types.BenchmarkStartPayload
			if err := json.Unmarshal(frame.Payload, &start); err != nil || strings.TrimSpace(start.ScanID) == "" {
				continue
			}
			go func(p types.BenchmarkStartPayload) {
				if !benchmarkScanRunning.CompareAndSwap(false, true) {
					log.Printf("[spired-ws] benchmark scan already in progress; rejecting overlapping scan_id=%s", p.ScanID)
					_ = reportBenchmarkStatus(ctx, httpClient, serverURL, token, types.BenchmarkResultPayload{
						ScanID:       p.ScanID,
						Status:       "FAILED",
						ErrorMessage: "another benchmark scan is already running on this endpoint",
					})
					return
				}
				defer benchmarkScanRunning.Store(false)

				log.Printf("[spired-ws] received TYPE_BENCHMARK_START scan_id=%s profile=%q", p.ScanID, p.Profile)
				// 1. Immediately report status RUNNING to server
				_ = reportBenchmarkStatus(ctx, httpClient, serverURL, token, types.BenchmarkResultPayload{
					ScanID: p.ScanID,
					Status: "RUNNING",
				})

				// 2. Execute benchmark scan via OpenSCAP engine
				scanCtx, scanCancel := context.WithTimeout(ctx, 10*time.Minute)
				defer scanCancel()

				payload, err := engine.RunBenchmarkScan(scanCtx, p.Profile, p.DatastreamPath)
				if err != nil {
					log.Printf("[spired-ws] benchmark scan failed for scan_id=%s: %v", p.ScanID, err)
					_ = reportBenchmarkStatus(ctx, httpClient, serverURL, token, types.BenchmarkResultPayload{
						ScanID:       p.ScanID,
						Status:       "FAILED",
						ErrorMessage: err.Error(),
					})
					return
				}

				payload.ScanID = p.ScanID
				payload.Status = "COMPLETED"
				if err := reportBenchmarkStatus(ctx, httpClient, serverURL, token, *payload); err != nil {
					log.Printf("[spired-ws] failed to report benchmark results for scan_id=%s: %v", p.ScanID, err)
				} else {
					log.Printf("[spired-ws] benchmark results reported successfully scan_id=%s score=%.2f", p.ScanID, payload.Score)
				}
			}(start)
		}
	}
}

func buildWebSocketURL(serverURL string) string {
	u := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if strings.HasPrefix(u, "https://") {
		u = "wss://" + strings.TrimPrefix(u, "https://")
	} else if strings.HasPrefix(u, "http://") {
		u = "ws://" + strings.TrimPrefix(u, "http://")
	} else if !strings.HasPrefix(u, "ws://") && !strings.HasPrefix(u, "wss://") {
		u = "ws://" + u
	}
	return u + "/api/v1/desktop/stream"
}

func streamBackoffWithJitter(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 4 {
		attempt = 4
	}
	base := 2 * time.Second * time.Duration(1<<(attempt-1))
	if base > 25*time.Second {
		base = 25 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(2 * time.Second)))
	total := base + jitter
	if total > 30*time.Second {
		total = 30 * time.Second
	}
	return total
}
