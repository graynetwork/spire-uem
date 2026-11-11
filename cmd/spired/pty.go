package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/spire-uem/spire-uem/internal/types"
)

type ptySession struct {
	sessionID string
	ptmx      *os.File
	cmd       *exec.Cmd
	closeOnce sync.Once
}

func (s *ptySession) close() {
	s.closeOnce.Do(func() {
		if s.ptmx != nil {
			_ = s.ptmx.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_, _ = s.cmd.Process.Wait()
		}
	})
}

type ptyManager struct {
	mu       sync.Mutex
	sessions map[string]*ptySession
	writeFn  func(types.GatewayFrame) error
}

func newPTYManager(writeFn func(types.GatewayFrame) error) *ptyManager {
	return &ptyManager{
		sessions: make(map[string]*ptySession),
		writeFn:  writeFn,
	}
}

func (m *ptyManager) startSession(ctx context.Context, payload types.PTYStartPayload) {
	if payload.SessionID == "" {
		return
	}
	rows := payload.Rows
	if rows == 0 {
		rows = 24
	}
	cols := payload.Cols
	if cols == 0 {
		cols = 80
	}

	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
	if err != nil {
		log.Printf("[spired-pty] failed to start PTY session %s: %v", payload.SessionID, err)
		stopBytes, _ := json.Marshal(types.PTYStopPayload{
			SessionID: payload.SessionID,
			Reason:    err.Error(),
		})
		_ = m.writeFn(types.GatewayFrame{
			Type:      types.FrameTypePTYStop,
			Timestamp: time.Now().UTC(),
			Payload:   stopBytes,
		})
		return
	}

	sess := &ptySession{
		sessionID: payload.SessionID,
		ptmx:      ptmx,
		cmd:       cmd,
	}

	m.mu.Lock()
	if prev, exists := m.sessions[payload.SessionID]; exists {
		prev.close()
	}
	m.sessions[payload.SessionID] = sess
	m.mu.Unlock()

	log.Printf("[spired-pty] started PTY session id=%s shell=%s (%dx%d)", payload.SessionID, shell, cols, rows)

	go func() {
		defer func() {
			sess.close()
			m.mu.Lock()
			if curr, ok := m.sessions[payload.SessionID]; ok && curr == sess {
				delete(m.sessions, payload.SessionID)
			}
			m.mu.Unlock()

			stopBytes, _ := json.Marshal(types.PTYStopPayload{
				SessionID: payload.SessionID,
				Reason:    "process_exited",
			})
			_ = m.writeFn(types.GatewayFrame{
				Type:      types.FrameTypePTYStop,
				Timestamp: time.Now().UTC(),
				Payload:   stopBytes,
			})
		}()

		buf := make([]byte, 4096)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				outBytes, _ := json.Marshal(types.PTYDataPayload{
					SessionID: payload.SessionID,
					Data:      string(buf[:n]),
				})
				if wErr := m.writeFn(types.GatewayFrame{
					Type:      types.FrameTypePTYOutput,
					Timestamp: time.Now().UTC(),
					Payload:   outBytes,
				}); wErr != nil {
					return
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					log.Printf("[spired-pty] read ended for session %s: %v", payload.SessionID, readErr)
				}
				return
			}
		}
	}()
}

func (m *ptyManager) handleInput(payload types.PTYDataPayload) {
	m.mu.Lock()
	sess := m.sessions[payload.SessionID]
	m.mu.Unlock()
	if sess == nil || sess.ptmx == nil {
		return
	}
	_, _ = sess.ptmx.Write([]byte(payload.Data))
}

func (m *ptyManager) handleResize(payload types.PTYResizePayload) {
	m.mu.Lock()
	sess := m.sessions[payload.SessionID]
	m.mu.Unlock()
	if sess == nil || sess.ptmx == nil || payload.Rows == 0 || payload.Cols == 0 {
		return
	}
	_ = pty.Setsize(sess.ptmx, &pty.Winsize{
		Rows: payload.Rows,
		Cols: payload.Cols,
	})
}

func (m *ptyManager) stopSession(sessionID string) {
	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	if ok {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
	if sess != nil {
		sess.close()
	}
}

func (m *ptyManager) closeAll() {
	m.mu.Lock()
	all := make([]*ptySession, 0, len(m.sessions))
	for id, s := range m.sessions {
		all = append(all, s)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}
