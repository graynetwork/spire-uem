package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CampaignDeferRequest is the body the local Spire Hub "Defer" button sends over the IPC
// socket. The authenticated active-seat0/root user is the only caller the peer-cred
// middleware admits, so this is an authenticated local action as the spec requires.
type CampaignDeferRequest struct {
	CampaignID string `json:"campaign_id"`
}

// CampaignDeferResponse mirrors the control-plane response: whether the deferral was granted
// and how many remain.
type CampaignDeferResponse struct {
	Deferred       bool   `json:"deferred"`
	DeferralsUsed  int    `json:"deferrals_used"`
	DeferralsLeft  int    `json:"deferrals_left"`
	Message        string `json:"message,omitempty"`
}

// handleCampaignDefer forwards a user's deferral request for a running campaign to the
// control plane, authenticated with the device's own bearer token. The server decides
// whether a deferral is still allowed (count + deadline); this handler never makes that
// decision locally. seat0/root only is already enforced by peerCredMiddleware.
func (s *Server) handleCampaignDefer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req CampaignDeferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.CampaignID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "campaign_id required"})
		return
	}
	resp, err := s.forwardCampaignDefer(r.Context(), strings.TrimSpace(req.CampaignID))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if resp.Deferred {
		s.recordCampaignDeferral(strings.TrimSpace(req.CampaignID))
	}
	writeJSON(w, http.StatusOK, resp)
}

// forwardCampaignDefer POSTs the deferral to the control plane with the device bearer token.
func (s *Server) forwardCampaignDefer(ctx context.Context, campaignID string) (*CampaignDeferResponse, error) {
	token := s.readToken()
	if token == "" || strings.TrimSpace(s.serverURL) == "" {
		return nil, fmt.Errorf("agent not enrolled")
	}
	body, _ := json.Marshal(map[string]string{"campaign_id": campaignID})
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.serverURL+"/api/v1/desktop/campaign/defer", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", httpResp.StatusCode)
	}
	var out CampaignDeferResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandleCampaignDeferForTest exposes handleCampaignDefer for external-package tests.
func (s *Server) HandleCampaignDeferForTest(w http.ResponseWriter, r *http.Request) {
	s.handleCampaignDefer(w, r)
}
