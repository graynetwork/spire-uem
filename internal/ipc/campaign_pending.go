package ipc

// PendingCampaign describes a patch-campaign install announced to the active user. The
// agent sets it before installing so Spire Hub can offer a Defer button, and clears it once
// the install starts or is deferred.
type PendingCampaign struct {
	CampaignID    string `json:"campaign_id"`
	Name          string `json:"name,omitempty"`
	MayDefer      bool   `json:"may_defer"`
	DeferralsLeft int    `json:"deferrals_left"`
}

// SetPendingCampaign publishes the pending campaign install on GET /v1/status.
func (s *Server) SetPendingCampaign(p PendingCampaign) {
	s.campaignMu.Lock()
	defer s.campaignMu.Unlock()
	cp := p
	s.pendingCampaign = &cp
}

// ClearPendingCampaign removes the pending campaign if it is the given one.
func (s *Server) ClearPendingCampaign(campaignID string) {
	s.campaignMu.Lock()
	defer s.campaignMu.Unlock()
	if s.pendingCampaign != nil && s.pendingCampaign.CampaignID == campaignID {
		s.pendingCampaign = nil
	}
}

// PendingCampaignSnapshot returns a copy of the pending campaign, or nil.
func (s *Server) PendingCampaignSnapshot() *PendingCampaign {
	s.campaignMu.Lock()
	defer s.campaignMu.Unlock()
	if s.pendingCampaign == nil {
		return nil
	}
	cp := *s.pendingCampaign
	return &cp
}

// recordCampaignDeferral remembers a deferral the SERVER granted so the agent skips the
// install it was about to run. Only a server-granted deferral is recorded.
func (s *Server) recordCampaignDeferral(campaignID string) {
	s.campaignMu.Lock()
	defer s.campaignMu.Unlock()
	if s.campaignDeferred == nil {
		s.campaignDeferred = map[string]bool{}
	}
	s.campaignDeferred[campaignID] = true
}

// TakeCampaignDeferral reports whether the user deferred the campaign (server-granted) and
// clears the flag.
func (s *Server) TakeCampaignDeferral(campaignID string) bool {
	s.campaignMu.Lock()
	defer s.campaignMu.Unlock()
	if s.campaignDeferred[campaignID] {
		delete(s.campaignDeferred, campaignID)
		return true
	}
	return false
}
