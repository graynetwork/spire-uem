package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// DefaultSocketPath is the local Unix domain socket path for unprivileged desktop IPC.
	DefaultSocketPath = "/run/spire/agent.sock"
	// DefaultCatalogCachePath stores the cached self-service catalog on disk.
	DefaultCatalogCachePath = "/etc/spire/self-service-catalog.json"
)

// AgentStatus represents the current daemon status returned by GET /v1/status.
type AgentStatus struct {
	DeviceID          string                   `json:"device_id"`
	ServerURL         string                   `json:"server_url"`
	HardwareUUID      string                   `json:"hardware_uuid"`
	Hostname          string                   `json:"hostname"`
	Connected         bool                     `json:"connected"`
	WSConnected       bool                     `json:"ws_connected"`
	LastCheckinAt     time.Time                `json:"last_checkin_at,omitempty"`
	IsCompliant       bool                     `json:"is_compliant"`
	ComplianceState   string                   `json:"compliance_state"`
	AttestationStatus string                   `json:"attestation_status"`
	SecureBootEnabled bool                     `json:"secure_boot_enabled"`
	LUKSEscrowed      bool                     `json:"luks_escrowed"`
	CISAuditScore     float64                  `json:"cis_audit_score"`
	CompliantPolicies int                      `json:"compliant_policies"`
	FailedPolicies    int                      `json:"failed_policies"`
	TotalPolicies     int                      `json:"total_policies"`
	SecurityPolicies  []types.PolicyStatusItem `json:"security_policies"`
	MandatoryApps     []types.AppStatusItem    `json:"mandatory_apps"`
	AvailableCatalog  []types.CatalogAppItem   `json:"available_catalog"`
}

type peerCredKey struct{}

// WithPeerCred injects a *syscall.Ucred into context for testing and peer propagation.
func WithPeerCred(ctx context.Context, ucred *syscall.Ucred) context.Context {
	return context.WithValue(ctx, peerCredKey{}, ucred)
}

// Server exposes a local Unix domain socket HTTP API for unprivileged desktop users via spire-ctl and spire-hub.
type Server struct {
	socketPath       string
	serverURL        string
	tokenPath        string
	hwUUID           string
	hostname         string
	httpClient       *http.Client
	syncFunc         func(ctx context.Context) error
	triggerCh        chan<- struct{}
	engineMu         *sync.Mutex
	mu               sync.RWMutex
	lastStatus       AgentStatus
	assignedPolicies []types.AssignedPolicy
	policyResults    []types.PolicyExecutionItem
}

// SetEngineMutex binds the daemon's policy execution mutex so IPC install/uninstall operations serialize with check-in cycles.
func (s *Server) SetEngineMutex(mu *sync.Mutex) {
	s.engineMu = mu
}

// NewServer constructs a new local IPC server for spired.
func NewServer(
	socketPath string,
	serverURL string,
	tokenPath string,
	hwUUID string,
	hostname string,
	httpClient *http.Client,
	syncFunc func(ctx context.Context) error,
	triggerCh chan<- struct{},
) *Server {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = DefaultSocketPath
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Server{
		socketPath: socketPath,
		serverURL:  strings.TrimRight(serverURL, "/"),
		tokenPath:  tokenPath,
		hwUUID:     hwUUID,
		hostname:   hostname,
		httpClient: httpClient,
		syncFunc:   syncFunc,
		triggerCh:  triggerCh,
		lastStatus: AgentStatus{
			DeviceID:          hwUUID,
			ServerURL:         serverURL,
			HardwareUUID:      hwUUID,
			Hostname:          hostname,
			Connected:         false,
			IsCompliant:       true,
			ComplianceState:   "PENDING",
			AttestationStatus: "UNATTESTED",
			SecurityPolicies:  make([]types.PolicyStatusItem, 0),
			MandatoryApps:     make([]types.AppStatusItem, 0),
			AvailableCatalog:  make([]types.CatalogAppItem, 0),
		},
	}
}

// UpdateAttestation updates the TPM 2.0 attestation state exposed on GET /v1/status.
func (s *Server) UpdateAttestation(status string, secureBoot bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(status) != "" {
		s.lastStatus.AttestationStatus = status
	}
	s.lastStatus.SecureBootEnabled = secureBoot
}

// UpdateLUKSEscrow updates the LUKS2 escrow status exposed on GET /v1/status.
func (s *Server) UpdateLUKSEscrow(escrowed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastStatus.LUKSEscrowed = escrowed
}

// UpdateCISScore updates the CIS OpenSCAP benchmark score exposed on GET /v1/status.
func (s *Server) UpdateCISScore(score float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastStatus.CISAuditScore = score
}

// UpdateWSConnected updates the live WebSocket stream state exposed on GET /v1/status.
func (s *Server) UpdateWSConnected(connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastStatus.WSConnected = connected
	if connected {
		s.lastStatus.Connected = true
	}
}

// UpdateDevicePolicies updates the cached device ID, assigned policies, and execution results on the IPC server.
func (s *Server) UpdateDevicePolicies(deviceID string, policies []types.AssignedPolicy, results []types.PolicyExecutionItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(deviceID) != "" {
		s.lastStatus.DeviceID = strings.TrimSpace(deviceID)
	}
	if policies != nil {
		s.assignedPolicies = append([]types.AssignedPolicy(nil), policies...)
	}
	if results != nil {
		s.policyResults = append([]types.PolicyExecutionItem(nil), results...)
	}
}

// UpdateStatus updates the cached agent status snapshot exposed on GET /v1/status.
func (s *Server) UpdateStatus(connected bool, lastCheckin time.Time, results []types.PolicyExecutionItem) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastStatus.Connected = connected
	if !lastCheckin.IsZero() {
		s.lastStatus.LastCheckinAt = lastCheckin
	}

	if results != nil {
		s.policyResults = append([]types.PolicyExecutionItem(nil), results...)
		availableMap := make(map[string]bool)
		for _, p := range s.assignedPolicies {
			if engine.IsApplicationPolicy(p.PolicyType) && engine.ResolveAssignmentType(p.AssignmentType, p.Payload) == types.AssignmentAvailable {
				availableMap[p.ID] = true
			}
		}
		compliant := 0
		failed := 0
		for _, r := range results {
			if r.ComplianceStatus == types.ComplianceRevoked || availableMap[r.PolicyID] {
				continue
			}
			if r.ComplianceStatus == types.ComplianceCompliant {
				compliant++
			} else if r.ComplianceStatus == types.ComplianceFailed || r.ComplianceStatus == types.ComplianceNonCompliant {
				failed++
			}
		}
		s.lastStatus.CompliantPolicies = compliant
		s.lastStatus.FailedPolicies = failed
		s.lastStatus.TotalPolicies = compliant + failed
		s.lastStatus.IsCompliant = failed == 0
		if failed > 0 {
			s.lastStatus.ComplianceState = string(types.ComplianceNonCompliant)
		} else {
			s.lastStatus.ComplianceState = string(types.ComplianceCompliant)
		}
	}
}

// Run creates /run/spire/agent.sock and serves IPC requests until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	sockDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		return fmt.Errorf("create ipc socket dir %s: %w", sockDir, err)
	}
	_ = os.Chmod(sockDir, 0755)
	_ = os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod unix socket %s: %w", s.socketPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/sync", s.handleSync)
	mux.HandleFunc("/v1/catalog", s.handleCatalog)
	mux.HandleFunc("/v1/install", s.handleInstall)
	mux.HandleFunc("/v1/uninstall", s.handleUninstall)

	srv := &http.Server{
		Handler:           s.peerCredMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ConnContext: func(cCtx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*net.UnixConn); ok {
				if raw, err := uc.SyscallConn(); err == nil {
					var ucred *syscall.Ucred
					_ = raw.Control(func(fd uintptr) {
						cred, credErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
						if credErr == nil {
							ucred = cred
						}
					})
					if ucred != nil {
						return context.WithValue(cCtx, peerCredKey{}, ucred)
					}
				}
			}
			return cCtx
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = os.Remove(s.socketPath)
	}()

	log.Printf("[ipc] listening on unix socket %s (mode 0666 + SO_PEERCRED)", s.socketPath)
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// GetActiveSeat0UID returns the numeric UID of the active graphical console user on seat0.
func GetActiveSeat0UID() (uint32, error) {
	// 1. Environment override for automated/container test harnesses
	if envVal := strings.TrimSpace(os.Getenv("SPIRE_SEAT0_UID")); envVal != "" {
		if uidVal, err := strconv.ParseUint(envVal, 10, 32); err == nil {
			return uint32(uidVal), nil
		}
	}

	// 2. Parse /run/systemd/seats/seat0 state file if present
	const seat0Path = "/run/systemd/seats/seat0"
	if f, err := os.Open(seat0Path); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		var activeSessionID string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "ACTIVE_UID=") {
				val := strings.TrimPrefix(line, "ACTIVE_UID=")
				if u, err := strconv.ParseUint(val, 10, 32); err == nil {
					return uint32(u), nil
				}
			} else if strings.HasPrefix(line, "ACTIVE=") {
				activeSessionID = strings.TrimPrefix(line, "ACTIVE=")
			}
		}
		if activeSessionID != "" {
			sessPath := filepath.Join("/run/systemd/sessions", activeSessionID)
			if sf, sErr := os.Open(sessPath); sErr == nil {
				defer sf.Close()
				sScanner := bufio.NewScanner(sf)
				for sScanner.Scan() {
					sLine := strings.TrimSpace(sScanner.Text())
					if strings.HasPrefix(sLine, "UID=") {
						val := strings.TrimPrefix(sLine, "UID=")
						if u, err := strconv.ParseUint(val, 10, 32); err == nil {
							return uint32(u), nil
						}
					}
				}
			}
		}
	}

	// 3. Fallback to loginctl list-sessions / show-seat
	if _, lookErr := exec.LookPath("loginctl"); lookErr == nil {
		out, err := exec.Command("loginctl", "show-seat", "seat0", "-p", "ActiveSession", "--value").Output()
		if err == nil {
			activeSession := strings.TrimSpace(string(out))
			if activeSession != "" && activeSession != "(null)" {
				uidOut, uErr := exec.Command("loginctl", "show-session", activeSession, "-p", "User", "--value").Output()
				if uErr == nil {
					val := strings.TrimSpace(string(uidOut))
					if u, err := strconv.ParseUint(val, 10, 32); err == nil {
						return uint32(u), nil
					}
				}
			}
		}
	}

	// 4. Fallback to inventory.GetActiveSessionDetails()
	if _, uidStr, err := inventory.GetActiveSessionDetails(); err == nil && uidStr != "" {
		if u, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
			return uint32(u), nil
		}
	}

	return 0, errors.New("no active console session user found on seat0")
}

// PeerCredMiddlewareForTest exposes peerCredMiddleware for unit testing.
func (s *Server) PeerCredMiddlewareForTest(next http.Handler) http.Handler {
	return s.peerCredMiddleware(next)
}

func (s *Server) peerCredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ucred, ok := r.Context().Value(peerCredKey{}).(*syscall.Ucred)
		if !ok || ucred == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "Caller is not the active console session user",
			})
			return
		}

		// Enforce a strict 1 MiB request body limit on all local IPC requests
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}

		// Root (UID 0) is unconditionally authorized
		if ucred.Uid == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Non-root UIDs must match the active console session user on seat0
		seat0UID, err := GetActiveSeat0UID()
		if err != nil || ucred.Uid != seat0UID {
			log.Printf("[ipc] HTTP 403 authorization failure: caller UID %d != active seat0 UID %d (err=%v)", ucred.Uid, seat0UID, err)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "Caller is not the active console session user",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	st := s.buildPartitionedStatus(r.Context())
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) buildPartitionedStatus(ctx context.Context) AgentStatus {
	s.mu.RLock()
	st := s.lastStatus
	assigned := append([]types.AssignedPolicy(nil), s.assignedPolicies...)
	results := append([]types.PolicyExecutionItem(nil), s.policyResults...)
	s.mu.RUnlock()

	pkgs, _ := inventory.GetInstalledPackages()
	installedPkgs := engine.BuildInstalledPackageMap(pkgs)
	_, installedFlatpaks := engine.GetInstalledFlatpaks(ctx)

	if len(assigned) == 0 {
		if cached, err := engine.LoadPolicyCache(engine.DefaultPolicyCachePath); err == nil && cached != nil {
			assigned = cached.Policies
			if st.DeviceID == "" || st.DeviceID == s.hwUUID {
				if strings.TrimSpace(cached.DeviceID) != "" {
					st.DeviceID = strings.TrimSpace(cached.DeviceID)
				}
			}
		}
	}

	catalog, _ := s.fetchOrLoadCatalog(ctx)

	// Query server's authoritative partitioned status if connected & token present, then reconcile with live host inventory
	if serverStatus, err := s.fetchServerDeviceStatus(ctx); err == nil && serverStatus != nil {
		if strings.TrimSpace(serverStatus.DeviceID) != "" {
			st.DeviceID = strings.TrimSpace(serverStatus.DeviceID)
		}
		localResMap := make(map[string]types.PolicyExecutionItem, len(results))
		for _, r := range results {
			localResMap[r.PolicyID] = r
		}

		st.SecurityPolicies = make([]types.PolicyStatusItem, 0, len(serverStatus.SecurityPolicies))
		for _, sp := range serverStatus.SecurityPolicies {
			if sp.ComplianceStatus == types.CompliancePending {
				if lr, ok := localResMap[sp.PolicyID]; ok && lr.ComplianceStatus != "" {
					sp.ComplianceStatus = lr.ComplianceStatus
					sp.IsCompliant = lr.ComplianceStatus == types.ComplianceCompliant
					sp.ErrorMessage = lr.ErrorMessage
				}
			}
			st.SecurityPolicies = append(st.SecurityPolicies, sp)
		}

		st.MandatoryApps = make([]types.AppStatusItem, 0, len(serverStatus.MandatoryApps))
		for _, ma := range serverStatus.MandatoryApps {
			if ma.PolicyType == types.PolicyTypeFlatpakApp && installedFlatpaks != nil && ma.AppID != "" {
				ma.Installed = installedFlatpaks[ma.AppID]
			} else if ma.PolicyType == types.PolicyTypePackagePresence && installedPkgs != nil && ma.AppID != "" {
				ma.Installed = installedPkgs[ma.AppID]
			}
			ma.IsCompliant = ma.Installed
			if ma.Installed {
				ma.ComplianceStatus = types.ComplianceCompliant
			} else {
				ma.ComplianceStatus = types.ComplianceNonCompliant
			}
			st.MandatoryApps = append(st.MandatoryApps, ma)
		}

		st.AvailableCatalog = make([]types.CatalogAppItem, 0, len(serverStatus.AvailableCatalog))
		for _, ca := range serverStatus.AvailableCatalog {
			if ca.PolicyType == types.PolicyTypeFlatpakApp && installedFlatpaks != nil && ca.AppID != "" {
				ca.Installed = installedFlatpaks[ca.AppID]
			} else if ca.PolicyType == types.PolicyTypePackagePresence && installedPkgs != nil && ca.AppID != "" {
				ca.Installed = installedPkgs[ca.AppID]
			}
			st.AvailableCatalog = append(st.AvailableCatalog, ca)
		}
	} else {
		eval := engine.EvaluateDeviceCompliance(st.DeviceID, assigned, results, catalog, installedPkgs, installedFlatpaks)
		st.SecurityPolicies = eval.SecurityPolicies
		st.MandatoryApps = eval.MandatoryApps
		st.AvailableCatalog = eval.AvailableCatalog
	}

	if st.SecurityPolicies == nil {
		st.SecurityPolicies = make([]types.PolicyStatusItem, 0)
	}
	if st.MandatoryApps == nil {
		st.MandatoryApps = make([]types.AppStatusItem, 0)
	}
	if st.AvailableCatalog == nil {
		st.AvailableCatalog = make([]types.CatalogAppItem, 0)
	}

	// Core Rule: Overall compliance depends strictly on SecurityPolicies and MandatoryApps (REQUIRED).
	// Optional (AVAILABLE) catalog applications never impact IsCompliant or FailedPolicies.
	compliantCount := 0
	failedCount := 0
	isCompliant := true
	for _, sp := range st.SecurityPolicies {
		if sp.IsCompliant {
			compliantCount++
		} else {
			failedCount++
			isCompliant = false
		}
	}
	for _, ma := range st.MandatoryApps {
		if ma.IsCompliant {
			compliantCount++
		} else {
			failedCount++
			isCompliant = false
		}
	}

	st.IsCompliant = isCompliant
	if len(st.SecurityPolicies)+len(st.MandatoryApps) > 0 {
		st.CompliantPolicies = compliantCount
		st.FailedPolicies = failedCount
		st.TotalPolicies = compliantCount + failedCount
		if isCompliant {
			st.ComplianceState = string(types.ComplianceCompliant)
		} else {
			st.ComplianceState = string(types.ComplianceNonCompliant)
		}
	}

	return st
}

func (s *Server) fetchServerDeviceStatus(ctx context.Context) (*types.DeviceStatusResponse, error) {
	token := s.readToken()
	if token == "" || strings.TrimSpace(s.serverURL) == "" {
		return nil, errors.New("missing token or server URL")
	}
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.serverURL+"/api/v1/desktop/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status HTTP %d", resp.StatusCode)
	}
	var statusResp types.DeviceStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return nil, err
	}
	return &statusResp, nil
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.syncFunc != nil {
		if err := s.syncFunc(r.Context()); err != nil {
			log.Printf("[ipc] on-demand sync error: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
	} else if s.triggerCh != nil {
		select {
		case s.triggerCh <- struct{}{}:
		default:
		}
	}

	s.mu.RLock()
	st := s.lastStatus
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "synced",
		"last_checkin_at":  st.LastCheckinAt,
		"compliance_state": st.ComplianceState,
	})
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	items, err := s.fetchOrLoadCatalog(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	pkgs, _ := inventory.GetInstalledPackages()
	installedPkgs := engine.BuildInstalledPackageMap(pkgs)
	_, installedFlatpaks := engine.GetInstalledFlatpaks(r.Context())

	for i := range items {
		invInst, hasInv := engine.IsApplicationInstalled(items[i].PolicyType, items[i].Payload, installedPkgs, installedFlatpaks)
		if hasInv && invInst {
			items[i].Installed = true
		}
		if items[i].AssignmentType == "" {
			items[i].AssignmentType = types.AssignmentAvailable
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"catalog": items,
	})
}

func (s *Server) findInstallablePolicy(ctx context.Context, target string) (*types.SelfServiceCatalogItem, error) {
	catalog, catErr := s.fetchOrLoadCatalog(ctx)
	for i := range catalog {
		item := &catalog[i]
		if strings.EqualFold(item.PolicyID, target) || strings.EqualFold(item.Name, target) || payloadMatchesIdentifier(item, target) {
			return item, nil
		}
	}

	// Also search assigned policies (e.g. REQUIRED application policies) in memory or local policy cache
	s.mu.RLock()
	assigned := append([]types.AssignedPolicy(nil), s.assignedPolicies...)
	s.mu.RUnlock()

	if len(assigned) == 0 {
		if cached, err := engine.LoadPolicyCache(engine.DefaultPolicyCachePath); err == nil && cached != nil {
			assigned = cached.Policies
		}
	}

	for _, pol := range assigned {
		cand := &types.SelfServiceCatalogItem{
			PolicyID:       pol.ID,
			Name:           pol.Name,
			PolicyType:     pol.PolicyType,
			AssignmentType: engine.ResolveAssignmentType(pol.AssignmentType, pol.Payload),
			Payload:        pol.Payload,
		}
		if strings.EqualFold(cand.PolicyID, target) || strings.EqualFold(cand.Name, target) || payloadMatchesIdentifier(cand, target) {
			return cand, nil
		}
	}

	// Also check server status if policy was just staged and not yet in local cache
	if srvSt, err := s.fetchServerDeviceStatus(ctx); err == nil && srvSt != nil {
		for _, ma := range srvSt.MandatoryApps {
			if strings.EqualFold(ma.PolicyID, target) || strings.EqualFold(ma.Name, target) || strings.EqualFold(ma.AppID, target) {
				rawPayload, _ := json.Marshal(types.ApplicationPolicyPayload{
					AppID:          ma.AppID,
					PackageName:    ma.AppID,
					Version:        ma.Version,
					AssignmentType: types.AssignmentRequired,
				})
				return &types.SelfServiceCatalogItem{
					PolicyID:       ma.PolicyID,
					Name:           ma.Name,
					PolicyType:     ma.PolicyType,
					AssignmentType: types.AssignmentRequired,
					Payload:        rawPayload,
				}, nil
			}
		}
		for _, ca := range srvSt.AvailableCatalog {
			if strings.EqualFold(ca.PolicyID, target) || strings.EqualFold(ca.Name, target) || strings.EqualFold(ca.AppID, target) {
				rawPayload := ca.Payload
				if len(rawPayload) == 0 {
					rawPayload, _ = json.Marshal(types.ApplicationPolicyPayload{
						AppID:          ca.AppID,
						PackageName:    ca.AppID,
						Version:        ca.Version,
						AssignmentType: types.AssignmentAvailable,
					})
				}
				return &types.SelfServiceCatalogItem{
					PolicyID:       ca.PolicyID,
					Name:           ca.Name,
					Description:    ca.Description,
					PolicyType:     ca.PolicyType,
					AssignmentType: types.AssignmentAvailable,
					Payload:        rawPayload,
				}, nil
			}
		}
	}

	if catErr != nil {
		return nil, fmt.Errorf("unable to load self-service catalog: %v", catErr)
	}
	return nil, nil
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request payload"})
		return
	}
	target := strings.TrimSpace(req.PolicyID)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id is required"})
		return
	}

	matched, err := s.findInstallablePolicy(r.Context(), target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if matched == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("policy %q not found in self-service catalog", target),
		})
		return
	}

	token := s.readToken()
	if token == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device is not enrolled/approved"})
		return
	}

	// 1. Notify spire-server via POST /api/v1/desktop/self-service/install
	installReqBody, _ := json.Marshal(types.SelfServiceInstallRequest{
		HardwareUUID: s.hwUUID,
		PolicyID:     matched.PolicyID,
	})
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.serverURL+"/api/v1/desktop/self-service/install", bytes.NewReader(installReqBody))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("failed to notify server: %v", err)})
		return
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, resp.StatusCode, map[string]string{
			"error": fmt.Sprintf("server rejected self-service install (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes))),
		})
		return
	}

	// 2. Execute the policy locally via spired's engine without requiring user sudo rights
	// Use dedicated execution context with generous timeout so large downloads are never cancelled prematurely
	execCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if s.engineMu != nil {
		s.engineMu.Lock()
	}
	execItem := s.executeCatalogItem(execCtx, *matched)
	if s.engineMu != nil {
		s.engineMu.Unlock()
	}

	// 3. Report compliance outcome to POST /api/v1/desktop/report
	if repErr := s.reportSinglePolicyResult(execCtx, token, execItem); repErr != nil {
		log.Printf("[ipc] warning: failed to report self-service install compliance for policy=%s: %v", matched.PolicyID, repErr)
	}

	// 4. Refresh cached catalog and trigger background sync
	_, _ = s.fetchOrLoadCatalog(execCtx)
	if s.triggerCh != nil {
		select {
		case s.triggerCh <- struct{}{}:
		default:
		}
	}

	if execItem.ComplianceStatus != types.ComplianceCompliant {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status":            "failed",
			"policy_id":         matched.PolicyID,
			"name":              matched.Name,
			"compliance_status": execItem.ComplianceStatus,
			"error":             execItem.ErrorMessage,
		})
		return
	}

	log.Printf("[ipc] installed self-service policy id=%s name=%q status=%s", matched.PolicyID, matched.Name, execItem.ComplianceStatus)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "installed",
		"policy_id":         matched.PolicyID,
		"name":              matched.Name,
		"policy_type":       matched.PolicyType,
		"compliance_status": execItem.ComplianceStatus,
	})
}

func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request payload"})
		return
	}
	target := strings.TrimSpace(req.PolicyID)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id is required"})
		return
	}

	matched, err := s.findInstallablePolicy(r.Context(), target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if matched == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("policy %q not found in self-service catalog", target),
		})
		return
	}

	token := s.readToken()
	if token == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device is not enrolled/approved"})
		return
	}

	// 1. Notify spire-server via POST /api/v1/desktop/self-service/uninstall
	uninstallReqBody, _ := json.Marshal(types.SelfServiceUninstallRequest{
		HardwareUUID: s.hwUUID,
		PolicyID:     matched.PolicyID,
	})
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.serverURL+"/api/v1/desktop/self-service/uninstall", bytes.NewReader(uninstallReqBody))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("failed to notify server: %v", err)})
		return
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, resp.StatusCode, map[string]string{
			"error": fmt.Sprintf("server rejected self-service uninstall (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes))),
		})
		return
	}

	// 2. Execute uninstallation locally with a generous timeout
	execCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if s.engineMu != nil {
		s.engineMu.Lock()
	}
	execItem := s.uninstallCatalogItem(execCtx, *matched)
	if s.engineMu != nil {
		s.engineMu.Unlock()
	}

	// 3. Report compliance outcome to POST /api/v1/desktop/report
	if repErr := s.reportSinglePolicyResult(execCtx, token, execItem); repErr != nil {
		log.Printf("[ipc] warning: failed to report self-service uninstall compliance for policy=%s: %v", matched.PolicyID, repErr)
	}

	// 4. Refresh cached catalog and trigger background sync
	_, _ = s.fetchOrLoadCatalog(execCtx)
	if s.triggerCh != nil {
		select {
		case s.triggerCh <- struct{}{}:
		default:
		}
	}

	log.Printf("[ipc] uninstalled self-service policy id=%s name=%q status=%s", matched.PolicyID, matched.Name, execItem.ComplianceStatus)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "uninstalled",
		"policy_id":         matched.PolicyID,
		"name":              matched.Name,
		"policy_type":       matched.PolicyType,
		"compliance_status": execItem.ComplianceStatus,
	})
}

func (s *Server) uninstallCatalogItem(ctx context.Context, item types.SelfServiceCatalogItem) types.PolicyExecutionItem {
	outcomeStatus := types.ComplianceRevoked
	if engine.ResolveAssignmentType(item.AssignmentType, item.Payload) == types.AssignmentRequired && item.AssignmentType != "" {
		outcomeStatus = types.ComplianceNonCompliant
	}

	switch item.PolicyType {
	case types.PolicyTypeFlatpakApp:
		var payload types.FlatpakAppPayload
		_ = json.Unmarshal(item.Payload, &payload)
		appID := strings.TrimSpace(payload.AppID)
		if appID != "" {
			if _, err := exec.LookPath("flatpak"); err == nil {
				_ = exec.CommandContext(ctx, "flatpak", "uninstall", "-y", "--system", appID).Run()
			}
			engine.RemoveFlatpakDesktopExports(appID)
		}
		meta, _ := json.Marshal(map[string]any{
			"app_id":     appID,
			"state":      "absent",
			"action":     "self_service_uninstalled",
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         item.PolicyID,
			ComplianceStatus: outcomeStatus,
			ExecutionOutput:  meta,
		}

	case types.PolicyTypeFlatpakBundle:
		var payload types.FlatpakBundlePayload
		_ = json.Unmarshal(item.Payload, &payload)
		cmdOut := engine.UninstallAndCleanFlatpakBundle(ctx, payload.AppID, payload.SHA256)
		meta, _ := json.Marshal(map[string]any{
			"app_id":     payload.AppID,
			"sha256":     payload.SHA256,
			"state":      "absent",
			"output":     cmdOut,
			"action":     "self_service_uninstalled",
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         item.PolicyID,
			ComplianceStatus: outcomeStatus,
			ExecutionOutput:  meta,
		}

	case types.PolicyTypePackagePresence:
		var payload types.PackagePresencePayload
		_ = json.Unmarshal(item.Payload, &payload)
		pkg := strings.TrimSpace(payload.PackageName)
		if pkg != "" {
			if _, err := exec.LookPath("apt-get"); err == nil {
				_ = exec.CommandContext(ctx, "apt-get", "remove", "-y", pkg).Run()
			}
		}
		meta, _ := json.Marshal(map[string]any{
			"package_name": pkg,
			"action":       "self_service_uninstalled",
			"checked_at":   time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         item.PolicyID,
			ComplianceStatus: outcomeStatus,
			ExecutionOutput:  meta,
		}

	default:
		return types.PolicyExecutionItem{
			PolicyID:         item.PolicyID,
			ComplianceStatus: outcomeStatus,
		}
	}
}

func forceAutoInstallPayload(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	m["auto_install"] = true
	updated, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return updated
}

func (s *Server) executeCatalogItem(ctx context.Context, item types.SelfServiceCatalogItem) types.PolicyExecutionItem {
	pol := types.AssignedPolicy{
		ID:             item.PolicyID,
		Name:           item.Name,
		PolicyType:     item.PolicyType,
		AssignmentType: item.AssignmentType,
		Payload:        forceAutoInstallPayload(item.Payload),
		Version:        1,
	}

	switch item.PolicyType {
	case types.PolicyTypePackagePresence:
		pkgs, _ := inventory.GetInstalledPackages()
		installedMap := engine.BuildInstalledPackageMap(pkgs)
		return engine.ReconcilePackagePresence(ctx, pol, installedMap)
	case types.PolicyTypePackageAbsence:
		pkgs, _ := inventory.GetInstalledPackages()
		installedMap := engine.BuildInstalledPackageMap(pkgs)
		return engine.ReconcilePackageAbsence(ctx, pol, installedMap)
	case types.PolicyTypeFlatpakApp:
		_, installedFlatpaks := engine.GetInstalledFlatpaks(ctx)
		return engine.ReconcileFlatpakApp(ctx, pol, installedFlatpaks)
	case types.PolicyTypeFlatpakBundle:
		_, installedFlatpaks := engine.GetInstalledFlatpaks(ctx)
		return engine.ReconcileFlatpakBundle(ctx, pol, installedFlatpaks, s.httpClient, s.serverURL, s.readToken())
	case types.PolicyTypeDconfSetting:
		execItem, drifted := engine.ReconcileDconfSetting(ctx, pol)
		if drifted {
			if _, err := engine.RunDconfUpdate(ctx); err != nil && execItem.ComplianceStatus == types.ComplianceCompliant {
				execItem.ComplianceStatus = types.ComplianceFailed
				execItem.ErrorMessage = err.Error()
			}
		}
		return execItem
	case types.PolicyTypeSystemdService:
		return engine.EnforceSystemdServicePolicy(ctx, pol)
	default:
		return types.PolicyExecutionItem{
			PolicyID:         item.PolicyID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("unsupported self-service policy type: %s", item.PolicyType),
		}
	}
}

func (s *Server) reportSinglePolicyResult(ctx context.Context, token string, item types.PolicyExecutionItem) error {
	payload, _ := json.Marshal(types.PolicyReportRequest{
		HardwareUUID: s.hwUUID,
		Results:      []types.PolicyExecutionItem{item},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL+"/api/v1/desktop/report", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *Server) fetchOrLoadCatalog(ctx context.Context) ([]types.SelfServiceCatalogItem, error) {
	token := s.readToken()
	if token != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.serverURL+"/api/v1/desktop/self-service/catalog", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, doErr := s.httpClient.Do(req)
			if doErr == nil {
				bodyBytes, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var wrapper struct {
						Catalog []types.SelfServiceCatalogItem `json:"catalog"`
					}
					if jsonErr := json.Unmarshal(bodyBytes, &wrapper); jsonErr == nil {
						_ = saveCatalogCache(DefaultCatalogCachePath, wrapper.Catalog)
						return wrapper.Catalog, nil
					}
				}
			}
		}
	}

	cached, err := loadCatalogCache(DefaultCatalogCachePath)
	if err != nil {
		return nil, fmt.Errorf("unable to reach server and no local catalog cache available: %w", err)
	}
	return cached, nil
}

func saveCatalogCache(path string, items []types.SelfServiceCatalogItem) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func loadCatalogCache(path string) ([]types.SelfServiceCatalogItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []types.SelfServiceCatalogItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func payloadMatchesIdentifier(item *types.SelfServiceCatalogItem, target string) bool {
	if item == nil {
		return false
	}
	targetLower := strings.ToLower(strings.TrimSpace(target))
	if targetLower == "" {
		return false
	}
	if strings.Contains(strings.ToLower(item.Name), targetLower) {
		return true
	}
	if targetLower == "vscode" && (strings.Contains(strings.ToLower(item.Name), "code") || strings.Contains(strings.ToLower(string(item.Payload)), "code")) {
		return true
	}
	if len(item.Payload) == 0 {
		return false
	}
	var raw map[string]any
	if err := json.Unmarshal(item.Payload, &raw); err != nil {
		return false
	}
	for _, key := range []string{"package_name", "app_id", "service_name"} {
		if val, ok := raw[key].(string); ok {
			valLower := strings.ToLower(strings.TrimSpace(val))
			if valLower == targetLower || strings.Contains(valLower, targetLower) {
				return true
			}
		}
	}
	return false
}

func (s *Server) readToken() string {
	data, err := os.ReadFile(s.tokenPath)
	if err != nil {
		return ""
	}
	tok := strings.Clone(strings.TrimSpace(string(data)))
	clear(data)
	return tok
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
