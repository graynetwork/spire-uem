package ipc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// browserCertIssuesPerHour caps issue requests from one local uid.
	browserCertIssuesPerHour = 6
	browserCertCAFile        = "browser-device-ca.pem"
	minLocalUID              = 1000
	// firstNonUserUID is where "nobody" and the reserved ids start (65534 and above).
	firstNonUserUID = 65534
)

// BrowserCertConfig is the body of GET /v1/browser-cert/config.
type BrowserCertConfig struct {
	// Enabled is true while a BROWSER_CERTIFICATE policy is assigned to this device.
	Enabled bool `json:"enabled"`
	// Eligible is true when the calling account may hold a browser certificate (a regular
	// local user, not root or a system account).
	Eligible bool `json:"eligible"`
	// DeviceCAPEM is the device CA certificate, once the agent has seen it. It can be empty
	// before the first certificate is issued.
	DeviceCAPEM string `json:"device_ca_pem,omitempty"`
}

// BrowserCertIssueRequest is the body of POST /v1/browser-cert/issue. It carries only the
// CSR: the account name always comes from the caller's uid.
type BrowserCertIssueRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// BrowserCertIssueResponse is returned by POST /v1/browser-cert/issue.
type BrowserCertIssueResponse struct {
	User           string `json:"user"`
	CertificatePEM string `json:"certificate_pem"`
	DeviceCAPEM    string `json:"device_ca_pem"`
	NotAfter       string `json:"not_after"`
}

// browserCertState is the per-server state for browser certificates.
type browserCertState struct {
	mu      sync.Mutex
	issues  map[uint32][]time.Time // issue attempts per uid within the last hour
	lookup  func(uid uint32) (string, error)
	uidMin  func() uint32
	now     func() time.Time
	perHour int
}

func (s *Server) bcState() *browserCertState {
	s.bcOnce.Do(func() {
		s.bc = &browserCertState{
			issues:  map[uint32][]time.Time{},
			lookup:  lookupUserName,
			uidMin:  localUIDMin,
			now:     time.Now,
			perHour: browserCertIssuesPerHour,
		}
	})
	return s.bc
}

func lookupUserName(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// loginDefsPath is where the distribution's UID_MIN lives. Tests override it.
var loginDefsPath = "/etc/login.defs"

// localUIDMin returns the lowest uid that counts as a regular user: the larger of 1000 and the
// distribution's UID_MIN.
func localUIDMin() uint32 {
	min := uint32(minLocalUID)
	f, err := os.Open(loginDefsPath)
	if err != nil {
		return min
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "UID_MIN" {
			if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil && uint32(v) > min {
				min = uint32(v)
			}
		}
	}
	return min
}

// browserCertEnabled reports whether a BROWSER_CERTIFICATE policy is assigned to the device.
func (s *Server) browserCertEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.assignedPolicies {
		if p.PolicyType == types.PolicyTypeBrowserCertificate {
			return true
		}
	}
	return false
}

func (s *Server) browserCertCAPath() string {
	return filepath.Join(filepath.Dir(s.tokenPath), browserCertCAFile)
}

func (s *Server) readBrowserCertCA() string {
	if strings.TrimSpace(s.tokenPath) == "" {
		return ""
	}
	b, err := os.ReadFile(s.browserCertCAPath())
	if err != nil {
		return ""
	}
	return string(b)
}

// eligibleBrowserUser maps the peer uid to a local account name. It refuses root, system
// accounts (uid below max(1000, UID_MIN), and 65534 and above) and names that would not be
// accepted in a certificate.
func (b *browserCertState) eligibleBrowserUser(uid uint32) (string, error) {
	if uid == 0 {
		return "", fmt.Errorf("root cannot hold a browser certificate")
	}
	if uid < b.uidMin() || uid >= firstNonUserUID {
		return "", fmt.Errorf("uid %d is a system account", uid)
	}
	name, err := b.lookup(uid)
	if err != nil || name == "" {
		return "", fmt.Errorf("uid %d has no local account name", uid)
	}
	if !crypto.ValidCertUser(name) {
		return "", fmt.Errorf("account name %q cannot be used in a certificate", name)
	}
	return name, nil
}

func peerUcred(r *http.Request) *syscall.Ucred {
	uc, _ := r.Context().Value(peerCredKey{}).(*syscall.Ucred)
	return uc
}

// handleBrowserCertConfig serves GET /v1/browser-cert/config.
func (s *Server) handleBrowserCertConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	uc := peerUcred(r)
	if uc == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no peer credentials"})
		return
	}
	_, err := s.bcState().eligibleBrowserUser(uc.Uid)
	writeJSON(w, http.StatusOK, BrowserCertConfig{
		Enabled:     s.browserCertEnabled(),
		Eligible:    err == nil,
		DeviceCAPEM: s.readBrowserCertCA(),
	})
}

// handleBrowserCertIssue serves POST /v1/browser-cert/issue. The certificate is for the
// account that owns the calling process; nothing in the request names a user.
func (s *Server) handleBrowserCertIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	uc := peerUcred(r)
	if uc == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no peer credentials"})
		return
	}
	bc := s.bcState()
	name, err := bc.eligibleBrowserUser(uc.Uid)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if !s.browserCertEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no BROWSER_CERTIFICATE policy is assigned to this device"})
		return
	}
	var req BrowserCertIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	csr := strings.TrimSpace(req.CSRPEM)
	if err := checkBrowserCSR(csr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !bc.allow(uc.Uid) {
		w.Header().Set("Retry-After", "600")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many certificate requests; try again later"})
		return
	}
	resp, err := s.forwardBrowserCertIssue(r.Context(), name, csr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// allow records an issue attempt for the uid and reports whether it is within the hourly cap.
func (b *browserCertState) allow(uid uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	cutoff := now.Add(-time.Hour)
	kept := b.issues[uid][:0]
	for _, t := range b.issues[uid] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= b.perHour {
		b.issues[uid] = kept
		return false
	}
	b.issues[uid] = append(kept, now)
	return true
}

// checkBrowserCSR accepts only a well-formed PKCS#10 request, signed by its own key, for an
// ECDSA P-256 key.
func checkBrowserCSR(csrPEM string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return fmt.Errorf("csr_pem is not a PEM CERTIFICATE REQUEST block")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("csr_pem does not parse: %v", err)
	}
	if err := req.CheckSignature(); err != nil {
		return fmt.Errorf("csr signature is invalid")
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("the key must be ECDSA P-256")
	}
	return nil
}

// forwardBrowserCertIssue sends the CSR to the control plane over the agent's own mTLS client
// and the device bearer token, naming the account the IPC peer owns.
func (s *Server) forwardBrowserCertIssue(ctx context.Context, userName, csrPEM string) (*BrowserCertIssueResponse, error) {
	token := s.readToken()
	if token == "" || strings.TrimSpace(s.serverURL) == "" {
		return nil, fmt.Errorf("agent not enrolled")
	}
	body, _ := json.Marshal(types.DeviceCertIssueRequest{
		Purpose: types.CertPurposeBrowser,
		CSRPEM:  csrPEM,
		User:    userName,
	})
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.serverURL+"/api/v1/desktop/cert/issue", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("control plane unreachable")
	}
	defer httpResp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = "control plane refused the request"
		}
		return nil, fmt.Errorf("server returned HTTP %d: %s", httpResp.StatusCode, e.Error)
	}
	var out types.DeviceCertIssueResponse
	if err := json.Unmarshal(data, &out); err != nil || strings.TrimSpace(out.DeviceCertificatePEM) == "" {
		return nil, fmt.Errorf("control plane returned no certificate")
	}
	if out.Purpose != types.CertPurposeBrowser {
		return nil, fmt.Errorf("control plane returned a %q certificate, not a browser certificate", out.Purpose)
	}
	if ca := strings.TrimSpace(out.DeviceCACertPEM); ca != "" && strings.TrimSpace(s.tokenPath) != "" {
		_ = os.WriteFile(s.browserCertCAPath(), []byte(ca+"\n"), 0644)
	}
	return &BrowserCertIssueResponse{
		User:           userName,
		CertificatePEM: strings.TrimSpace(out.DeviceCertificatePEM) + "\n",
		DeviceCAPEM:    strings.TrimSpace(out.DeviceCACertPEM) + "\n",
		NotAfter:       out.NotAfter,
	}, nil
}

// HandleBrowserCertConfigForTest and HandleBrowserCertIssueForTest expose the handlers, and
// SetBrowserCertHooksForTest swaps the uid lookup and system-account threshold, for tests.
func (s *Server) HandleBrowserCertConfigForTest(w http.ResponseWriter, r *http.Request) {
	s.handleBrowserCertConfig(w, r)
}

func (s *Server) HandleBrowserCertIssueForTest(w http.ResponseWriter, r *http.Request) {
	s.handleBrowserCertIssue(w, r)
}

func (s *Server) SetBrowserCertHooksForTest(lookup func(uid uint32) (string, error), uidMin func() uint32, perHour int) {
	bc := s.bcState()
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if lookup != nil {
		bc.lookup = lookup
	}
	if uidMin != nil {
		bc.uidMin = uidMin
	}
	if perHour > 0 {
		bc.perHour = perHour
	}
}

// SetLoginDefsPathForTest points the UID_MIN lookup at another file and returns a restore func.
func SetLoginDefsPathForTest(p string) func() {
	old := loginDefsPath
	loginDefsPath = p
	return func() { loginDefsPath = old }
}

// LocalUIDMinForTest returns the system-account threshold in force.
func LocalUIDMinForTest() uint32 { return localUIDMin() }
