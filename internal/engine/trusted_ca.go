package engine

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// TRUSTED_CA_CERTIFICATES engine: writes PEM CA certs to the system trust-anchor directory under a
// spire-owned subdirectory, runs update-ca-certificates, and removes spire-managed certs that are no
// longer present in the policy. Compliance is reported by SHA-256 fingerprint of each cert.

var (
	// caRoot is the filesystem root. "" means the real root ("/"). Tests set a temp dir.
	caRoot = ""
	// findUpdateCACertsBin locates update-ca-certificates. Overridden in tests.
	findUpdateCACertsBin = FindUpdateCACertsBinary
	// runUpdateCACerts runs update-ca-certificates. Overridden in tests with a fake.
	runUpdateCACerts = defaultRunUpdateCACerts

	validCANameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

// caSpireDirRel is the spire-owned subdirectory of the local trust-anchor source directory.
const caSpireDirRel = "usr/local/share/ca-certificates/spire"

// FindUpdateCACertsBinary locates update-ca-certificates in standard directories.
func FindUpdateCACertsBinary() (string, error) {
	for _, p := range []string{"/usr/sbin/update-ca-certificates", "/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("update-ca-certificates executable not found in standard directories")
}

// defaultRunUpdateCACerts runs update-ca-certificates and returns combined output.
func defaultRunUpdateCACerts(ctx context.Context) (string, error) {
	bin, err := findUpdateCACertsBin()
	if err != nil {
		return "", err
	}
	out, runErr := exec.CommandContext(ctx, bin).CombinedOutput()
	return string(out), runErr
}

// caSpireDir returns the absolute spire cert directory honoring caRoot.
func caSpireDir() string {
	if caRoot == "" {
		return "/" + caSpireDirRel
	}
	return filepath.Join(caRoot, caSpireDirRel)
}

// ParseCACertificate decodes a PEM block and verifies it parses as an X.509 CA certificate.
// Returns the parsed certificate and its lowercase hex SHA-256 fingerprint. Shared with the server
// so invalid or non-CA certs are rejected before storage, and subject/expiry can be displayed.
func ParseCACertificate(pemText string) (*x509.Certificate, string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, "", fmt.Errorf("certificate %q is not a CA certificate (BasicConstraints CA=false)", cert.Subject.CommonName)
	}
	sum := sha256.Sum256(cert.Raw)
	return cert, hex.EncodeToString(sum[:]), nil
}

// validateTrustedCAPayload validates a TRUSTED_CA_CERTIFICATES payload at the trust boundary.
func validateTrustedCAPayload(p types.TrustedCACertificatesPayload) error {
	if len(p.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required")
	}
	seen := make(map[string]bool)
	for i, c := range p.Certificates {
		name := strings.TrimSpace(c.Name)
		if name == "" || !validCANameRe.MatchString(name) || strings.Contains(name, "..") {
			return fmt.Errorf("certificates[%d]: invalid name %q", i, c.Name)
		}
		if seen[name] {
			return fmt.Errorf("certificates[%d]: duplicate name %q", i, name)
		}
		seen[name] = true
		if _, _, err := ParseCACertificate(c.PEM); err != nil {
			return fmt.Errorf("certificates[%d] (%s): %w", i, name, err)
		}
	}
	return nil
}

// normalizePEM re-encodes a parsed cert to canonical PEM so on-disk content is stable.
func normalizePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EnforceTrustedCACertificates writes the desired CA certs, removes spire-managed orphans, runs
// update-ca-certificates, and reports compliance by fingerprint.
func EnforceTrustedCACertificates(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.TrustedCACertificatesPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return failItem(policy.ID, fmt.Sprintf("invalid TRUSTED_CA_CERTIFICATES payload: %v", err), nil)
	}
	if err := validateTrustedCAPayload(payload); err != nil {
		return failItem(policy.ID, err.Error(), nil)
	}

	dir := caSpireDir()
	details := map[string]any{
		"policy_id": policy.ID,
		"dir":       dir,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return failItem(policy.ID, fmt.Sprintf("mkdir %s: %v", dir, err), details)
	}

	// Desired file set (<name>.crt) and fingerprints.
	desiredFiles := make(map[string]bool, len(payload.Certificates))
	fingerprints := make(map[string]string, len(payload.Certificates))
	changed := false

	names := make([]string, 0, len(payload.Certificates))
	certByName := make(map[string]types.TrustedCACertificate, len(payload.Certificates))
	for _, c := range payload.Certificates {
		name := strings.TrimSpace(c.Name)
		names = append(names, name)
		certByName[name] = c
	}
	sort.Strings(names)

	for _, name := range names {
		c := certByName[name]
		cert, fp, err := ParseCACertificate(c.PEM)
		if err != nil {
			return failItem(policy.ID, fmt.Sprintf("certificate %q: %v", name, err), details)
		}
		fileName := name + ".crt"
		desiredFiles[fileName] = true
		fingerprints[name] = fp
		path := filepath.Join(dir, fileName)
		want := normalizePEM(cert)
		if existing, err := os.ReadFile(path); err != nil || string(existing) != string(want) {
			if err := atomicWriteFile(path, want, 0644); err != nil {
				return failItem(policy.ID, fmt.Sprintf("write cert %s: %v", path, err), details)
			}
			changed = true
		}
	}

	// Remove spire-managed certs no longer in the policy.
	removed := []string{}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
				continue
			}
			if !desiredFiles[e.Name()] {
				if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
					removed = append(removed, e.Name())
					changed = true
				}
			}
		}
	}

	// Run update-ca-certificates when anything changed (or always, to converge the trust store).
	if changed {
		out, err := runUpdateCACerts(ctx)
		details["update_ca_output"] = strings.TrimSpace(out)
		if err != nil {
			return failItem(policy.ID, fmt.Sprintf("update-ca-certificates failed: %v", err), details)
		}
	}

	// Verify each desired cert is present on disk and matches its fingerprint.
	for _, name := range names {
		path := filepath.Join(dir, name+".crt")
		data, err := os.ReadFile(path)
		if err != nil {
			details["drifted"] = true
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceNonCompliant,
				ErrorMessage:     fmt.Sprintf("cert %q missing after enforcement", name),
				ExecutionOutput:  mustJSON(details),
			}
		}
		block, _ := pem.Decode(data)
		if block == nil {
			details["drifted"] = true
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceNonCompliant,
				ErrorMessage:     fmt.Sprintf("cert %q unreadable after enforcement", name),
				ExecutionOutput:  mustJSON(details),
			}
		}
		sum := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(sum[:]) != fingerprints[name] {
			details["drifted"] = true
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceNonCompliant,
				ErrorMessage:     fmt.Sprintf("cert %q fingerprint mismatch (drift detected and reasserted)", name),
				ExecutionOutput:  mustJSON(details),
			}
		}
	}

	details["installed"] = fingerprints
	details["removed"] = removed
	details["verified"] = true
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  mustJSON(details),
	}
}

// RemoveTrustedCACertificates removes all spire-managed certs and refreshes the trust store. On revoke.
func RemoveTrustedCACertificates(ctx context.Context) error {
	dir := caSpireDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", dir, err)
	}
	removedAny := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removedAny = true
		}
	}
	_ = os.Remove(dir) // best-effort: drop the now-empty spire dir
	if removedAny {
		if _, err := runUpdateCACerts(ctx); err != nil {
			return fmt.Errorf("update-ca-certificates after removal: %w", err)
		}
	}
	return nil
}

// ValidateTrustedCAPayload is the exported trust-boundary validator, used by the server to reject
// non-parseable or non-CA certificates before a TRUSTED_CA_CERTIFICATES policy is stored.
func ValidateTrustedCAPayload(p types.TrustedCACertificatesPayload) error {
	return validateTrustedCAPayload(p)
}
