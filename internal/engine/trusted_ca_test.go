package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// makeTestCACert returns a PEM-encoded self-signed CA (isCA=true) certificate.
func makeTestCACert(t *testing.T, cn string, isCA bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"SpireUEM Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseCACertificate(t *testing.T) {
	caPEM := makeTestCACert(t, "Spire Root CA", true)
	cert, fp, err := ParseCACertificate(caPEM)
	if err != nil {
		t.Fatalf("expected CA to parse, got %v", err)
	}
	if cert.Subject.CommonName != "Spire Root CA" {
		t.Errorf("unexpected CN %q", cert.Subject.CommonName)
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-hex-char fingerprint, got %q", fp)
	}

	// Non-CA cert must be rejected.
	leafPEM := makeTestCACert(t, "Leaf", false)
	if _, _, err := ParseCACertificate(leafPEM); err == nil {
		t.Error("expected non-CA cert to be rejected")
	}
	// Garbage must be rejected.
	if _, _, err := ParseCACertificate("not a pem"); err == nil {
		t.Error("expected garbage PEM to be rejected")
	}
}

func TestValidateTrustedCAPayload(t *testing.T) {
	ca1 := makeTestCACert(t, "CA One", true)
	ca2 := makeTestCACert(t, "CA Two", true)

	if err := ValidateTrustedCAPayload(types.TrustedCACertificatesPayload{
		Certificates: []types.TrustedCACertificate{{Name: "root-ca", PEM: ca1}, {Name: "intermediate", PEM: ca2}},
	}); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	bad := []types.TrustedCACertificatesPayload{
		{},
		{Certificates: []types.TrustedCACertificate{{Name: "../evil", PEM: ca1}}},
		{Certificates: []types.TrustedCACertificate{{Name: "dup", PEM: ca1}, {Name: "dup", PEM: ca2}}},
		{Certificates: []types.TrustedCACertificate{{Name: "leaf", PEM: makeTestCACert(t, "Leaf", false)}}},
	}
	for i, p := range bad {
		if err := ValidateTrustedCAPayload(p); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestEnforceTrustedCACertificates_ApplyOrphanDriftRemove(t *testing.T) {
	tmp := t.TempDir()
	origRoot := caRoot
	origRun := runUpdateCACerts
	caRoot = tmp
	updateCalls := 0
	runUpdateCACerts = func(ctx context.Context) (string, error) {
		updateCalls++
		return "1 added, 0 removed; done.", nil
	}
	defer func() { caRoot = origRoot; runUpdateCACerts = origRun }()

	ctx := context.Background()
	ca1 := makeTestCACert(t, "CA One", true)
	ca2 := makeTestCACert(t, "CA Two", true)

	// 1. Install two certs.
	p1, _ := json.Marshal(types.TrustedCACertificatesPayload{
		Certificates: []types.TrustedCACertificate{{Name: "root-ca", PEM: ca1}, {Name: "intermediate", PEM: ca2}},
	})
	pol1 := types.AssignedPolicy{ID: "ca-1", PolicyType: types.PolicyTypeTrustedCACerts, Payload: p1}
	item := EnforceTrustedCACertificates(ctx, pol1)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT, got %v (err=%s)", item.ComplianceStatus, item.ErrorMessage)
	}
	dir := filepath.Join(tmp, caSpireDirRel)
	for _, f := range []string{"root-ca.crt", "intermediate.crt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s written: %v", f, err)
		}
	}
	if updateCalls == 0 {
		t.Error("expected update-ca-certificates to run on first apply")
	}

	// 2. Idempotent re-apply: no change -> update-ca-certificates NOT re-run.
	before := updateCalls
	item = EnforceTrustedCACertificates(ctx, pol1)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("second apply not COMPLIANT: %v", item.ComplianceStatus)
	}
	if updateCalls != before {
		t.Errorf("expected no update-ca-certificates call on unchanged re-apply, got %d extra", updateCalls-before)
	}

	// 3. Orphan removal: policy now only has root-ca; intermediate.crt must be removed.
	p2, _ := json.Marshal(types.TrustedCACertificatesPayload{
		Certificates: []types.TrustedCACertificate{{Name: "root-ca", PEM: ca1}},
	})
	pol2 := types.AssignedPolicy{ID: "ca-1", PolicyType: types.PolicyTypeTrustedCACerts, Payload: p2}
	item = EnforceTrustedCACertificates(ctx, pol2)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("orphan-removal apply not COMPLIANT: %v", item.ComplianceStatus)
	}
	if _, err := os.Stat(filepath.Join(dir, "intermediate.crt")); !os.IsNotExist(err) {
		t.Errorf("expected orphaned intermediate.crt to be removed")
	}

	// 4. Drift: someone corrupts root-ca.crt -> NON_COMPLIANT reasserted.
	//    Re-run with a drift: overwrite the on-disk cert, then enforce detects fingerprint mismatch
	//    only if the content differs from desired. Since enforce rewrites drifted files, simulate by
	//    writing a DIFFERENT valid CA under the same filename and confirming enforce converges it back.
	_ = os.WriteFile(filepath.Join(dir, "root-ca.crt"), []byte(ca2), 0644)
	item = EnforceTrustedCACertificates(ctx, pol2)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected enforce to converge drift back to COMPLIANT, got %v", item.ComplianceStatus)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "root-ca.crt"))
	wantCert, _, _ := ParseCACertificate(ca1)
	if string(got) != string(normalizePEM(wantCert)) {
		t.Errorf("drifted root-ca.crt was not reasserted to desired content")
	}

	// 5. Removal clears all spire certs.
	if err := RemoveTrustedCACertificates(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".crt") {
				t.Errorf("expected all spire certs removed, found %s", e.Name())
			}
		}
	}
}

func TestEnforceTrustedCACertificates_InvalidPayload(t *testing.T) {
	ctx := context.Background()
	pol := types.AssignedPolicy{ID: "ca-bad", PolicyType: types.PolicyTypeTrustedCACerts, Payload: json.RawMessage(`{"certificates":[{"name":"x","pem":"garbage"}]}`)}
	if item := EnforceTrustedCACertificates(ctx, pol); item.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected FAILED for invalid cert, got %v", item.ComplianceStatus)
	}
}
