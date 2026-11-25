package db_test

import (
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// An admin revoke raises device_cert_revoked with purpose, serial and user and nothing else;
// pruning or revoking nothing raises no event.
func TestWebhook_DeviceCertRevoked(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	tag := tagFor("certrev")
	sub := subFor(t, repo, ctx, rc, []string{"device_cert_revoked"}, []string{tag})

	dev, _, err := repo.GetOrCreateDevice(ctx, uniqueHW("certrev"), "certrev-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, dev.ID, []string{tag}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c, err := repo.StoreDeviceCertificateFor(ctx, dev.ID, types.CertPurposeBrowser, "alice", tag+"-serial", tag+"-fp", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// A certificate id of another device revokes nothing and raises nothing.
	if got, err := repo.RevokeDeviceCertificateByAdmin(ctx, "00000000-0000-0000-0000-000000000000", c.ID); err != nil || got != nil {
		t.Fatalf("wrong device: %v %v", got, err)
	}
	if got, err := repo.RevokeDeviceCertificateByAdmin(ctx, dev.ID, c.ID); err != nil || got == nil {
		t.Fatalf("revoke: %v %v", got, err)
	}
	if got, _ := repo.RevokeDeviceCertificateByAdmin(ctx, dev.ID, c.ID); got != nil {
		t.Fatalf("second revoke must return nil")
	}
	drainWebhooks(testWorker(repo, sub.ID))

	got := rc.byDevice(dev.ID, "device_cert_revoked")
	if len(got) != 1 {
		t.Fatalf("want exactly 1 delivery, got %d", len(got))
	}
	e := got[0]
	if e.SigError != nil {
		t.Fatalf("signature: %v", e.SigError)
	}
	if e.Env.Data["purpose"] != "browser" || e.Env.Data["serial"] != c.Serial || e.Env.Data["user"] != "alice" {
		t.Errorf("data = %v", e.Env.Data)
	}
	if len(e.Env.Data) != 3 {
		t.Errorf("data must hold only purpose, serial and user: %v", e.Env.Data)
	}
	raw := strings.ToLower(string(e.Raw))
	if strings.Contains(raw, "private") || strings.Contains(raw, "-----begin") || strings.Contains(raw, "fingerprint") {
		t.Errorf("payload carries key or certificate material: %s", e.Raw)
	}
}

// Revoking one agent certificate revokes every live agent certificate of the device (a renewed
// device still holds its predecessor) and sets the re-approval flag, but leaves the device's
// network and browser certificates alone.
func TestRevokeAgentCertByAdmin_RevokesAllAgentCerts(t *testing.T) {
	repo, ctx := whRepo(t)
	dev, _, err := repo.GetOrCreateDevice(ctx, uniqueHW("agentrev"), "agentrev-host")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tag := tagFor("agentrev")
	oldAgent, err := repo.StoreDeviceCertificate(ctx, dev.ID, tag+"-a1", tag+"-fa1", now.Add(-2*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newAgent, err := repo.StoreDeviceCertificate(ctx, dev.ID, tag+"-a2", tag+"-fa2", now.Add(-time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	netCert, err := repo.StoreDeviceCertificateFor(ctx, dev.ID, types.CertPurposeNetwork, "", tag+"-n", tag+"-fn", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repo.RevokeDeviceCertificateByAdmin(ctx, dev.ID, newAgent.ID); err != nil || got == nil {
		t.Fatalf("revoke: %v %v", got, err)
	}
	for _, c := range []struct {
		serial      string
		wantRevoked bool
	}{{oldAgent.Serial, true}, {newAgent.Serial, true}, {netCert.Serial, false}} {
		rec, err := repo.GetDeviceCertificateBySerial(ctx, c.serial)
		if err != nil || rec == nil {
			t.Fatalf("lookup %s: %v", c.serial, err)
		}
		if rec.Revoked() != c.wantRevoked {
			t.Errorf("%s (%s): revoked=%v, want %v", c.serial, rec.Purpose, rec.Revoked(), c.wantRevoked)
		}
	}
	if blocked, err := repo.DeviceCertReapprovalRequired(ctx, dev.ID); err != nil || !blocked {
		t.Fatalf("re-approval flag: %v %v", blocked, err)
	}
}
