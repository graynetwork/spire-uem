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
