package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// If the enforcement setting cannot be read, secrets must be withheld, not delivered as if
// enforcement were off. A pool pointed at a closed port makes every query fail.
func TestGatePolicySecrets_FailsClosedWhenSettingsUnreadable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, "postgres://u:p@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	h := &Handler{repo: db.NewRepository(pool)}

	pols := []types.AssignedPolicy{wifiPolicy(t, sealed())}
	trust := h.gatePolicySecrets(ctx, &types.Device{ID: "dev-1"}, pols)
	if trust.Trusted {
		t.Fatalf("unreadable settings must not yield a trusted device: %+v", trust)
	}
	if !pols[0].SecretsWithheld {
		t.Fatal("unreadable enforcement setting must withhold sealed secrets")
	}
	var out types.NetworkProfilePayload
	_ = json.Unmarshal(pols[0].Payload, &out)
	if out.Wifi.PSK.IsSealed() || out.Wifi.PSK.Plaintext != "" {
		t.Fatalf("secret leaked despite fail-closed gating: %+v", out.Wifi.PSK)
	}
}

// A device that matched a baseline and then fails at the challenge stage must become
// untrusted at once. Before the fix the failure only updated the current-status row, while
// the trust decision read the history, so the old BASELINE_MATCH kept the device trusted.
func TestRecordAttestationFailure_RevokesTrust(t *testing.T) {
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping failed: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	repo := db.NewRepository(pool)
	h := &Handler{repo: repo}

	hw := "pcr-fail-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordAttestationResult(ctx, &types.AttestationResult{
		DeviceID: dev.ID, Status: types.AttestationBaselineMatch, PCRValues: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	latest, _ := repo.GetLatestAttestationResult(ctx, dev.ID)
	if !crypto.EvaluateTrust(latest, nil, 24*time.Hour, time.Now()).Trusted {
		t.Fatal("setup: device should be trusted after a baseline match")
	}

	h.recordAttestationFailure(httptest.NewRequest("POST", "/api/v1/desktop/attest/challenge", nil), dev.ID, "")

	latest, _ = repo.GetLatestAttestationResult(ctx, dev.ID)
	if latest == nil || latest.Status != types.AttestationFailed {
		t.Fatalf("challenge failure must be the latest history entry, got %+v", latest)
	}
	if crypto.EvaluateTrust(latest, nil, 24*time.Hour, time.Now()).Trusted {
		t.Fatal("device must be untrusted after a challenge-stage attestation failure")
	}
}
