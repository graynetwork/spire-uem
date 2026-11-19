// Command access_proxy_seed prepares a throwaway SpireUEM database for
// scripts/test_access_proxy.sh: a posture:read connector token, devices in several posture
// states at known loopback addresses, and the forward-auth settings. It only ever talks to the
// DATABASE_URL it is given and prints KEY=VALUE lines for the script.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

func main() {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	repo := db.NewRepository(pool)

	raw, tid, hash, err := web.GenerateServiceAccountToken()
	if err != nil {
		log.Fatal(err)
	}
	if _, _, err := repo.CreateServiceAccount(ctx, &types.ServiceAccount{
		Name: "access-proxy-e2e", Role: types.RoleAuditor, Scopes: []string{types.ScopePostureRead}, Enabled: true, CreatedBy: "e2e",
	}, tid, hash, "e2e"); err != nil {
		log.Fatal(err)
	}

	mk := func(name, ip string, state types.PostureState) string {
		d, _, err := repo.GetOrCreateDevice(ctx, "hw-"+name, name)
		if err != nil {
			log.Fatal(err)
		}
		if _, _, err := repo.ApproveDevice(ctx, d.ID); err != nil {
			log.Fatal(err)
		}
		if err := repo.UpdateDeviceSeenFacts(ctx, d.ID, ip, ""); err != nil {
			log.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{
			DeviceID: d.ID, State: state, EvaluatedAt: now, ValidUntil: now.Add(time.Hour),
		}); err != nil {
			log.Fatal(err)
		}
		return d.ID
	}
	good := mk("e2e-compliant", "127.0.0.2", types.PostureCompliant)
	mk("e2e-noncompliant", "127.0.0.3", types.PostureNoncompliant)
	mk("e2e-shared-a", "127.0.0.5", types.PostureCompliant)
	mk("e2e-shared-b", "127.0.0.5", types.PostureCompliant)

	prefixes, err := db.ParseTrustedProxyList("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	if err := repo.SaveAccessProxySettings(ctx, db.AccessProxySettings{
		TrustedProxies: prefixes, IPHeader: db.IPHeaderXForwardedFor, AllowWeakIdentity: true,
	}, "e2e"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("SPIRE_CONNECTOR_TOKEN=%s\nGOOD_DEVICE_ID=%s\n", raw, good)
}
