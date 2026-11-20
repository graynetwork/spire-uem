// Command browser_cert_seed prepares a device for the browser certificate part of
// scripts/test_access_proxy.sh: an approved, compliant device with a bearer token and an AGENT
// client certificate (written as agent.crt / agent.key into the directory given as the first
// argument), as if it had enrolled and claimed. It talks only to the DATABASE_URL it is given
// and prints KEY=VALUE lines for the script. The browser and network certificates are NOT made
// here: the script obtains them from the real /api/v1/desktop/cert/issue endpoint.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: browser_cert_seed OUTDIR CA_CERT CA_KEY")
	}
	outDir, caCert, caKey := os.Args[1], os.Args[2], os.Args[3]
	ctx := context.Background()
	pool, err := db.NewPool(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	repo := db.NewRepository(pool)
	ca, err := crypto.NewFileDeviceCA(caCert, caKey)
	if err != nil {
		log.Fatal(err)
	}

	d, _, err := repo.GetOrCreateDevice(ctx, "hw-bc-e2e", "bc-e2e-laptop")
	if err != nil {
		log.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, d.ID); err != nil {
		log.Fatal(err)
	}
	bearer, err := repo.ClaimApprovedToken(ctx, d)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{
		DeviceID: d.ID, State: types.PostureCompliant, EvaluatedAt: now, ValidUntil: now.Add(4 * time.Hour),
	}); err != nil {
		log.Fatal(err)
	}
	if err := repo.UpdateDeviceSeenFacts(ctx, d.ID, "127.0.0.20", "carol"); err != nil {
		log.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		log.Fatal(err)
	}
	issued, err := ca.IssueFromCSR(csr, d.ID, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := repo.StoreDeviceCertificate(ctx, d.ID, issued.Serial, issued.FingerprintSHA256, issued.NotBefore, issued.NotAfter); err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "agent.crt"), issued.CertPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "agent.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BC_DEVICE_ID=%s\nBC_BEARER=%s\n", d.ID, bearer)
}
