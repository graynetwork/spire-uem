package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArtifactResolver_HashesServedDeb(t *testing.T) {
	dir := t.TempDir()
	body := []byte("dummy agent debian package payload")
	name := debFileName("0.2.0")
	if err := os.WriteFile(filepath.Join(dir, name), body, 0644); err != nil {
		t.Fatal(err)
	}

	ar := newArtifactResolver(dir)
	a, err := ar.Resolve("0.2.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := sha256.Sum256(body)
	if a.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", a.SHA256, hex.EncodeToString(want[:]))
	}
	if a.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", a.Size, len(body))
	}
	if a.URL != "/dist/"+name {
		t.Errorf("url = %s, want /dist/%s", a.URL, name)
	}
	if a.Version != "0.2.0" {
		t.Errorf("version = %s, want 0.2.0", a.Version)
	}
}

func TestArtifactResolver_MissingFileErrors(t *testing.T) {
	ar := newArtifactResolver(t.TempDir())
	if _, err := ar.Resolve("9.9.9"); err == nil {
		t.Fatal("expected error for missing .deb, got nil")
	}
}

func TestArtifactResolver_SetsManifestURLWhenPresent(t *testing.T) {
	dir := t.TempDir()
	name := debFileName("0.2.0")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("deb"), 0644); err != nil {
		t.Fatal(err)
	}
	ar := newArtifactResolver(dir)

	// No manifest yet → ManifestURL empty.
	a, err := ar.Resolve("0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if a.ManifestURL != "" {
		t.Errorf("expected empty ManifestURL with no manifest, got %q", a.ManifestURL)
	}

	// Drop a manifest beside the .deb → ManifestURL set.
	if err := os.WriteFile(filepath.Join(dir, name+".manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	a, err = ar.Resolve("0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if a.ManifestURL != "/dist/"+name+".manifest.json" {
		t.Errorf("ManifestURL = %q, want /dist/%s.manifest.json", a.ManifestURL, name)
	}
}

func TestArtifactResolver_CacheInvalidatesOnMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, debFileName("0.3.0"))
	if err := os.WriteFile(path, []byte("v1 contents"), 0644); err != nil {
		t.Fatal(err)
	}

	ar := newArtifactResolver(dir)
	first, err := ar.Resolve("0.3.0")
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite with different contents and a newer mtime; the resolver must re-hash.
	newBody := []byte("v2 different contents, different length")
	if err := os.WriteFile(path, newBody, 0644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := ar.Resolve("0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 == second.SHA256 {
		t.Error("expected sha256 to change after the .deb was re-published")
	}
	want := sha256.Sum256(newBody)
	if second.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("second sha256 = %s, want %s", second.SHA256, hex.EncodeToString(want[:]))
	}
}
