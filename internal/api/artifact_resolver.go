package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/spire-uem/spire-uem/internal/types"
)

// artifactResolver computes and caches the SHA-256 of the agent .deb packages the server
// serves from its dist directory. The hash is cached per file and invalidated when the
// file's size or modification time changes, so re-publishing a .deb is picked up without a
// restart but steady-state check-ins do not re-hash on every request.
type artifactResolver struct {
	distDir string

	mu    sync.Mutex
	cache map[string]artifactCacheEntry // keyed by absolute path
}

type artifactCacheEntry struct {
	sha256  string
	size    int64
	modUnix int64
}

func newArtifactResolver(distDir string) *artifactResolver {
	if distDir == "" {
		distDir = "dist"
	}
	return &artifactResolver{distDir: distDir, cache: map[string]artifactCacheEntry{}}
}

// debFileName is the canonical agent package name for a given version, matching the
// Makefile `deb` target output (nfpm: spire-agent_<version>_amd64.deb).
func debFileName(version string) string {
	return fmt.Sprintf("spire-agent_%s_amd64.deb", version)
}

// Resolve returns the artifact descriptor for the target version's .deb, computing (and
// caching) its SHA-256 and size from the file actually on disk. The returned URL is the
// public /dist path the agent downloads from with its bearer token. A missing file is an
// error, so the caller can withhold the update rather than dispatch an unservable artifact.
func (ar *artifactResolver) Resolve(version string) (*types.AgentArtifact, error) {
	name := debFileName(version)
	// ServeDebPackage serves dist/<filename> relative to the server CWD, so the public URL
	// is always /dist/<name> regardless of where distDir points on disk.
	path := filepath.Join(ar.distDir, name)

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("agent artifact %s: %w", name, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("agent artifact %s is a directory", name)
	}

	abs, _ := filepath.Abs(path)
	ar.mu.Lock()
	ent, ok := ar.cache[abs]
	if ok && ent.size == info.Size() && ent.modUnix == info.ModTime().UnixNano() {
		sum := ent.sha256
		ar.mu.Unlock()
		return &types.AgentArtifact{
			Version:     version,
			URL:         "/dist/" + name,
			SHA256:      sum,
			Size:        info.Size(),
			ManifestURL: ar.manifestURL(name),
		}, nil
	}
	ar.mu.Unlock()

	sum, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hash agent artifact %s: %w", name, err)
	}

	ar.mu.Lock()
	ar.cache[abs] = artifactCacheEntry{sha256: sum, size: info.Size(), modUnix: info.ModTime().UnixNano()}
	ar.mu.Unlock()

	return &types.AgentArtifact{
		Version:     version,
		URL:         "/dist/" + name,
		SHA256:      sum,
		Size:        info.Size(),
		ManifestURL: ar.manifestURL(name),
	}, nil
}

// manifestURL returns the public /dist path of the detached signed manifest for the given
// .deb name when the file exists on disk beside the .deb, else "" (unsigned artifact). The
// server only serves a manifest release engineering published; it never creates or signs one.
func (ar *artifactResolver) manifestURL(debName string) string {
	manifestName := debName + ".manifest.json"
	if info, err := os.Stat(filepath.Join(ar.distDir, manifestName)); err == nil && !info.IsDir() {
		return "/dist/" + manifestName
	}
	return ""
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
