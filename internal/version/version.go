// Package version holds the build version, set at link time:
//
//	go build -ldflags "-X github.com/spire-uem/spire-uem/internal/version.Version=0.1.0"
package version

// Version is the SpireUEM release this binary was built from. "dev" means an unversioned build.
var Version = "dev"
