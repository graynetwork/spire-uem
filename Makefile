VERSION ?= 0.1.0

.PHONY: all build server agent build-hub deb release init-repo publish-deb test vet review audit install-hooks clean sign-deb

all: build

build: server agent build-hub

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/spire-uem/spire-uem/internal/version.Version=$(VERSION)" -o bin/spire-server ./cmd/spire-server

agent:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/spire-uem/spire-uem/internal/version.Version=$(VERSION)" -o bin/spired ./cmd/spired
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/spire-uem/spire-uem/internal/version.Version=$(VERSION)" -o bin/spire-ctl ./cmd/spire-ctl
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/spire-uem/spire-uem/internal/version.Version=$(VERSION)" -o bin/spire-release ./cmd/spire-release

build-hub:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/spire-uem/spire-uem/internal/version.Version=$(VERSION)" -o bin/spire-hub ./cmd/spire-hub

vet:
	go vet ./...

deb: agent build-hub
	mkdir -p dist
	nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

# sign-deb produces the detached Ed25519 manifest beside the built .deb using RELEASE_KEY
# (a private key held OFF the control plane). The server serves dist/<deb>.manifest.json
# automatically once it is present. Usage: make sign-deb RELEASE_KEY=/secure/release.key
sign-deb:
	@if [ -z "$(RELEASE_KEY)" ]; then echo "set RELEASE_KEY=/path/to/release.key" >&2; exit 1; fi
	@if [ ! -f "dist/spire-agent_$(VERSION)_amd64.deb" ]; then $(MAKE) deb; fi
	go run ./cmd/spire-release sign -key "$(RELEASE_KEY)" -deb "dist/spire-agent_$(VERSION)_amd64.deb"

release: build deb
	cp bin/spire-server dist/spire-server_$(VERSION)_linux_amd64
	cp bin/spired dist/spired_$(VERSION)_linux_amd64
	cp bin/spire-hub dist/spire-hub_$(VERSION)_linux_amd64
	sha256sum bin/spire-server bin/spired bin/spire-hub dist/spire-agent_$(VERSION)_amd64.deb dist/spire-server_$(VERSION)_linux_amd64 dist/spired_$(VERSION)_linux_amd64 dist/spire-hub_$(VERSION)_linux_amd64 > dist/checksums.txt
	@echo "Release artifacts & SHA-256 checksums written to dist/checksums.txt"

init-repo:
	packaging/repo/init_repo.sh

publish-deb:
	@if [ ! -f "dist/spire-agent_$(VERSION)_amd64.deb" ]; then \
		$(MAKE) release; \
	fi
	packaging/repo/publish_deb.sh dist/spire-agent_$(VERSION)_amd64.deb

test:
	./scripts/test_e2e.sh

review:
	./scripts/security_audit.sh

audit: review

install-hooks:
	@mkdir -p .git/hooks
	@ln -sf ../../scripts/hooks/pre-commit-security.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Installed SpireUEM security pre-commit hook into .git/hooks/pre-commit"

clean:
	rm -rf bin/ dist/ bin/spire-hub
