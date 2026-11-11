VERSION ?= 0.1.0

.PHONY: all build server agent build-hub deb release init-repo publish-deb test vet clean

all: build

build: server agent build-hub

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spire-server ./cmd/spire-server

agent:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spired ./cmd/spired
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spire-ctl ./cmd/spire-ctl

build-hub:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spire-hub ./cmd/spire-hub

vet:
	go vet ./...

deb: agent build-hub
	mkdir -p dist
	nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

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

clean:
	rm -rf bin/ dist/ bin/spire-hub
