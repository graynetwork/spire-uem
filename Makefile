.PHONY: all build server agent deb release test vet clean

all: build

build: server agent

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spire-server ./cmd/spire-server

agent:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/spired ./cmd/spired

vet:
	go vet ./...

deb: agent
	mkdir -p dist
	nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

release: build deb
	cp bin/spire-server dist/spire-server_0.1.0_linux_amd64
	cp bin/spired dist/spired_0.1.0_linux_amd64
	sha256sum bin/spire-server bin/spired dist/spire-agent_0.1.0_amd64.deb dist/spire-server_0.1.0_linux_amd64 dist/spired_0.1.0_linux_amd64 > dist/checksums.txt
	@echo "Release artifacts & SHA-256 checksums written to dist/checksums.txt"

test:
	./scripts/test_e2e.sh

clean:
	rm -rf bin/ dist/
