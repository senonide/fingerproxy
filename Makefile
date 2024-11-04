TARGET = fingerproxy

build: build_darwin_arm64 build_darwin_amd64 \
	build_linux_amd64 build_linux_arm build_linux_arm64 \
	build_windows_amd64 build_windows_arm64

build_darwin_%: GOOS = darwin
build_linux_%: GOOS = linux
build_windows_%: GOOS = windows
build_windows_%: EXT = .exe

build_%_amd64: GOARCH = amd64
build_%_arm: GOARCH = arm
build_%_arm64: GOARCH = arm64

COMMIT = $(shell git rev-parse --short HEAD || true)
TAG = $(shell git describe --tags --abbrev=0 HEAD 2>/dev/null || true)
BINPATH = bin/$(TARGET)_$(GOOS)_$(GOARCH)$(EXT)

build_%:
	export GOOS=$(GOOS) GOARCH=$(GOARCH)

	go build -o $(BINPATH) \
		-ldflags "-X main.buildCommit=$(COMMIT) -X main.buildVersion=$(TAG)" .

	chmod +x $(BINPATH)

PKG_LIST = $(shell go list ./... | grep -v github.com/senonide/fingerproxy/pkg/http2)
test:
	@go test -v $(PKG_LIST)

benchmark:
	@go test -v $(PKG_LIST) -run=NONE -bench=^Benchmark -benchmem -count=3 -cpu=2

prepare:
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
      -nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

run-test:
	go run . -listen-addr :8443 -forward-url https://httpbin.io

run-example:
	go run example/echo-server/main.go -listen-addr :8443

run:
	go run . -listen-addr :8443
