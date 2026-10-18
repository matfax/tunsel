VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build armv7 test integration image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tunsel ./cmd/tunsel

# Turris Omnia and other ARMv7 routers.
armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tunsel-armv7 ./cmd/tunsel

test:
	go vet ./... && go test -race ./...

# Needs root: network namespaces, nftables, conntrack.
integration:
	go test -count=1 -tags integration ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t tunsel:$(VERSION) .
