VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build armv7 ipk test integration image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tunsel ./cmd/tunsel

# Turris Omnia and other ARMv7 routers.
armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tunsel-armv7 ./cmd/tunsel

# OpenWrt / Turris OS packages, one per opkg architecture (the last line of
# `opkg print-architecture` on the device). Omnia, MOX, other ARMv7/ARMv8, x86.
IPK_ARCHS ?= arm_cortex-a9_vfpv3-d16 arm_cortex-a7_neon-vfpv4 arm_cortex-a15_neon-vfpv4 \
	aarch64_cortex-a53 aarch64_cortex-a72 aarch64_generic x86_64

ipk:
	LDFLAGS="$(LDFLAGS)" packaging/openwrt/build-ipk.sh $(VERSION) bin $(IPK_ARCHS)

test:
	go vet ./... && go test -race ./...

# Needs root: network namespaces, nftables, conntrack.
integration:
	go test -count=1 -tags integration ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t tunsel:$(VERSION) .
