# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Cross-compiles on the build host; no emulation needed for arm/v7 or arm64.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
# Modules live in a layer (reusable from the CI layer cache), the compile
# cache in a cache mount (reusable on local and self-hosted builders).
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/tunsel ./cmd/tunsel

# nftables and conntrack are driven over netlink: the binary is all it needs.
FROM scratch
COPY --from=build /out/tunsel /tunsel
ENTRYPOINT ["/tunsel"]
CMD ["run", "-config", "/etc/tunsel/config.yaml"]
