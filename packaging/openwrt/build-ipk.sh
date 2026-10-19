#!/bin/sh
# Builds OpenWrt / Turris OS packages (.ipk) of tunsel, one per opkg
# architecture, in the layout of the SDK's ipkg-build: an outer tar.gz with
# debian-binary, control.tar.gz and data.tar.gz. Needs Go and GNU tar.
#
# usage: build-ipk.sh <version> <outdir> <opkg-arch>...
# The opkg architecture of a device is the last line of
# `opkg print-architecture`, e.g. arm_cortex-a9_vfpv3-d16 on a Turris Omnia.
set -eu
umask 022

[ $# -ge 3 ] || { echo "usage: $0 <version> <outdir> <opkg-arch>..." >&2; exit 2; }
version=$1 outdir=$2
shift 2

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
ldflags=${LDFLAGS:-"-s -w -X main.version=$version"}
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}

# v1.2.3 → 1.2.3. Anything else (an untagged commit, "dev") sorts below every
# release: opkg would read a commit hash like 1315eb6 as the number 1315.
pkgver=${version#v}
case $pkgver in [0-9]*.[0-9]*) ;; *) pkgver=0~$pkgver ;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Reproducible archives, owned by root like the SDK's.
mktar() { # <dir> <archive.tar.gz> <entry>...
	dir=$1 out=$2
	shift 2
	(cd "$dir" && tar --format=gnu --numeric-owner --owner=0 --group=0 --sort=name \
		--mtime="@$epoch" -cf - "$@") | gzip -9n >"$out"
}

for arch in "$@"; do
	# The binary is static, so one build per Go target serves every opkg
	# architecture of that CPU family.
	case $arch in
	arm_cortex-a*) goarch=arm goarm=7 ;;
	aarch64_*) goarch=arm64 goarm= ;;
	x86_64) goarch=amd64 goarm= ;;
	*) echo "$0: no Go target known for opkg architecture $arch" >&2; exit 1 ;;
	esac

	pkg=$work/$arch
	data=$pkg/data
	ctrl=$pkg/control
	mkdir -p "$data/usr/sbin" "$data/etc/init.d" "$data/etc/tunsel" "$data/lib/upgrade/keep.d" "$ctrl"

	(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch GOARM=$goarm \
		go build -trimpath -ldflags "$ldflags" -o "$data/usr/sbin/tunsel" ./cmd/tunsel)
	install -m 0755 "$here/tunsel.init" "$data/etc/init.d/tunsel"
	install -m 0644 "$root/config.example.yaml" "$data/etc/tunsel/config.example.yaml"
	# The config is the user's, not the package's: opkg never replaces or
	# removes it, and sysupgrade keeps it.
	echo /etc/tunsel/config.yaml >"$data/lib/upgrade/keep.d/tunsel"
	chmod 0644 "$data/lib/upgrade/keep.d/tunsel"

	size=$(du -sb --apparent-size "$data" | cut -f1)
	cat >"$ctrl/control" <<-EOF
	Package: tunsel
	Version: $pkgver
	Depends: kmod-nft-core, kmod-nft-fib, kmod-nf-conntrack-netlink
	Source: https://github.com/matfax/tunsel
	Section: net
	SourceDateEpoch: $epoch
	URL: https://github.com/matfax/tunsel
	Architecture: $arch
	Installed-Size: $size
	Description:  Health-aware selection between VPN tunnels
	EOF
	install -m 0755 "$here/postinst" "$ctrl/postinst"
	install -m 0755 "$here/prerm" "$ctrl/prerm"
	chmod 0644 "$ctrl/control"

	echo 2.0 >"$pkg/debian-binary"
	mktar "$data" "$pkg/data.tar.gz" .
	mktar "$ctrl" "$pkg/control.tar.gz" .
	mktar "$pkg" "$outdir/tunsel_${pkgver}_$arch.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz
	echo "$outdir/tunsel_${pkgver}_$arch.ipk"
done
