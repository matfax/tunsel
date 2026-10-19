#!/bin/sh
# Installs an x86_64 .ipk into an OpenWrt rootfs booted with procd and walks
# the service through install, start, reload, stop, upgrade and removal.
# Needs Docker (privileged containers) and network access to the OpenWrt feeds,
# which also checks that the package's dependencies resolve.
#
# usage: smoke-test.sh <tunsel_*_x86_64.ipk>
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <ipk>" >&2; exit 2; }
ipk=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
image=${OPENWRT_IMAGE:-openwrt/rootfs:x86_64-24.10.4}
name=tunsel-smoke-$$

# Booting takes eth0 down (preinit) and netifd would move it into br-lan, so
# the network and firewall services stay off and Docker's address and route
# are restored once procd is up: the feeds are reached through them.
docker run -d --name "$name" --privileged -v "$ipk:/root/tunsel.ipk:ro" "$image" \
	sh -c 'rm -f /etc/rc.d/S*network /etc/rc.d/S*firewall && exec /sbin/init' >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT
net=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}/{{.IPPrefixLen}} {{.Gateway}}{{end}}' "$name")

docker exec -i -e NET="$net" "$name" sh -eu <<'EOF'
fail() { echo "FAIL: $*" >&2; logread | grep tunsel >&2 || true; exit 1; }
pid() { ubus call service list '{"name":"tunsel"}' | sed -n 's/.*"pid": \([0-9]*\).*/\1/p'; }

# procd, ubus and logd come up asynchronously.
i=0; until ubus list service >/dev/null 2>&1 && ubus list log >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 30 ] || fail "procd not up"; sleep 1; done
set -- $NET
ip link set eth0 up
ip addr replace "$1" dev eth0
ip route replace default via "$2"

mkdir -p /var/lock
opkg update >/dev/null
opkg install /root/tunsel.ipk

echo "- installed without config: enabled, not running"
/etc/init.d/tunsel enabled || fail "not enabled after install"
[ -z "$(pid)" ] || fail "running without config"

echo "- invalid config: not started"
echo 'bogus: 1' >/etc/tunsel/config.yaml
/etc/init.d/tunsel start 2>/dev/null || true
[ -z "$(pid)" ] || fail "started with an invalid config"

echo "- start"
cp /etc/tunsel/config.example.yaml /etc/tunsel/config.yaml
sysupgrade -l | grep -qx /etc/tunsel/config.yaml || fail "config not kept by sysupgrade"
/etc/init.d/tunsel start
sleep 2
p=$(pid)
[ -n "$p" ] || fail "not running"
tunsel status >/dev/null || fail "status socket"
nft list table inet tunsel >/dev/null || fail "table not installed"

echo "- reload: same process; invalid reload is reported"
/etc/init.d/tunsel reload
sleep 1
[ "$(pid)" = "$p" ] || fail "reload restarted the daemon"
logread | grep -q "configuration reloaded" || fail "no reload logged"
echo 'bogus: 1' >>/etc/tunsel/config.yaml
if /etc/init.d/tunsel reload 2>/dev/null; then fail "invalid reload succeeded"; fi
sed -i '/^bogus/d' /etc/tunsel/config.yaml

echo "- upgrade: restarted, still enabled"
opkg install --force-reinstall /root/tunsel.ipk >/dev/null
sleep 2
[ -n "$(pid)" ] && [ "$(pid)" != "$p" ] || fail "not restarted by upgrade"
/etc/init.d/tunsel enabled || fail "upgrade changed the enabled state"

echo "- stop"
/etc/init.d/tunsel stop
sleep 1
[ -z "$(pid)" ] || fail "still running after stop"
logread | grep -q "msg=stopped" || fail "no clean shutdown logged"

echo "- remove: config stays"
opkg remove tunsel >/dev/null
[ ! -e /etc/init.d/tunsel ] || fail "init script left behind"
[ -f /etc/tunsel/config.yaml ] || fail "config removed"
echo ok
EOF
