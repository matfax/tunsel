#!/bin/sh
# Installs the x86_64 .ipk and luci-app-tunsel into an OpenWrt rootfs booted
# with procd and walks the service through install, start, reload (including
# the UCI reload trigger), stop, upgrade and removal, and the status through
# rpcd. Needs Docker (privileged containers) and network access to the
# OpenWrt feeds, which also checks that the packages' dependencies resolve.
#
# usage: smoke-test.sh <tunsel_*_x86_64.ipk> <luci-app-tunsel_*_all.ipk>
set -eu

[ $# -eq 2 ] || { echo "usage: $0 <tunsel ipk> <luci-app-tunsel ipk>" >&2; exit 2; }
ipk=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
luci=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
image=${OPENWRT_IMAGE:-openwrt/rootfs:x86_64-24.10.4}
name=tunsel-smoke-$$

# Booting takes eth0 down (preinit) and netifd would move it into br-lan, so
# the network and firewall services stay off and Docker's address and route
# are restored once procd is up: the feeds are reached through them.
docker run -d --name "$name" --privileged -v "$ipk:/root/tunsel.ipk:ro" -v "$luci:/root/luci-app-tunsel.ipk:ro" "$image" \
	sh -c 'rm -f /etc/rc.d/S*network /etc/rc.d/S*firewall && exec /sbin/init' >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT
net=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}/{{.IPPrefixLen}} {{.Gateway}}{{end}}' "$name")

docker exec -i -e NET="$net" "$name" sh -eu <<'EOF'
fail() { echo "FAIL: $*" >&2; logread | grep tunsel >&2 || true; exit 1; }
pid() { ubus call service list '{"name":"tunsel"}' | sed -n 's/.*"pid": \([0-9]*\).*/\1/p'; }
# procd runs reload triggers asynchronously.
until_pid() { # <want: running | stopped | changed:<old pid>>
	local q i=0
	while :; do
		q=$(pid)
		case $1 in
		running) [ -n "$q" ] && return 0 ;;
		stopped) [ -z "$q" ] && return 0 ;;
		changed:*) [ -n "$q" ] && [ "$q" != "${1#changed:}" ] && return 0 ;;
		esac
		i=$((i+1)); [ $i -lt 10 ] || return 1
		sleep 1
	done
}
# The socket appears after the first health round.
until_status() {
	local i=0
	until tunsel status >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 10 ] || return 1; sleep 1; done
}

# procd, ubus and logd come up asynchronously.
i=0; until ubus list service >/dev/null 2>&1 && ubus list log >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 30 ] || fail "procd not up"; sleep 1; done
set -- $NET
ip link set eth0 up
ip addr replace "$1" dev eth0
ip route replace default via "$2"

mkdir -p /var/lock
opkg update >/dev/null
opkg install /root/tunsel.ipk

echo "- installed disabled: enabled service, not running"
/etc/init.d/tunsel enabled || fail "not enabled after install"
[ "$(uci get tunsel.main.enabled)" = 0 ] || fail "shipped config not disabled"
[ -z "$(pid)" ] || fail "running while disabled"

echo "- invalid config: not started"
uci set tunsel.main.enabled=1
uci set tunsel.main.bogus=1
uci commit tunsel
/etc/init.d/tunsel start 2>/dev/null || true
[ -z "$(pid)" ] || fail "started with an invalid config"

echo "- start"
uci delete tunsel.main.bogus
uci commit tunsel
/etc/init.d/tunsel start
until_pid running || fail "not running"
p=$(pid)
until_status || fail "status socket"
nft list counter inet tunsel new >/dev/null || fail "table or counters not installed"
sysupgrade -l | grep -qx /etc/config/tunsel || fail "changed config not kept by sysupgrade"

echo "- reload: same process; invalid reload is reported"
/etc/init.d/tunsel reload
sleep 1
[ "$(pid)" = "$p" ] || fail "reload restarted the daemon"
logread | grep -q "configuration reloaded" || fail "no reload logged"
uci set tunsel.main.bogus=1
uci commit tunsel
if /etc/init.d/tunsel reload 2>/dev/null; then fail "invalid reload succeeded"; fi
uci delete tunsel.main.bogus
uci commit tunsel

echo "- uci commit reloads (LuCI Save & Apply)"
# What rpcd runs after LuCI's apply: a config.change event per package
# changed since its previous run, so the first run only takes the baseline.
reload_config
n=$(logread | grep -c "configuration reloaded")
uci set tunsel.wg_a.interval=5s
uci commit tunsel
reload_config
i=0; until [ "$(logread | grep -c "configuration reloaded")" -gt "$n" ]; do i=$((i+1)); [ $i -lt 10 ] || fail "uci commit did not reload"; sleep 1; done
[ "$(pid)" = "$p" ] || fail "trigger restarted the daemon"

echo "- disabling stops it"
uci set tunsel.main.enabled=0
uci commit tunsel
/etc/init.d/tunsel reload
until_pid stopped || fail "still running while disabled"
uci set tunsel.main.enabled=1
uci commit tunsel
/etc/init.d/tunsel reload
until_pid running || fail "not started again when enabled"
p=$(pid)
until_status || fail "status socket after enabling"

echo "- luci-app: status over rpcd"
opkg install /root/luci-app-tunsel.ipk >/dev/null
i=0; until ubus list tunsel >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 10 ] || fail "rpcd plugin not on ubus"; sleep 1; done
ubus call tunsel status | grep -q '"connections"' || fail "ubus tunsel status"
ubus call tunsel flows | grep -q '"flows"' || fail "ubus tunsel flows"
ubus call tunsel history | grep -q '"history"' || fail "ubus tunsel history"
# Learning is off in the shipped config, so this only checks the method.
ubus call tunsel learned | grep -q '"connections"' || fail "ubus tunsel learned"
[ -f /www/luci-static/resources/view/tunsel/status.js ] || fail "views not installed"

echo "- upgrade: restarted, still enabled, config kept"
opkg install --force-reinstall /root/tunsel.ipk >/dev/null
until_pid "changed:$p" || fail "not restarted by upgrade"
# procd reports the pid as soon as it forks; a stop before the exec would
# hit procd's own signal handlers in the child.
until_status || fail "status socket after upgrade"
/etc/init.d/tunsel enabled || fail "upgrade changed the enabled state"
[ "$(uci get tunsel.wg_a.interval)" = 5s ] || fail "upgrade replaced the config"

echo "- stop"
/etc/init.d/tunsel stop
until_pid stopped || fail "still running after stop"
logread | grep -q "msg=stopped" || fail "no clean shutdown logged"

echo "- remove: config stays"
opkg remove luci-app-tunsel >/dev/null
opkg remove tunsel >/dev/null
[ ! -e /etc/init.d/tunsel ] || fail "init script left behind"
[ -f /etc/config/tunsel ] || fail "config removed"
echo ok
EOF
