# tunsel

Health-aware selection between VPN tunnels on a Linux router. New connections
from the LAN go to the first healthy tunnel in a configured order, with static
per-prefix preferences; when a tunnel fails, traffic moves to the next one and
moves back on recovery. tunsel owns one nftables table and nothing else:
interfaces, routing tables, policy rules and the firewall stay with the host.

See [DESIGN.md](DESIGN.md) for the design, the full ruleset and failure
semantics, and [config.example.yaml](config.example.yaml) for all options.

## Host setup

Per tunnel, the host provides a routing table with a default route via the
tunnel and a policy rule for its mark (DESIGN.md §3 lists all requirements,
including NAT, `rp_filter` and leak protection in the firewall):

```sh
ip route add default dev wg-a table 101
ip -6 route add default dev wg-a table 101
ip rule add fwmark 0x1/0xf lookup 101 prio 100
ip -6 rule add fwmark 0x1/0xf lookup 101 prio 100
sysctl -w net.ipv4.conf.wg-a.rp_filter=2
```

On OpenWrt / Turris OS the same goes into `/etc/config/network`, so it
survives interface restarts:

```
config route
	option interface 'wg_a'
	option target '0.0.0.0/0'
	option table '101'

config rule
	option mark '0x1/0xf'
	option lookup '101'
	option priority '100'
```

(plus the `route6` / `rule6` equivalents).

## Run

OpenWrt / Turris OS: each release has an `.ipk` per architecture (pick the
last line of `opkg print-architecture`; `arm_cortex-a9_vfpv3-d16` on a Turris
Omnia). It installs the binary, a procd service (enabled, but idle until a
config exists) and the nftables/conntrack kernel modules it needs:

```sh
opkg update && opkg install ./tunsel_<version>_<arch>.ipk
cp /etc/tunsel/config.example.yaml /etc/tunsel/config.yaml   # edit
/etc/init.d/tunsel start
tunsel status
/etc/init.d/tunsel reload            # validate, then SIGHUP
logread -e tunsel
```

The config is never replaced or removed by opkg and is kept by sysupgrade.

Container (host network; see DESIGN.md §9.1 for the runtime contract):

```sh
cp config.example.yaml config.yaml   # edit
docker compose up -d
docker exec tunsel /tunsel status
docker kill -s HUP tunsel            # reload config
```

Natively (builds use [Task](https://taskfile.dev); `task --list` shows all tasks):

```sh
task armv7                           # bin/tunsel-armv7, static, for Turris Omnia
task ipk IPK_ARCHS=arm_cortex-a9_vfpv3-d16   # bin/*.ipk
tunsel check -config /etc/tunsel/config.yaml
tunsel run -config /etc/tunsel/config.yaml
tunsel status
```

## Development

```sh
task test                            # unit tests (nft tests skip without root)
sudo task integration                # all tests incl. network-namespace end-to-end test
task image                           # local image for the build host's platform
packaging/openwrt/smoke-test.sh bin/tunsel_*_x86_64.ipk   # ipk on OpenWrt with procd (Docker)
```
