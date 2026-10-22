# tunsel

Health-aware selection between VPN tunnels on a Linux router. New connections
from the LAN go to the first healthy tunnel in a configured order, with static
per-prefix preferences; when a tunnel fails, traffic moves to the next one and
moves back on recovery. Optionally, tunsel learns the fastest tunnel per
destination: it takes the busiest current connections, times a TCP handshake
to port 443 through every healthy tunnel, and steers new connections to each
destination through the fastest one for an hour. tunsel owns one nftables table and nothing else: interfaces,
routing tables, policy rules and the firewall stay with the host.

See [DESIGN.md](DESIGN.md) for the design, the full ruleset and failure
semantics, and [config.example.yaml](config.example.yaml) for all options
(on OpenWrt the same options in UCI form:
[packaging/openwrt/tunsel.config](packaging/openwrt/tunsel.config)).

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
Omnia) and `luci-app-tunsel_<version>_all.ipk`. The first installs the
binary, a procd service, the UCI config `/etc/config/tunsel` (disabled, with
placeholder tunnels) and the nftables/conntrack kernel modules it needs; the
second adds Services → Tunsel to LuCI, with a configuration page and a status
page (health, latency history, connections and flows per tunnel, learned
destinations):

```sh
opkg update && opkg install ./tunsel_<version>_<arch>.ipk ./luci-app-tunsel_<version>_all.ipk
```

Configure in LuCI and Save & Apply, or from the shell:

```sh
uci set tunsel.main.enabled=1        # plus your tunnels; see /etc/config/tunsel
uci commit tunsel
/etc/init.d/tunsel reload            # validate, then SIGHUP (or start, stop if disabled)
tunsel status                        # -flows: conntrack per tunnel; -history: RTT history; -learned: measured destinations
logread -e tunsel
```

Latency learning (DESIGN.md §7 has the details, LuCI the same options under
Latency learning):

```sh
uci set tunsel.main.learning=1
uci commit tunsel                    # reloads the daemon
tunsel status -learned               # what was measured and where it goes
```

opkg keeps a changed config on upgrade and removal, and sysupgrade keeps it.

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

A config file whose name ends in `.yaml` or `.yml` is read as YAML, any other
as UCI.

## Development

```sh
task test                            # unit tests (nft tests skip without root)
sudo task integration                # all tests incl. network-namespace end-to-end test
task image                           # local image for the build host's platform
packaging/openwrt/smoke-test.sh bin/tunsel_*_x86_64.ipk bin/luci-app-tunsel_*_all.ipk   # on OpenWrt with procd and rpcd (Docker)
```
