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

Container (host network; see DESIGN.md §9.1 for the runtime contract):

```sh
cp config.example.yaml config.yaml   # edit
docker compose up -d
docker exec tunsel /tunsel status
docker kill -s HUP tunsel            # reload config
```

Natively:

```sh
make armv7                           # bin/tunsel-armv7, static, for Turris Omnia
tunsel check -config /etc/tunsel/config.yaml
tunsel run -config /etc/tunsel/config.yaml
tunsel status
```

## Development

```sh
make test                            # unit tests (nft tests skip without root)
sudo make integration                # all tests incl. network-namespace end-to-end test
make image                           # local image for the build host's platform
```

CI (`.github/workflows/ci.yml`) runs everything and builds `linux/amd64`,
`linux/arm64` and `linux/arm/v7` images, pushing on `v*` tags to
`ghcr.io/<repository>` unless the `IMAGE`/`REGISTRY` repository variables say
otherwise. Go and Docker layer caches persist between runs.

Dependencies are kept current by Renovate (`renovate.json`). Actions and base
images are pinned to commit SHAs / digests. Minor, patch and digest updates
merge automatically once CI passes; major updates wait for review. This needs,
on GitHub:

- the [Renovate app](https://github.com/apps/renovate) installed on the repository,
- "Allow auto-merge" enabled in the repository settings,
- branch protection on `main` requiring the `test` and `image` checks.
