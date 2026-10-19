# tunsel — design

Health-aware, per-destination selection between multiple VPN tunnels on a Linux router.
All site specifics live in a config file; the repository contains no environment-specific values.

## 1. Purpose

- **Failover:** when a tunnel stops passing traffic, new connections move to the next healthy tunnel; when it recovers, they move back.
- **Per-destination selection (phase 2):** for frequently used destinations, measure which tunnel is faster and prefer it for a limited time.
- **Static preferences:** route configured prefixes via a preferred tunnel (e.g. a provider's own ranges via that provider's tunnel), subject to health.

## 2. Non-goals

The tool deliberately does **not**:

- create or modify interfaces, routing tables, `ip rule`s, or firewall zones;
- implement a kill switch or any leak protection — that stays in the host firewall;
- touch traffic outside the configured ingress interfaces;
- alter established connections (decisions apply to new connections only) — with one exception: when a tunnel becomes unhealthy, its conntrack entries are deleted (`conntrack.flush_on_unhealthy`, default on), so long-lived flows (UDP, QUIC) are decided anew instead of staying pinned to a dead tunnel.

If the tool is stopped, the host must still behave safely using its own default routing.

## 3. Host requirements (provided by the system, not the tool)

For each managed tunnel:

1. The tunnel is a network interface (e.g. WireGuard).
2. A dedicated routing table containing a default route via that interface, for each family the tunnel carries. The route must come back when the interface is recreated or set up again (Linux deletes a device's routes when it goes down); the health check verifies it (§6).
3. A policy rule `fwmark <mark>/<mask> lookup <table>` for IPv4 and IPv6 (`ip rule`, `ip -6 rule`), with a priority that is evaluated before the main table and after any rules that must stay untouched (e.g. strictly isolated segments).
4. Tunnel endpoint traffic must not be routed into any tunnel (e.g. host routes for endpoints via the underlying WANs). The tool additionally never marks addresses in `exclude`. If WireGuard's own `fwmark` is used, it must lie outside `mark_mask`.
5. Leak protection: the firewall allows forwarding from steered ingress only into tunnel interfaces.
6. Source NAT (masquerade) on traffic leaving through the tunnels.
7. Reverse-path filtering loose (`rp_filter=2`) or off on tunnel interfaces; strict mode drops replies arriving on a tunnel, because the main table points the internet at the WAN.
8. Kernel: nftables with `fib`, `ct` and verdict maps; ctnetlink (`nf_conntrack_netlink`, Linux ≥ 5.3 for filtered flush). With `include_local_output`, the main table needs a route for the initial lookup of local connections (normally the WAN default).

Unmarked traffic falls through to the host's normal routing — this is the fail-safe default.

## 4. Architecture

A single daemon owns one nftables table (default `inet tunsel`) and nothing else.

### 4.1 Mark scheme

- Each tunnel has a unique, non-zero mark value within `mark_mask`.
- The tool only reads/writes bits inside `mark_mask`, so other mark users can coexist.
- Every mark write goes through a per-tunnel chain using constant operands only (`mark & ~mask | value`). Combining two runtime values (e.g. `(ct mark & ~m) | (meta mark & m)`) is not supported by the kernels on typical routers, so maps hold verdicts (`goto to_<tunnel>`) rather than mark values.
- On `ct state new`, the chosen mark is written to the packet and to `ct mark`; subsequent packets restore it from `ct mark`. NAT and flow offloading therefore stay consistent for the lifetime of a connection.
- Restore happens only for packets entering on an ingress interface (or local output). Replies arriving on a tunnel are never marked; otherwise the policy rule would send them straight back into the tunnel.

### 4.2 nftables objects

As installed (example: two tunnels, `mark_mask 0xf`; `nft list table inet tunsel`):

```
table inet tunsel {
  counter new { packets 0 bytes 0 }                             # named counters, see 4.4
  counter local { ... }
  counter excluded { ... }
  counter static_wg_a { ... }                                   # static_, default_, restore_ per tunnel
  ...

  set ingress  { type ifname; }
  set exclude4 { type ipv4_addr; flags interval; }              # never marked
  set exclude6 { type ipv6_addr; flags interval; }
  map static4  { type ipv4_addr : verdict; flags interval; }    # effective static prefs → goto static_<tunnel>
  map static6  { type ipv6_addr : verdict; flags interval; }

  chain to_wg_a {                                               # one per tunnel
    meta mark set meta mark & 0xfffffff1 | 0x00000001           # i.e. & ~mask | mark
    ct mark set ct mark & 0xfffffff1 | 0x00000001
  }
  chain to_wg_b { ... }

  chain static_wg_a { counter name "static_wg_a" goto to_wg_a } # one per tunnel
  chain static_wg_b { ... }

  chain pick4 { counter name "default_wg_b" goto to_wg_b }      # current defaults
  chain pick6 { counter name "default_wg_a" goto to_wg_a }

  chain decide {
    fib daddr type local counter name "local" return
    fib daddr type broadcast counter name "local" return
    fib daddr type multicast counter name "local" return
    ip daddr @exclude4 counter name "excluded" return
    ip6 daddr @exclude6 counter name "excluded" return
    ip daddr vmap @static4                                      # no entry → next rule
    ip6 daddr vmap @static6
    meta nfproto ipv4 goto pick4
    meta nfproto ipv6 goto pick6
  }

  chain steer {
    ct state new counter name "new" goto decide
    ct mark & 0x0000000f == 0x00000001 counter name "restore_wg_a" goto to_wg_a   # restore, one per tunnel
    ct mark & 0x0000000f == 0x00000002 counter name "restore_wg_b" goto to_wg_b
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname @ingress jump steer
  }

  chain output {                                                # only with include_local_output
    type route hook output priority mangle; policy accept;      # route hook → re-route on mark change
    meta mark & 0x0000000f != 0x00000000 return                 # pre-marked, e.g. the tool's own probes
    jump steer
  }
}
```

Phase 2 adds `learned4`/`learned6` (`type ipv4_addr : verdict; flags timeout`), looked up in `decide` before the static maps.

### 4.3 Materialized state

The daemon owns the *effective* contents of `static*`, `learned*` and `pick4`/`pick6`:

- `static*` is derived from config minus entries whose tunnel is unhealthy. Nested prefixes are flattened into disjoint intervals, the more specific prefix winning; when a specific entry is dropped, a covering static prefix (if any) takes over, otherwise the default applies.
- `learned*` never contains entries for unhealthy tunnels.
- `pick4`/`pick6` point at the first healthy tunnel in `default_order` that carries the family (`families`, default both). If none is healthy, the last value is kept (traffic fails closed via the firewall, never leaks). With no previous value (cold start, nothing healthy) the chain is empty and traffic stays unmarked.

Every change replaces the whole table in one nft transaction (delete + create), so there is never a partially updated state; conntrack marks of existing connections are unaffected. The daemon re-checks every 15 s that its table exists and re-applies it if another tool removed it.

### 4.4 Counters

Named counters attribute new connections to the decision taken: `new` counts every new connection entering `decide`, and exactly one of `local`, `excluded`, `static_<tunnel>` or `default_<tunnel>` counts its outcome; the difference is the connections left unmarked (no default for the family). `restore_<tunnel>` counts the upstream packets and bytes of established connections. Each apply reads the counters of the table it replaces and creates the new ones with those values, so they count from the table's first install (normally boot, or until `cleanup_on_exit`), not from the last change. Packets of flows offloaded to a flowtable skip the hook, so `restore_*` undercounts with flow offloading; the per-decision counts are unaffected, since the first packets of a connection are never offloaded.

## 5. Decision order (per new connection)

1. Destination is a local, broadcast or multicast address, or in `exclude` → unmarked (host routing).
2. `learned` entry → that tunnel.
3. `static_pref` entry → that tunnel.
4. `pick4`/`pick6` → first healthy tunnel in `default_order` that carries the family.

Health filtering is applied when materializing 2–4, so a dead tunnel is never selected.

## 6. Health checking

- Probes are sent **bound to the tunnel device** (`SO_BINDTODEVICE`) and **carry the tunnel's mark** (`SO_MARK`), so a tunnel can be tested even while it carries no traffic. The mark selects the tunnel's routing table and makes the output chain leave probes alone (otherwise, with `include_local_output`, they would be re-marked to the default tunnel).
- Per tunnel: one or more targets, probe type `icmp` (raw socket, needs `NET_RAW`) or `tcp:<port>` (a completed handshake or a RST counts as an answer), interval, timeout.
- A round passes if at least `min_ok` targets answer.
- Every round also checks that a route lookup with the tunnel's mark resolves via the tunnel device (`ip route get <target> mark <mark>`). A device-bound probe still gets out when the policy table has lost its route, while forwarded traffic would fall through to other tables.
- Hysteresis: `fail_after` consecutive failed rounds → unhealthy; `recover_after` consecutive passed rounds → healthy. The first round after start sets the state directly.
- Interface missing or down, or the route check failing, is treated as immediately unhealthy.
- Latency: every probe records its round-trip time (ICMP echo to reply; TCP until the handshake completes or is refused). The last 360 probes per target (1 h at the default interval) are kept in memory, with lost probes, including rounds skipped while the link is down; the status reports last, min, avg, max, jitter (mean change between consecutive answers) and loss over that window, and the samples on request. A reload keeps them for unchanged tunnels.
- Rationale: an "up" WireGuard interface says nothing about whether the peer answers.

## 7. Per-destination learning (phase 2)

- **Candidates:** top-N destinations by bytes from conntrack (ingress-steered flows only), refreshed periodically.
- **Measurement:** TCP handshake time to `probe.port` via each healthy tunnel (bound sockets), several samples, median.
- **Decision:** switch only if the winner beats the current choice by `min_gain.abs` **and** `min_gain.rel`; store with `ttl`. Repeated flips within a window are damped.
- **Caveat:** CDN answers depend on the resolver's location. A measurement compares paths to the *same* IP; it does not account for a different IP the other tunnel's resolver might have returned. Documented limitation, not solved in phase 2.
- **Caveat:** ICMP is not used for learning (often deprioritized by VPN servers).

## 8. Failure semantics

| Situation | Behavior |
|---|---|
| Daemon not running (boot, crash) | Learned entries expire; last defaults stay; unmarked traffic uses host routing. No leak (firewall). |
| Daemon (re)starts | The first health round completes before the table is touched, so the previous table stays in effect until a fresh decision is installed. The defaults of an installed table are read back and kept if no tunnel is healthy. Conntrack entries of tunnels found unhealthy are flushed. |
| A tunnel fails | Within `fail_after × interval` (immediately for link down / route missing), new connections avoid it, its learned entries are removed and its conntrack entries are flushed. |
| All tunnels fail | No healthy target; last defaults stay; traffic fails closed via the firewall. |
| Config invalid at start | Daemon refuses to start; existing nft table left untouched. |
| Config invalid on `SIGHUP`, or its ruleset rejected by nft | Error logged; the daemon keeps running with the previous configuration and its monitors. |
| Table removed by another tool | Re-applied within 15 s. |
| Daemon exits cleanly | Optional: remove its table (`cleanup_on_exit`), restoring pure host routing. |

## 9. Runtime and deployment

- Language: Go, static binary, no cgo. Libraries: `github.com/google/nftables`, a netlink conntrack client.
- Targets: `linux/arm/v7`, `linux/arm64`, `linux/amd64`.
- Container: see 9.1.
- Also runnable natively as a service: OpenWrt package with a procd service (9.2), or systemd.
- Config: YAML, or UCI on OpenWrt (9.2), chosen by file name (`.yaml`/`.yml` is YAML); both map to the same structure and the same validation, with unknown keys as errors. Validated at start; `SIGHUP` reloads. A reload keeps the health state of tunnels whose configuration is unchanged. `status.socket` and `log.format` changes need a restart.
- CLI: `tunsel run -config <path>`, `tunsel check -config <path>`, `tunsel status [-socket <path>] [-json] [-flows] [-history]`, `tunsel version`.

### 9.1 Container image

A working Docker engine on the host is assumed; the tool ships only the image and a compose file.

#### Image

- Multi-arch manifest: `linux/arm/v7` (`GOARM=7`), `linux/arm64`, `linux/amd64`.
- Base `scratch`: the static binary only, as entrypoint. No shell, no `nft` binary — nftables and conntrack are driven via netlink.
- Fixed paths: config `/etc/tunsel/config.yaml`, runtime directory `/run/tunsel/` (status socket `/run/tunsel/tunsel.sock`).
- Name and registry are a CI parameter (`<registry>/tunsel`). Tags: `X.Y.Z`, `X.Y`, `latest`.

#### Runtime contract

| Aspect | Requirement |
|---|---|
| Network | host network namespace (`network_mode: host`) |
| Capabilities | drop all, add `NET_ADMIN` (nftables, conntrack), `NET_RAW` (ICMP probes, `SO_BINDTODEVICE`) |
| Filesystem | read-only root; config mounted read-only; `/run/tunsel/` mounted as a directory (a socket file cannot be bind-mounted reliably, since it is recreated on start) |
| Signals | `SIGHUP` reloads config; `SIGTERM` shuts down cleanly, honoring `cleanup_on_exit` |
| Logs | stdout/stderr only; log routing is the engine's concern |
| Status | `docker exec tunsel /tunsel status`, or the host CLI against the mounted socket |

**compose.yaml** (shipped in the repository)

```yaml
services:
  tunsel:
    image: ${TUNSEL_IMAGE:-tunsel}:${TUNSEL_TAG:-latest}
    build: .
    container_name: tunsel
    network_mode: host
    cap_drop: [ALL]
    cap_add: [NET_ADMIN, NET_RAW]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    volumes:
      - ${TUNSEL_CONFIG:-./config.yaml}:/etc/tunsel/config.yaml:ro
      - ${TUNSEL_RUN_DIR:-/run/tunsel}:/run/tunsel
    restart: unless-stopped
    stop_signal: SIGTERM
    stop_grace_period: 10s
```

Reload: `docker kill -s HUP tunsel`.

### 9.2 OpenWrt package

For OpenWrt and Turris OS, where Docker support is limited. Built without the SDK by `packaging/openwrt/build-ipk.sh` (`task ipk`), in the SDK's format; CI attaches one package per architecture to each release.

- Architectures: opkg names mapped to the three Go targets (`arm_cortex-a*` → `arm/v7`, `aarch64_*` → `arm64`, `x86_64` → `amd64`); `IPK_ARCHS` in `Taskfile.yml` lists the released ones.
- Depends: `kmod-nft-core`, `kmod-nft-fib`, `kmod-nf-conntrack-netlink` (ctnetlink is not part of a default image).
- Files: `/usr/sbin/tunsel`, `/etc/init.d/tunsel`, `/etc/config/tunsel`.
- Config: UCI, `/etc/config/tunsel`, shipped with `enabled 0` and the placeholder tunnels of `config.example.yaml`. It is a conffile: opkg keeps a changed one on upgrade and removal, and sysupgrade keeps it. The schema is flat: one `tunsel` section named `main` with the global options and the `enabled` switch (read by the init script only), and one `tunnel` section per tunnel with the interface as option `iface` (section names cannot hold `-`), the health options folded in and the tunnel's static preferences as list `prefer`. Learning and metrics have no UCI options until they are implemented.
- `luci-app-tunsel` (`Architecture: all`, depends on `tunsel` and `luci-base`): Services → Tunsel in LuCI. The configuration page is a form on the UCI config; Save & Apply commits it, and the reload trigger reloads the daemon. The status page reads the report through an rpcd exec plugin (`/usr/libexec/rpcd/tunsel`, ubus object `tunsel` with methods `status`, `flows` and `history`, each running `tunsel status -json`), polls it every 5 s and draws the RTT history per target.
- Version: the tag without `v`; untagged builds are `0~<git describe>`, so they sort below every release.

| Aspect | Behavior |
|---|---|
| Install | Service enabled and started (SDK default scripts); while `main.enabled` is 0, start is a no-op with a hint |
| Start | `tunsel check` first, so an invalid config fails at the caller instead of in a respawn loop; procd respawns on crashes |
| Reload | `tunsel check`, then `SIGHUP`; an invalid config is reported and the daemon keeps the previous one. Starts the daemon if it is not running, stops it if `enabled` is now 0. Also triggered by a change to the UCI config (`reload_config`, LuCI's Save & Apply) |
| Stop | `SIGTERM`, 10 s before `SIGKILL` (`cleanup_on_exit`) |
| Upgrade | Stopped and restarted on the new binary; the enabled state is kept |
| Logs | stdout/stderr to logd (`logread -e tunsel`) |
| Status | `/run` links to `/var/run` (tmpfs), so the default socket path works |

## 10. Observability

- Structured logs: health transitions, default switches, learned decisions (with measured values).
- `tunsel status`: health per tunnel (state, since, link, last round, streak, per-target errors), latency per health target (6), current defaults, last apply error; new connections by decision and upstream traffic per tunnel (4.4); per tunnel the static preferences in effect and the address space they cover after flattening and health filtering, and the same for `exclude`. `-flows` adds the current conntrack table attributed to tunnels by mark: entries, distinct destinations, bytes per direction (with `nf_conntrack_acct`, the OpenWrt default) and the top 10 destinations by bytes; dumps are reused for 5 s. `-history` adds the RTT samples. `-json` for scripts. Phase 2 adds top learned entries.
- The status socket takes a one-line request (`status`, optionally followed by `flows` and/or `history`) and answers with the JSON report.
- Optional metrics endpoint bound to localhost.

## 11. Phases

1. **MVP (implemented):** config loading, nft table management, health checks with hysteresis, default switching, `exclude`, `static_pref` with health filtering, conntrack flush on failure, status command, container image. `learning.enabled: true` and a non-empty `metrics.listen` are rejected until phases 2 and 3.
2. **Learning:** conntrack candidate selection, TCP probing, margins, TTL, damping.
3. **Optional:** dynamic prefix sources for `static_pref` (URL lists with refresh), metrics.

## 12. Testing

- Unit tests: config validation, prefix flattening, decision logic, hysteresis, monitor rounds.
- nft tests (root): the ruleset is installed in a throwaway network namespace and compared against `nft list` output.
- Integration test (root, `-tags integration`): LAN client, router, two veth "tunnels" to provider namespaces and a WAN namespace. Per-provider counters assert the path of: default, static and excluded destinations, local output, failover (probes dropped) including a running flow moved by the conntrack flush, recovery, link down with the policy route lost, reload (valid and invalid) and clean shutdown. IPv6 checks are skipped on hosts booted with `ipv6.disable=1`.
- OpenWrt smoke test (Docker, `packaging/openwrt/smoke-test.sh`): the x86_64 package and `luci-app-tunsel` installed into an OpenWrt rootfs booted with procd, dependencies from the feeds; install (disabled), start (invalid and valid config), reload (explicit and by `reload_config`), disable and enable, the rpcd plugin's methods, upgrade (config kept), stop and removal.
- CI runs all of the above and builds the multi-arch image and the packages. Releases are cut by the manually run release workflow, which bumps the major, minor or patch part of the latest version, runs the same jobs, pushes and attests the image and leaves a draft release with the packages; publishing the draft creates the `v*` tag.
