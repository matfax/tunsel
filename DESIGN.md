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
  set ingress  { type ifname; }
  set exclude4 { type ipv4_addr; flags interval; }              # never marked
  set exclude6 { type ipv6_addr; flags interval; }
  map static4  { type ipv4_addr : verdict; flags interval; }    # effective static prefs
  map static6  { type ipv6_addr : verdict; flags interval; }

  chain to_wg_a {                                               # one per tunnel
    meta mark set meta mark & 0xfffffff1 | 0x00000001           # i.e. & ~mask | mark
    ct mark set ct mark & 0xfffffff1 | 0x00000001
  }
  chain to_wg_b { ... }

  chain pick4 { goto to_wg_b }                                  # current defaults
  chain pick6 { goto to_wg_a }

  chain decide {
    fib daddr type local return
    fib daddr type broadcast return
    fib daddr type multicast return
    ip daddr @exclude4 return
    ip6 daddr @exclude6 return
    ip daddr vmap @static4                                      # no entry → next rule
    ip6 daddr vmap @static6
    meta nfproto ipv4 goto pick4
    meta nfproto ipv6 goto pick6
  }

  chain steer {
    ct state new goto decide
    ct mark & 0x0000000f == 0x00000001 goto to_wg_a             # restore, one per tunnel
    ct mark & 0x0000000f == 0x00000002 goto to_wg_b
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
- Also runnable natively as a service (procd, systemd).
- Config: YAML, validated at start (unknown keys are errors); `SIGHUP` reloads. A reload keeps the health state of tunnels whose configuration is unchanged. `status.socket` and `log.format` changes need a restart.
- CLI: `tunsel run -config <path>`, `tunsel check -config <path>`, `tunsel status [-socket <path>] [-json]`, `tunsel version`.

### 9.1 Container image

A working Docker engine on the host is assumed; the tool ships only the image and a compose file.

**Image**

- Multi-arch manifest: `linux/arm/v7` (`GOARM=7`), `linux/arm64`, `linux/amd64`.
- Base `scratch`: the static binary only, as entrypoint. No shell, no `nft` binary — nftables and conntrack are driven via netlink.
- Fixed paths: config `/etc/tunsel/config.yaml`, runtime directory `/run/tunsel/` (status socket `/run/tunsel/tunsel.sock`).
- Name and registry are a CI parameter (`<registry>/tunsel`). Tags: `X.Y.Z`, `X.Y`, `latest`.

**Runtime contract**

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

## 10. Observability

- Structured logs: health transitions, default switches, learned decisions (with measured values).
- `tunsel status`: health per tunnel (state, since, link, last round, streak, per-target errors), current defaults, interval counts, last apply error; `-json` for scripts. Phase 2 adds top learned entries.
- Optional metrics endpoint bound to localhost.

## 11. Phases

1. **MVP (implemented):** config loading, nft table management, health checks with hysteresis, default switching, `exclude`, `static_pref` with health filtering, conntrack flush on failure, status command, container image. `learning.enabled: true` and a non-empty `metrics.listen` are rejected until phases 2 and 3.
2. **Learning:** conntrack candidate selection, TCP probing, margins, TTL, damping.
3. **Optional:** dynamic prefix sources for `static_pref` (URL lists with refresh), metrics.

## 12. Testing

- Unit tests: config validation, prefix flattening, decision logic, hysteresis, monitor rounds.
- nft tests (root): the ruleset is installed in a throwaway network namespace and compared against `nft list` output.
- Integration test (root, `-tags integration`): LAN client, router, two veth "tunnels" to provider namespaces and a WAN namespace. Per-provider counters assert the path of: default, static and excluded destinations, local output, failover (probes dropped) including a running flow moved by the conntrack flush, recovery, link down with the policy route lost, reload (valid and invalid) and clean shutdown. IPv6 checks are skipped on hosts booted with `ipv6.disable=1`.
- CI runs all of the above and builds the multi-arch image; it pushes on `v*` tags.
