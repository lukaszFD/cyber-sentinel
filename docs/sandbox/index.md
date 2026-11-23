# Browser Sandbox

A "dirty browsing" browser for opening suspicious links. Everything it does is recorded as CTI material: every URL (with headers, redirects and payload hashes) and every DNS query. It is isolated from the LAN and from the rest of the stack.

Deployed by playbooks 04.1 (files), 04.2 (containers), 04.3 (database schema) and 04.7 (post-config); Nginx entries in 05, the *Sandbox Scan* workflow in 04.6.

This tab has three pages:

| Page | What |
|---|---|
| Overview (this page) | Containers, networks, isolation, TLS interception |
| [Using & Testing](usage.md) | Logging in, wiping the browser, logs, test scenarios |
| [Data & CTI](data.md) | Database schema and CTI checks of what the sandbox saw |

## Containers

| Container | Image | Networks | Role |
|---|---|---|---|
| `sandbox-browser` | `linuxserver/ungoogled-chromium` | `sandbox_network` `.10` | ungoogled-chromium in the Selkies web viewer (port 3000). Profile on tmpfs, no volumes except the read-only Chromium policy |
| `sandbox-mitmproxy` | `mitmproxy/mitmproxy` | `sandbox_network` `.2`, `sandbox_egress` `.2` | The only way out. Logs every flow, refuses private destinations |
| `sandbox-pihole` | `pihole/pihole` (same pin as the main Pi-hole) | `sandbox_network` `.3`, `internal_network` `.16` | DNS for the sandbox only — **no adlists**, upstream Unbound `10.10.10.2` |
| `sandbox_log_processor` | built (`python:3.12-slim`) | `internal_network` `.5` | Reads both logs read-only and stores them in `cyber_sentinel_sandbox` ([Data & CTI](data.md)); not reachable from the sandbox |

Images are pinned in `ansible/group_vars/all/images.yml` (`sandbox_browser`, `mitmproxy`, `pihole`), multi-arch.

## Networks

```mermaid
flowchart LR
    U[Your browser] -->|HTTPS sandbox.&lt;suffix&gt;| N[nginx-proxy]
    N -->|sandbox_network| B[sandbox-browser]
    B -->|HTTP proxy :8080| M[sandbox-mitmproxy]
    M -->|DNS| P[sandbox-pihole]
    P -->|internal_network| UB[unbound]
    M -->|sandbox_egress| I((Internet))
```

- `sandbox_network` (`10.10.20.0/24`) is `internal: true`: no route out. Nginx joins it (`.100`) only to serve the viewer.
- `sandbox_egress` (`10.10.21.0/24`) has only mitmproxy.
- Chromium is forced through the proxy by a managed policy (`ProxySettings`, no bypass, loopback included) and WebRTC may only use the proxy (`WebRtcIPHandling: disable_non_proxied_udp`).
- The mitmproxy addon resolves every destination itself and refuses it when any address is not public (RFC 1918, loopback, link-local, CGNAT, reserved). The checked IP is pinned for the connection, so DNS rebinding cannot reach the LAN, the stack or Nginx. Refused attempts are logged as `blocked`.
- The sandbox never uses the main Pi-hole (`10.10.10.4`), so none of its traffic reaches `cyber_sentinel.dns_queries` or the n8n queue.

Accepted risk: a browser exploit with code execution inside `sandbox-browser` can talk directly to Nginx and the sandbox Pi-hole on `sandbox_network` (nothing else, no internet).

## TLS interception

mitmproxy creates its CA on first start in `config/sandbox/mitmproxy/` on the host (private key stays there, 0600). Playbook 04.7 puts the public certificate into the Chromium policy (`CACertificates`) and recreates the browser when it changes. To rotate the CA, delete `config/sandbox/mitmproxy/mitmproxy-ca*`, restart `sandbox-mitmproxy` and re-run 04.7.

Upstream certificates are **not** enforced (`ssl_insecure`): malicious sites often have self-signed or expired certificates, and seeing them is the point. The addon verifies each upstream chain itself and logs the result in `upstream_tls`.

## Resources

Memory limits: browser 1.5 GB (shared memory 512 MB), mitmproxy 384 MB, Pi-hole 256 MB, log processor 128 MB.
