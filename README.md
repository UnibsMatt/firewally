# HTI Firewall Manager

A small web dashboard and API for writing iptables rules between **networks** (LANs, hosts, interfaces) and **services** (protocol + ports) without writing iptables syntax by hand. It runs as a Docker Compose stack and manages the **host** firewall.

```
Networks (LAN 192.168.1.0/24 @ eth1)  ─┐
Services (Web tcp/80,443)              ├─► Rules ─► iptables-restore script ─► host kernel
Settings (defaults, confirm timeout)  ─┘                                   └─► /etc/iptables/rules.v4
```

## Quick start

```bash
cp .env.example .env        # set ADMIN_PASSWORD
docker compose up -d --build
# open http://<host>:8088  (HTTP Basic auth: ADMIN_USER / ADMIN_PASSWORD)
```

Host requirements: Linux with iptables (nft or legacy backend). To restore rules at boot, install `iptables-persistent` (Debian/Ubuntu), which loads `/etc/iptables/rules.v4`. On RHEL-like hosts set `HOST_IPTABLES_DIR=/etc/sysconfig` and add `PERSIST_FILE=/host/iptables/iptables` in the compose file.

## How it works

| Concern | Approach |
|---|---|
| **Does not break other rules** | Only the chains `HTI-INPUT` and `HTI-FORWARD` are managed. They are loaded with `iptables-restore --noflush`, which replaces those two chains atomically and leaves Docker, libvirt and fail2ban rules alone. |
| **Hooks** | `INPUT → HTI-INPUT`. Forwarded traffic is hooked into `DOCKER-USER` when Docker is present (Docker's recommended place for user rules), otherwise into `FORWARD`. |
| **Validation** | Input is strictly validated (CIDR, interface names, port ranges, names), and the generated script is checked with `iptables-restore --test` before anything is applied. |
| **Lock-out protection** | The app takes a snapshot of the managed chains, then applies the change. If you don't confirm within *Confirm timeout* seconds (default 60), the snapshot is restored automatically. Set the timeout to 0 to apply without confirmation. |
| **Persistence** | Once a change is confirmed, the full live ruleset (`iptables-save`) is written atomically to the host's `/etc/iptables/rules.v4`, the same thing `netfilter-persistent save` does. The managed part alone is also written to `hti-managed.rules`. |
| **nft vs legacy** | Auto-detected so it matches the host, using the same heuristic as kube-proxy. You can force it with `IPTABLES_MODE`. |
| **Restart** | On start, the last *confirmed* ruleset is re-applied. Changes still waiting for confirmation are rolled back. |
| **Audit** | Every apply, confirm and rollback is recorded in History together with the exact script. |
| **Rule details** | Port lists longer than multiport's 15-port limit are split automatically. `tcp+udp` produces two rules. Each rule gets a comment `hti:<id> <name>`, so you can trace it in `iptables -L`. |

### Concepts

- **Network**: a CIDR (subnet or single host), an interface (`eth1`, `br-lan`, `veth+`), or both. A source network matches `-s`/`-i`. A destination network matches `-d`/`-o` (`-o` only on forward rules).
- **Service**: `tcp`, `udp`, `tcp+udp`, `icmp` or `any`, with ports like `22`, `80,443` or `8000-8010`.
- **Rule**: direction (*input* = traffic to the host itself, *forward* = traffic routed between LANs or to containers), source, destination, service, and an action (`ACCEPT` / `DROP` / `REJECT`). It can also log matches. An empty field means *any*. Rules are evaluated top to bottom and the first match wins.
- **Defaults**: what happens after the last rule. `RETURN` hands the packet back to the host chain and its policy. `DROP` gives you a default-deny zone; loopback and established traffic are still allowed.

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / *(required)* | HTTP Basic credentials |
| `BIND_HOST` / `PORT` | `0.0.0.0` / `8088` | Listen address (host network) |
| `IPTABLES_MODE` | `auto` | `auto`, `nft` or `legacy` |
| `APPLY_ON_START` | `true` | Re-apply the last confirmed ruleset on container start |
| `DRY_RUN` | `false` | Only generate scripts; never touch iptables (useful for development) |
| `HOST_IPTABLES_DIR` | `/etc/iptables` | Host directory mounted at `/host/iptables` |

## Security notes

- The container uses `network_mode: host` with `NET_ADMIN`/`NET_RAW`, so it **controls the host firewall**. Treat the dashboard like root SSH access.
- Prefer `BIND_HOST=127.0.0.1` and reach the dashboard through an SSH tunnel or a TLS reverse proxy. HTTP Basic credentials over plain HTTP are only acceptable on a trusted LAN.
- Before switching *Input default* to `DROP`, create an input `ACCEPT` rule for your admin access (e.g. SSH and port 8088 from your management LAN). The confirmation timeout is your safety net.
- Only IPv4 (`iptables`) is managed. IPv6 is left untouched.

## API

All endpoints are under `/api` and use HTTP Basic auth. Interactive docs are at `/docs`.

| Method | Path | |
|---|---|---|
| GET/POST | `/networks`, `/services`, `/rules` | list / create |
| PUT/DELETE | `/networks/{id}`, `/services/{id}`, `/rules/{id}` | update / delete (409 if still referenced) |
| POST | `/rules/reorder` | `{"ids": [3, 1, 2]}` |
| GET/PUT | `/settings` | defaults, established, confirm timeout |
| GET | `/preview` | generated script + warnings |
| POST | `/apply`, `/confirm`, `/rollback` | apply workflow |
| GET | `/status`, `/live`, `/history` | sync state, live counters, audit log |

## Layout

```
docker-compose.yml
.env.example
backend/
  Dockerfile
  app/
    main.py       FastAPI routes, auth
    models.py     validation
    firewall.py   rule rendering + iptables execution
    manager.py    apply / confirm / rollback / persist
    db.py         SQLite (volume hti-data)
    static/       dashboard (plain HTML/CSS/JS, no build step)
```
