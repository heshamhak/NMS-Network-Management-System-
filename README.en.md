**English** | **[العربية](README.md)**

# NMS — Network Management System

**NMS (Network Management System)** is an open-source management and monitoring console for Linux/ucode-based routers and network gateways. It features a modern bilingual interface (**English LTR / Arabic RTL**) and a dual-daemon privilege-separated architecture (`noc-apid` + `noc-helperd`) designed for security, responsiveness, and minimal resource usage.

---

## Target Audience
* **Network Administrators & Micro-ISPs:** Real-time monitoring, connected client discovery, per-client rate limiting, and firewall management from a single unified console.
* **Power Users:** Replace legacy router admin panels with an interactive live topology tree, DNS filtering, and Two-Factor Authentication (`TOTP`).
* **Developers & Systems Engineers:** A clean, extensible architecture for building custom control planes on embedded and `x86_64` gateways.

---

## Supported Systems & Requirements
* **Target OS:** OpenWrt (`24.10.0` with `opkg` and `25.12.6` with `apk`) using `procd`, `ubus`, `uci`, and `nftables` (`fw4`).
* **Supported Architectures:** `noarch` / `all` (zero ELF binaries — portable across `x86_64`, `ARM64`, `ARMv7`, and any `ucode`-capable target).
* **Required Packages:** `ucode` with modules (`fs`, `ubus`, `uci`, `socket`, `math`, `struct`, `uloop`, `digest`) — declared as package dependencies or installed via `scripts/install.sh`.
* **Optional Integrations:** `AdGuard Home`, `SQM / CAKE`, `Tailscale VPN`, `banIP`, `Docker`.

---

## Resource Consumption
Measured live on a running `x86_64` gateway (`Linux 6.12`):
* **API & Web Engine (`noc-apid`):** ~**`37.0 MB` RAM (`RSS`)**, **`1% – 2%` CPU** during active `SSE` streaming.
* **Privileged Helper (`noc-helperd`):** ~**`2.4 MB` RAM (`RSS`)**, **`0%` CPU** when idle.
* **Total Footprint:** ~**`39.4 MB` RAM**, **`0% – 2%` CPU**, and less than **`1 MB`** disk space.

---

## Core Features
* **Overview & Ports:** Real-time CPU, RAM, disk, `conntrack` sessions, and per-interface throughput via `SSE` streaming.
* **Interactive Live Topology:** Visual path tree from Internet uplinks through the router to connected devices with link heat gradients, instant `Ping` probes, and unbounded pan/zoom.
* **Clients & Access Control:** Automatic device discovery, instant `nftables` blocking, per-client upload/download rate limits, and static `DHCP` leases.
* **DNS Filtering & Firewall:** Native `AdGuard Home` integration, `fw4` zones/rules, port forwarding, and `SQM / CAKE` traffic shaping.
* **Security & Isolation:** Two-Factor Authentication (`TOTP`), privilege separation between `noc-api` and `noc-helperd`, and automatic rollback on connectivity loss.
* **Global Command Palette (`Ctrl+K`):** Instant search across tabs, clients, and actions.
* **Full Bilingual Support (`EN / عربي`):** Instant live switching between English (`LTR`) and Arabic (`RTL`) without page reload.

---

## Quick Install

Clone the repository and run the installer as `root`:

```sh
git clone https://github.com/heshamhak/NMS-Network-Management-System-.git
cd NMS-Network-Management-System-
sh scripts/install.sh
```

After installation completes, the console URL and initial bootstrap token will be displayed:
* **Web Console:** `http://<ROUTER_LAN_IP>:8780/`
* **Bootstrap Token:** `/etc/noc-console/bootstrap.token`

### Uninstall
```sh
sh scripts/uninstall.sh          # Remove services and web assets (keep config)
sh scripts/uninstall.sh --purge  # Full removal including config and credentials
```

---

## Repository Structure

```text
NMS-Network-Management-System-/
├── backend/
│   ├── noc-apid             # HTTP/API/SSE server & session manager (ucode)
│   ├── noc-helperd          # Privilege-separated system executor (ucode)
│   ├── nms_archive.uc       # Archive validation & transactional backup restore
│   ├── nms_network.uc       # Network, VLAN, DSA & IPv6 management
│   ├── nms_fw_wifi.uc       # Firewall fw4 & wireless iw/hostapd validation
│   ├── nms_discovery.uc     # Unified client & bridge discovery
│   ├── nms_clients.uc       # Per-client quotas, schedules & nftables rules
│   ├── nms_access_dhcp.uc   # RBAC enforcement & transactional DHCP hardening
│   ├── nms_sqm.uc           # SQM / CAKE shaping & tc verification
│   └── nms_topology.uc      # Evidence-driven live topology engine
├── frontend/
│   ├── index.html           # Main UI shell (strict CSP)
│   ├── styles.css           # Design tokens & RTL/LTR layout
│   ├── app.js               # Core frontend controller & DOM patching
│   ├── noc-topology.js      # Interactive live topology tree engine
│   ├── noc-search.js        # Global search & command palette (Ctrl+K)
│   ├── noc-tools.js         # Table sorting, filtering & section collapsers
│   ├── netchart.js          # Custom lightweight throughput charts
│   ├── nms-i18n.js          # Bilingual translation engine (EN / AR)
│   ├── manifest.json        # PWA manifest
│   └── sw.js                # Service Worker cache controller
├── packaging/openwrt/
│   └── Makefile             # Official OpenWrt package definition (opkg / apk)
├── init.d/
│   ├── noc-helperd          # Helper daemon init script
│   └── noc-apid             # API daemon init script
├── schemas/
│   └── noc_schemas.json     # API, backup/restore & telemetry schema contracts
├── scripts/
│   ├── install.sh           # Transactional installer with automatic rollback
│   ├── uninstall.sh         # Clean uninstaller
│   ├── build_packages.py    # Native .ipk & .apk package builder
│   └── run_ci_local.sh      # Full CI verification runner (fails on any skip/failure)
├── ci/
│   └── github-actions-ci.yml # GitHub Actions CI workflow template
├── tests/
│   ├── verify_noc_p15.py        # Security, CSP, schema & WCAG contrast checks
│   ├── verify_nms_local.py      # Local verification, DOM & API integration tests
│   ├── verify_phase3d_compat.py # Isolated OpenWrt 24.10.0 & 25.12.6 chroot suites
│   ├── verify_phase5a_pkg.py    # Signed .ipk/.apk lifecycle & migration tests
│   ├── verify_phase5c_ui.py     # Frontend RBAC, validate/restore separation & SSE tests
│   └── verify_phase*_ucode.uc   # Production ucode module suites (Phases 3A–5B)
└── LICENSE                  # MIT License
```

---

## Development & Testing
Run the complete verification pipeline (local + dual OpenWrt chroots + packaging + UI):

```sh
sh scripts/run_ci_local.sh
```

Or run individual suites:

```sh
python3 tests/verify_noc_p15.py
python3 tests/verify_nms_local.py
python3 tests/verify_phase3d_compat.py
python3 tests/verify_phase5a_pkg.py
python3 tests/verify_phase5c_ui.py
```

---

## License
Licensed under the [MIT License](LICENSE).
