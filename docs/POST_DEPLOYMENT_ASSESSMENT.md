# NMS Post-Deployment Assessment and Roadmap

Status date: 2026-11-22
Repository baseline: `b74d7b3c0d7973a78954a286612c5776a38476d0` (branch `main`)
CI baseline: GitHub Actions run `45062681485`, 340 passed, 0 failed, 0 skipped.
Scope: documentation only. No router change is performed or implied by this document.

## 1. Closed and approved stages

| Stage | Result |
|---|---|
| Phase 2 | Closed |
| Phase 3A-3D | Closed |
| Phase 4A-4F | Closed |
| Phase 5A-5D | Closed |
| Real-router Stage A, A2 | Closed |
| Real-router Stage B (TLS, `2c4121b`) | Closed |
| Option A, root interface redirect and atomic LuCI restore (`b74d7b3`) | Closed |

## 2. Live router state (192.168.1.1, OpenWrt 25.12.6 x86_64)

- NMS interface: `https://192.168.1.1:8743/` (stunnel TLS proxy in front of `noc-apid` on `127.0.0.1:8780`).
- Redirects: `/` and `/cgi-bin/luci` on ports 80 and 443 lead to port 8743, restricted to a trusted-host policy (private IPv4, local IPv6, approved local hostnames, system hostname, valid port 1..65535).
- Original LuCI backups are pinned by SHA-256 and recoverable with `/usr/sbin/restore-luci`.
  - `/www/index.luci.bak.html`: `f68138db6165da195c2b8347ebdfa43b1c1a13e1c96386d2abed09578cb06b30`
  - `/www/cgi-bin/luci.orig.bak`: `aced6c9b2e621bb6e1dd1bb7d675925e9325ed901f49b1aabb0696a06942dacb`
- Redirect can be re-enabled with `/usr/sbin/enable-nms-root-redirect`.
- Services verified running: `noc-apid`, `noc-helperd`, `noc_tls_proxy` (stunnel).
- Protected files unchanged: `/etc/config/uhttpd`, `tls.key`, `auth.json`, Pro app files.

## 3. Known gaps and observations

1. Stage evidence for the real router was gathered through manual SSH sessions; there is no automated post-deploy smoke script in the repository.
2. The `/proc/sys/kernel/hostname` fallback is tested against a file inside an isolated rootfs, not a live mounted procfs.
3. The installed `enable-nms-root-redirect` stamps the hostname once at activation. A later hostname change requires re-running the activator.
4. The default `stunnel` init service is intentionally disabled; the NMS proxy runs as a `noc-apid` procd instance. This is documented here to avoid confusion during audits.
5. A session cookie value was disclosed in a report and was invalidated. Reports must never include live cookie values.
6. The default `admin` credential used for acceptance testing should be rotated by the owner after handover.

## 4. Proposed next task (requires reviewer approval before any work)

Name: Post-deploy smoke script and credential hygiene.

Scope (repository and read-only router checks only until separately authorized):
- Add `scripts/smoke-check.sh`, a read-only script that verifies redirects, LuCI backup hashes, file modes and ownership, service status and listeners, and prints a pass/fail summary without printing secrets.
- Add CI tests for the script using the existing sandbox harness.
- Document the credential rotation procedure.

Acceptance criteria:
- Script exits non-zero on any mismatch and never prints cookies, tokens or passwords.
- Full CI passes with zero failures and zero skipped tests.
- No modification of the router during development.
- Reviewer approval before the script is run against 192.168.1.1.
