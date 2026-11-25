# NMS Multi-Architecture Compatibility & Distribution

`nms-console` is packaged with `PKG_ARCH:=all` (`noarch`, zero ELF binaries) and runs on `ucode`.

## Verified Compatibility Matrix (OpenWrt 25.12.6)

| Architecture | Environment | Status | Notes |
| --- | --- | --- | --- |
| `x86_64` | Production router (`192.168.1.1`) | **PASS** | `noc-helperd`, `noc-apid`, `stunnel`, `HTTP 200` verified |
| `aarch64` (`armsr/armv8`) | QEMU `virt` (`128 MB` RAM) | **PASS** | `nms-console`, `noc-helperd`, `noc-apid`, `stunnel` active |
| `arm` (`armsr/armv7`) | QEMU `virt` (`128 MB` RAM) | **PARTIAL** | `nms-console` + `noc-helperd` active; `noc-apid` requires `stunnel` + `openssl-util` |
| `mips` (`malta/be`) | QEMU `malta` (`64 MB` RAM) | **PARTIAL** | `nms-console` + `noc-helperd` active (`5.5 MB` RAM free); TLS deps not in initramfs |
| `mipsel` (`malta/le`) | QEMU `malta` (`64 MB` RAM) | **PARTIAL** | `nms-console` + `noc-helperd` active (`7.4 MB` RAM free); TLS deps not in initramfs |

## Signed APK Repository (GitHub Pages)

- **Index:** `https://heshamhak.github.io/NMS-Network-Management-System-/packages.adb`
- **Public Key:** `https://heshamhak.github.io/NMS-Network-Management-System-/nms-repo.pub.pem` (SHA-256: `b59eeb6af1d2b75f0345f560bf9736d5afffe5aa056e5a8ec97ee008482f13ec`)
- **Release (`v5.0.0-r1`):** `https://github.com/heshamhak/NMS-Network-Management-System-/releases/tag/v5.0.0-r1`
