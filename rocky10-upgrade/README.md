# Rocky Linux 9 to 10 Upgrade Guide for RADS

Upgrade scripts and documentation for migrating RADS-based Samba AD DC servers from Rocky Linux 9.x to Rocky Linux 10.x.

## Overview

Rocky Linux 10 introduces several changes that affect Samba AD DC installations:

1. **Network interface naming** - Changes from `enp*` to `ens*` pattern
2. **Samba DC packages** - Not available in official repos, must be rebuilt
3. **Python/library changes** - Require recompilation of Samba with DC support

## Files

| File | Description |
|------|-------------|
| `rocky9-to-10-upgrade.sh` | Main upgrade script (3 phases) |
| `fix-network-post-upgrade.sh` | Network interface rename fix |
| `fix-kea-post-upgrade.sh` | Kea DHCP migration (if applicable) |
| `ROCKY-10-UPGRADE-README.md` | Detailed documentation |
| `KEA-UPGRADE-REPORT.md` | Kea DHCP migration details |

## Quick Start

```bash
# 1. Create VM snapshot/backup first!

# 2. Pre-flight checks
./rocky9-to-10-upgrade.sh --check

# 3. Phase 1: OS upgrade
./rocky9-to-10-upgrade.sh --phase1

# 4. Phase 2: Fix network (BEFORE reboot!)
./rocky9-to-10-upgrade.sh --phase2

# 5. Reboot
reboot

# 6. Phase 3: Rebuild Samba DC (after reboot)
./rocky9-to-10-upgrade.sh --phase3
```

## Requirements

- Rocky Linux 9.x with RADS Samba AD DC installation
- CPU with x86-64-v3 support (required for Rocky 10)
- Minimum 10GB free disk space
- VM snapshot or backup (recommended)

## Tested On

- Rocky Linux 9.7 → 10.1
- Samba 4.22.4 with AD DC support

## Credits

- Original RADS: https://github.com/fumatchu/RADS
- Upgrade scripts contributed by the community
