# Rocky Linux 9 to 10 Upgrade Guide

## With Samba AD DC Support (RADS-compatible)

**Tested on:** Rocky Linux 9.7 -> 10.1
**Date:** 2026-01-24
**Source:** dc04.sloto.space upgrade experience

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Steps](#detailed-steps)
4. [Known Issues](#known-issues)
5. [Troubleshooting](#troubleshooting)
6. [Post-Upgrade Verification](#post-upgrade-verification)

---

## Prerequisites

### Hardware Requirements

- **CPU:** x86-64-v3 support required (check with: `/lib64/ld-linux-x86-64.so.2 --help | grep x86-64-v3`)
- **Disk:** Minimum 10GB free space
- **RAM:** 4GB+ recommended for Samba DC build

### Software Requirements

- Rocky Linux 9.x (any minor version)
- Root access
- Network connectivity to Rocky mirrors

### Pre-Upgrade Checklist

- [ ] Create VM snapshot or full system backup
- [ ] Document current network configuration
- [ ] Note current interface names (`ip link show`)
- [ ] Backup Samba AD database (`/var/lib/samba/`)
- [ ] Backup NetworkManager connections (`/etc/NetworkManager/system-connections/`)
- [ ] Backup TLS certificates if applicable

---

## Quick Start

```bash
# 1. Download the upgrade script
# (script should already be at /root/rocky9-to-10-upgrade.sh)

# 2. Run pre-flight checks
./rocky9-to-10-upgrade.sh --check

# 3. Phase 1: Upgrade
./rocky9-to-10-upgrade.sh --phase1

# 4. Phase 2: Fix network before reboot
./rocky9-to-10-upgrade.sh --phase2

# 5. Reboot
reboot

# 6. Phase 3: Rebuild Samba DC (after reboot)
./rocky9-to-10-upgrade.sh --phase3
```

---

## Detailed Steps

### Phase 1: Distro-Sync Upgrade

This phase performs the actual OS upgrade:

1. Updates current Rocky 9 system
2. Downloads Rocky 10 release packages
3. Installs release packages (with --force to bypass RPM conflicts)
4. Runs `dnf distro-sync` to upgrade all packages
5. Rebuilds RPM database

**Duration:** 15-30 minutes depending on network speed

**Command:**
```bash
./rocky9-to-10-upgrade.sh --phase1
```

### Phase 2: Post-Upgrade Fixes

**IMPORTANT: Run this BEFORE rebooting!**

This phase fixes issues that would break the system on reboot:

1. **Network Interface Rename Fix**
   - Rocky 10 uses different interface naming (enp* -> ens*)
   - Updates VLAN connection files with new parent interface name
   - Creates backup of original configuration

2. **Old Package Cleanup**
   - Removes el9 kernel packages
   - Removes remaining el9 packages

**Command:**
```bash
./rocky9-to-10-upgrade.sh --phase2
```

### Reboot

After Phase 2 completes:
```bash
reboot
```

### Phase 3: Samba DC Rebuild

**Only needed if running Samba AD DC (RADS installation)**

This phase rebuilds Samba with AD DC support:

1. Installs mock and build dependencies
2. Creates mock configuration with EPEL
3. Downloads Samba source RPM
4. Builds Samba with `--with dc` flag
5. Creates local repository
6. Installs Samba DC packages
7. Starts and enables Samba service

**Duration:** 30-60 minutes (mostly compilation time)

**Command:**
```bash
./rocky9-to-10-upgrade.sh --phase3
```

---

## Known Issues

### 1. Network Interface Naming Change

**Problem:** Interface names change from `enp*` to `ens*` pattern
**Solution:** Phase 2 script automatically fixes configurations

**Supported scenarios:**
- **Servery s VLANy:** Opraví `parent=enp*` na `parent=ens*` ve VLAN souborech
- **Servery bez VLANů:** Přejmenuje hlavní konfiguraci (např. `enp6s18.nmconnection` → `ens18.nmconnection`) a aktualizuje `interface-name` uvnitř

**Manual fix if needed:**
```bash
# Pro servery bez VLANů:
./fix-network-post-upgrade.sh enp6s18 ens18

# Pro servery s VLANy:
sed -i 's/parent=enp6s18/parent=ens18/g' /etc/NetworkManager/system-connections/vlan0.*.nmconnection
nmcli connection reload
```

### 2. Samba DC Not in Official Repos

**Problem:** Rocky 10 only provides `samba-dc-libs`, not full AD DC
**Solution:** Phase 3 rebuilds Samba from source with DC support

### 3. Missing Dependencies for Samba Build

**Problem:** `python3-setproctitle` in EPEL, `lmdb` in CRB
**Solution:** Script enables required repos automatically

### 4. Custom Compiled Software (Kea DHCP)

**Problem:** Custom-compiled Kea linked against el9 libraries fails to start
**Example errors:**
```
libpq.so.private13-5: cannot open shared object file
liblog4cplus-2.0.so.3: cannot open shared object file
libboost_system.so.1.75.0: cannot open shared object file
```

**Solution:** Install official Kea from Rocky 10 repos and run fix script:
```bash
dnf install kea kea-hooks -y
./fix-kea-post-upgrade.sh
```

**What the script fixes:**
- Removes custom systemd services (uses official ones)
- Updates socket paths (`/var/run/` -> `/run/kea/`)
- Updates hooks library paths (`/usr/local/kea/lib/` -> `/usr/lib64/kea/hooks/`)
- Moves run_script hooks to `/usr/share/kea/scripts/`
- Updates log paths to `/var/log/kea/`
- Fixes config permissions for 'kea' user

See `/root/KEA-UPGRADE-REPORT.md` for detailed documentation.

---

## Troubleshooting

### Network Not Working After Reboot

```bash
# Check interface names
ip link show

# Check NetworkManager connections
nmcli connection show

# Manually fix if interface name differs
sed -i 's/parent=OLD_NAME/parent=NEW_NAME/g' /etc/NetworkManager/system-connections/*.nmconnection
nmcli connection reload
nmcli connection up INTERFACE_NAME
```

### Samba Build Fails

```bash
# Check build logs
cat /var/lib/mock/rocky-10-x86_64-epel/result/build.log

# Common issues:
# - Missing dependency: install from EPEL/CRB
# - GPG key error: use --nogpgcheck
```

### Samba Service Won't Start

```bash
# Check status
systemctl status samba

# Check logs
journalctl -u samba -n 50

# Verify database
samba-tool dbcheck

# Verify configuration
testparm
```

---

## Post-Upgrade Verification

### System Checks

```bash
# OS Version
cat /etc/os-release

# Kernel
uname -r

# No el9 packages remaining
rpm -qa | grep el9

# Failed services
systemctl --failed

# dmesg errors
dmesg --level=err,crit,alert,emerg
```

### Network Checks

```bash
# Interface status
ip link show

# VLAN status
nmcli connection show --active | grep vlan

# Connectivity
ping -c 3 8.8.8.8
```

### Samba AD DC Checks

```bash
# Service status
systemctl status samba

# Domain info
samba-tool domain info 127.0.0.1

# Replication status
samba-tool drs showrepl

# Database integrity
samba-tool dbcheck

# DNS records
host -t SRV _ldap._tcp.YOUR_DOMAIN 127.0.0.1

# Package version (should show .dc suffix)
rpm -qa | grep samba-dc
```

---

## Files Created by This Script

| File | Purpose |
|------|---------|
| `/root/rocky9-to-10-upgrade.sh` | Main upgrade script |
| `/root/fix-kea-post-upgrade.sh` | Kea DHCP migration script |
| `/root/fix-network-post-upgrade.sh` | Network fix script (VLAN i non-VLAN servery) |
| `/root/ROCKY-10-UPGRADE-README.md` | This documentation |
| `/root/KEA-UPGRADE-REPORT.md` | Detailed Kea migration report |
| `/root/.servman/SambaManager/sm-samba-dnf-pkg-update-rl10` | RADS update script for RL10 |
| `/etc/mock/rocky-10-x86_64-epel.cfg` | Mock config with EPEL |
| `/root/.samba/*.rpm` | Compiled Samba DC packages |
| `/var/log/rocky-upgrade-*.log` | Upgrade log files |

---

## Rollback

If upgrade fails, restore from your VM snapshot or backup.

There is no supported downgrade path from Rocky 10 to 9.

---

## Credits

- Original upgrade method: https://vinfrastructure.it/2025/07/upgrade-rocky-linux-from-9-6-to-10/
- RADS (Rocky Active Directory Script): https://github.com/fumatchu/RADS
- Samba Team: https://www.samba.org/

---

## Support

For issues with this script:
- Check the log file: `/var/log/rocky-upgrade-*.log`
- Review the troubleshooting section above

For Rocky Linux issues:
- https://forums.rockylinux.org/

For Samba AD DC issues:
- https://wiki.samba.org/
