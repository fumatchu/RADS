# Kea DHCP Post-Upgrade Fix Report

**Server:** dc04.sloto.space
**Date:** 2026-01-24
**Upgrade:** Rocky Linux 9.7 -> 10.1
**Kea Version:** Custom 2.4.x (compiled) -> Official 3.0.1 (repo)

---

## Executive Summary

After upgrading Rocky Linux from 9 to 10, the Kea DHCP services failed to start due to:
1. Custom-compiled Kea binaries linked against el9 libraries (no longer available)
2. Configuration paths incompatible with official Kea 3.0.1 package

**Resolution:** Installed official Kea packages from Rocky 10 repository and migrated configuration to be compatible with the new security restrictions.

---

## Issues Encountered

### Issue 1: Missing Shared Libraries

**Symptom:**
```
error while loading shared libraries: libpq.so.private13-5: cannot open shared object file
error while loading shared libraries: liblog4cplus-2.0.so.3: cannot open shared object file
error while loading shared libraries: libboost_system.so.1.75.0: cannot open shared object file
```

**Cause:** Custom-compiled Kea in `/usr/local/kea/` was linked against Rocky 9 libraries that no longer exist in Rocky 10.

**Solution:** Install official Kea packages:
```bash
dnf install kea kea-hooks -y
```

### Issue 2: Custom Systemd Service Files

**Symptom:** Services still trying to run `/usr/local/kea/sbin/kea-dhcp4`

**Files affected:**
- `/etc/systemd/system/kea-dhcp4.service`
- `/etc/systemd/system/kea-ctrl-agent.service`
- `/etc/systemd/system/kea-dhcp-ddns.service`

**Solution:** Remove custom service files to use official ones from `/usr/lib/systemd/system/`:
```bash
rm /etc/systemd/system/kea-*.service
systemctl daemon-reload
```

### Issue 3: Socket Path Restrictions

**Symptom:**
```
'socket-name' is invalid: invalid path specified: '/var/run', supported path is '/run/kea'
```

**Cause:** Kea 3.0.1 enforces stricter path validation for security (runs as unprivileged 'kea' user).

**Solution:** Update socket paths in configuration:
```bash
sed -i 's|/var/run/kea4-ctrl-socket|/run/kea/kea4-ctrl-socket|g' /etc/kea/*.conf
```

### Issue 4: Hooks Library Path

**Symptom:**
```
invalid path specified: '/usr/local/kea/lib/kea/hooks', supported path is '/usr/lib64/kea/hooks'
```

**Solution:** Update hooks library paths:
```bash
sed -i 's|/usr/local/kea/lib/kea/hooks|/usr/lib64/kea/hooks|g' /etc/kea/kea-dhcp4.conf
```

### Issue 5: Run Script Hook Path

**Symptom:**
```
invalid path specified: '/var/lib/kea', supported path is '/usr/share/kea/scripts'
```

**Cause:** The run_script hook now requires scripts to be in a designated directory.

**Solution:** Move scripts and update config:
```bash
cp /var/lib/kea/dhcp-dyndns.sh /usr/share/kea/scripts/
sed -i 's|/var/lib/kea/dhcp-dyndns.sh|/usr/share/kea/scripts/dhcp-dyndns.sh|g' /etc/kea/kea-dhcp4.conf
```

### Issue 6: Log Path Restrictions

**Symptom:**
```
invalid path in 'output': invalid path specified: '/var/log', supported path is '/var/log/kea'
```

**Solution:** Update log paths:
```bash
sed -i 's|"/var/log/kea-ctrl-agent.log"|"/var/log/kea/kea-ctrl-agent.log"|g' /etc/kea/kea-ctrl-agent.conf
```

### Issue 7: Config File Permissions

**Symptom:**
```
Unable to open file /etc/kea/kea-ctrl-agent.conf
```

**Cause:** Service runs as 'kea' user but config files were owned by root:root.

**Solution:** Fix permissions:
```bash
chown -R root:kea /etc/kea
chmod 750 /etc/kea
chmod 640 /etc/kea/*.conf
```

---

## Changes Made

### Files Removed
| File | Reason |
|------|--------|
| `/etc/systemd/system/kea-dhcp4.service` | Custom service, replaced by official |
| `/etc/systemd/system/kea-ctrl-agent.service` | Custom service, replaced by official |
| `/etc/systemd/system/kea-dhcp-ddns.service` | Custom service, replaced by official |

### Files Modified
| File | Changes |
|------|---------|
| `/etc/kea/kea-dhcp4.conf` | Socket path, hooks paths, script paths |
| `/etc/kea/kea-ctrl-agent.conf` | Socket path, log path |

### Files Copied
| Source | Destination |
|--------|-------------|
| `/var/lib/kea/dhcp-dyndns.sh` | `/usr/share/kea/scripts/dhcp-dyndns.sh` |

### Configuration Backup
Location: `/root/kea-config-backup-20260124-*`

---

## Path Changes Summary

| Component | Old Path (Rocky 9 Custom) | New Path (Rocky 10 Official) |
|-----------|---------------------------|------------------------------|
| Binaries | `/usr/local/kea/sbin/` | `/usr/sbin/` |
| Hooks | `/usr/local/kea/lib/kea/hooks/` | `/usr/lib64/kea/hooks/` |
| Sockets | `/var/run/` | `/run/kea/` |
| Scripts | `/var/lib/kea/` | `/usr/share/kea/scripts/` |
| Logs | `/var/log/` | `/var/log/kea/` |
| Config | `/etc/kea/` | `/etc/kea/` (unchanged) |

---

## Service Configuration Changes

### Old (Custom) Service
```ini
[Service]
ExecStart=/usr/local/kea/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
Restart=on-failure
# Runs as: root
```

### New (Official) Service
```ini
[Service]
Type=notify
User=kea
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
Environment="KEA_PIDFILE_DIR=/run/kea"
Environment="KEA_LOCKFILE_DIR=/run/kea"
ExecStart=/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
# Runs as: kea (unprivileged)
```

**Benefits of official service:**
- Runs as unprivileged 'kea' user (security)
- Proper systemd integration (Type=notify)
- Automatic directory management (RuntimeDirectory, LogsDirectory, etc.)
- Minimal capabilities (only CAP_NET_BIND_SERVICE and CAP_NET_RAW)

---

## Final Status

### Services
| Service | Status | Notes |
|---------|--------|-------|
| kea-dhcp4 | Active | Dispatching packets, HOT-STANDBY mode |
| kea-ctrl-agent | Active | API on port 8112 |
| kea-dhcp-ddns | Active | Listening on port 53001 |

### HA Failover
- Partner: fw (10.10.0.253:8111)
- State: HOT-STANDBY
- Sync: Successful (51 leases synchronized)
- Unsent updates: 0

### Verification Commands
```bash
# Service status
systemctl status kea-dhcp4 kea-ctrl-agent kea-dhcp-ddns

# HA status
curl -s http://localhost:8112/ -H "Content-Type: application/json" \
  -d '{"command": "ha-heartbeat", "service": ["dhcp4"]}'

# Lease statistics
curl -s http://localhost:8112/ -H "Content-Type: application/json" \
  -d '{"command": "stat-lease4-get", "service": ["dhcp4"]}'

# Check logs
journalctl -u kea-dhcp4 -f
```

---

## Automation Script

A script has been created to automate this process for future upgrades:

**Location:** `/root/fix-kea-post-upgrade.sh`

**Usage:**
```bash
# After installing official Kea packages:
dnf install kea kea-hooks -y

# Run the fix script:
./fix-kea-post-upgrade.sh
```

---

## Recommendations

1. **For future upgrades:** Use official Kea packages instead of custom compilation when possible

2. **If custom compilation is needed:** Build for Rocky 10 using:
   ```bash
   # Install build dependencies
   dnf install gcc-c++ boost-devel log4cplus-devel openssl-devel \
       mariadb-devel postgresql-devel

   # Download and compile Kea
   # Ensure paths match official package structure
   ```

3. **Configuration management:** Store Kea configs in version control to track changes

4. **Monitoring:** Set up monitoring for Kea HA state transitions

---

## Related Files

| File | Purpose |
|------|---------|
| `/root/fix-kea-post-upgrade.sh` | Automation script for Kea fixes |
| `/root/rocky9-to-10-upgrade.sh` | Main Rocky 9->10 upgrade script |
| `/root/ROCKY-10-UPGRADE-README.md` | Complete upgrade documentation |
| `/root/fix-network-post-upgrade.sh` | Network/VLAN fix script |
