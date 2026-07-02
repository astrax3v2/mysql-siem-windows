# MySQL SIEM Log Collector (Windows)

Complete toolkit to enable, validate, and forward MySQL Server logs from Windows to a SIEM (Trident SIEM or any Filebeat-compatible platform).

## Overview

MySQL on Windows does not forward logs anywhere by default. This repo provides the scripts and configuration needed to:

- Enable MySQL's error log, general query log, slow query log, and (where available) the `audit_log` plugin
- Write those logs to a dedicated, access-controlled directory
- Ship them to your SIEM using Filebeat
- Validate — before and after go-live — that logging is actually healthy and events are reaching the SIEM

## Architecture

```
MySQL Server (Windows)
   │  error log / general log / slow query log / audit log (optional)
   ▼
C:\MySQLLogs\  (dedicated, ACL-restricted directory)
   │
   ▼
Filebeat  ──►  SIEM ingest (Trident SIEM / Elastic / Splunk / other)
```

## Repository Structure

```
mysql-siem-windows/
├── README.md
├── docs/
│   └── SOP.md                    # Full logging-enablement SOP (see "Enable logging (see SOP)")
├── scripts/
│   ├── setup_mysql_logging.ps1   # Enables and configures MySQL logging
│   └── validate_logs.ps1         # Validates logging health and SIEM-readiness
└── config/
    └── filebeat.yml              # Sample Filebeat config for the MySQL log paths
```

> If `docs/SOP.md` or `config/filebeat.yml` don't exist yet in your checkout, see the **Companion Documents** section below — ask your CSOC/SIEM engineering contact for the current versions.

## Prerequisites

- Windows Server (2016+) with MySQL Server (Community, Enterprise, or Percona Server) installed
- PowerShell 5.1+ run as **Administrator**
- Local admin rights to modify `my.ini` and restart the MySQL service
- Network path from the host to your SIEM's log collector/ingest endpoint
- [Filebeat](https://www.elastic.co/beats/filebeat) downloaded (or already installed) on the host

## Quick Start

1. **Enable logging** — read `docs/SOP.md` for the full rationale and manual steps, or run the automated script below.
2. **Run the setup script** (elevated PowerShell):
   ```powershell
   .\scripts\setup_mysql_logging.ps1 -MySqlServiceName "MySQL80" -LogDirectory "C:\MySQLLogs"
   ```
   Add `-EnableAuditLog` if you're on MySQL Enterprise or Percona Server and want the `audit_log` plugin enabled (Community Edition does not ship this plugin — the script detects and skips it automatically).
3. **Install Filebeat** and point it at `C:\MySQLLogs\*.log` — see `config/filebeat.yml` for a working example, or the [Filebeat MySQL module docs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-mysql.html).
4. **Validate logs**:
   ```powershell
   .\scripts\validate_logs.ps1 -LogDirectory "C:\MySQLLogs" -FilebeatServiceName "filebeat"
   ```
   This confirms the MySQL service is running, log files exist and are current, permissions are correct, and Filebeat is installed, configured, and actively harvesting. It exits with code `0` on pass and `1` on failure, so it can be wired into a scheduled task for ongoing health checks.

## Script Reference

### `setup_mysql_logging.ps1`

| Parameter | Default | Description |
|---|---|---|
| `-MySqlServiceName` | `MySQL80` | Windows service name for MySQL |
| `-MySqlRootUser` | `root` | MySQL account used for setup (reserved for future use) |
| `-MySqlRootPassword` | *(prompted)* | Secure string; prompted if not supplied |
| `-LogDirectory` | `C:\MySQLLogs` | Target directory for all log files |
| `-SlowQueryThresholdSeconds` | `2` | Queries slower than this are logged |
| `-EnableAuditLog` | *(off)* | Attempts to enable the `audit_log` plugin (Enterprise/Percona only) |

What it does: locates your MySQL install and `my.ini`, backs up the existing config, creates `LogDirectory` with restrictive ACLs, writes logging directives, restarts the MySQL service, and confirms each log file is being written.

### `validate_logs.ps1`

| Parameter | Default | Description |
|---|---|---|
| `-LogDirectory` | `C:\MySQLLogs` | Directory containing MySQL log files |
| `-MySqlServiceName` | `MySQL80` | Windows service name for MySQL |
| `-FilebeatServiceName` | `filebeat` | Windows service name for Filebeat |
| `-StalenessThresholdMinutes` | `30` | Flags a log/registry as stale if not updated within this window |
| `-FilebeatConfigPath` | `C:\Program Files\Filebeat\filebeat.yml` | Path used to confirm Filebeat is configured for these logs |

What it checks: MySQL service status, presence/freshness of each log file, directory permissions, Filebeat service status and config, Filebeat's harvesting progress (registry), and recent MySQL/Filebeat errors in the Windows Application event log. Outputs a color-coded summary plus a CSV report to `%TEMP%`.

## Notes

- **General query log has a performance cost.** It logs every statement executed against the server. Enable it only where the SIEM use case justifies the overhead, and prefer the slow query log + audit log (where available) for lower-impact, high-value coverage. Monitor disk I/O after enabling.
- **Community Edition has no `audit_log` plugin.** Rely on error/general/slow logs as your primary SIEM source on Community Edition; the `audit_log` plugin is Enterprise/Percona only.
- **Re-run `validate_logs.ps1` after any change** to MySQL, `my.ini`, or the Filebeat config — a passing run today doesn't guarantee tomorrow's config is still correct.
- Both scripts must be run **elevated** (Administrator) — service restarts and ACL changes will fail silently or with permission errors otherwise.

## Companion Documents

- `docs/SOP.md` — full Standard Operating Procedure for enabling MySQL logging on Windows (referenced in Quick Start step 1)
- `config/filebeat.yml` — sample Filebeat configuration wired to the paths these scripts create

## Support

For help with SIEM-side onboarding (collector endpoints, index/use-case mapping), contact CSOC & SIEM Engineering through your standard support channel.

