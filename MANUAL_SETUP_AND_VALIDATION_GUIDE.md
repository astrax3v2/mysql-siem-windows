# Manual Setup & Validation Guide — MySQL Logging for SIEM (Windows)

**Use this guide when a client's change-control or security policy does not permit running automated PowerShell scripts on production database servers.** It performs the exact same actions as `setup_mysql_logging.ps1` and `validate_logs.ps1`, but as discrete, auditable manual steps using the MySQL client, Windows GUI tools, and `cmd.exe`/`icacls` instead of PowerShell automation.

This document is suitable for inclusion as `docs/SOP.md` in the `mysql-siem-windows` repository, or for attaching directly to a client change request.

---

## Part A — Manual Logging Setup

### A.1 Locate the MySQL Installation

1. Open **Services** (`services.msc`) and find the MySQL service (commonly `MySQL80`, `MySQL57`, or similar). Right-click → **Properties** → note the **Path to executable**. This tells you the install directory, e.g.:
   ```
   C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe
   ```
2. The configuration file (`my.ini`) is typically at one of:
   ```
   C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
   C:\Program Files\MySQL\MySQL Server 8.0\my.ini
   ```
   If unsure, run in an elevated Command Prompt:
   ```
   "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" --verbose --help | findstr /I "Default options"
   ```
   This prints the exact `my.ini` path MySQL is reading on this host.

### A.2 Back Up the Existing Configuration

1. Open File Explorer, navigate to the `my.ini` location found in A.1.
2. Copy `my.ini` and rename the copy to:
   ```
   my.ini.bak_YYYYMMDD
   ```
3. Store this backup outside the MySQL directory as well (e.g., a change-ticket evidence folder), so it survives if the directory is later touched.

### A.3 Create the Log Directory

1. In File Explorer, create a new folder: `C:\MySQLLogs`.
2. Right-click the folder → **Properties** → **Security** tab → **Advanced**.
3. Click **Disable inheritance** → **Convert inherited permissions into explicit permissions**.
4. Remove any broad group (e.g., `Everyone`, `Authenticated Users`) that doesn't need access.
5. Add/confirm the following with **Full control** (or **Modify** for the service account):
   - `SYSTEM`
   - `Administrators`
   - The account the MySQL service runs as (check on the Services console → MySQL service → **Log On** tab; default is often `Network Service` or `Local System`)
   - The account Filebeat runs as, once installed (Section A.6)
6. Click **Apply** → **OK**.

   *Command-line equivalent (cmd.exe, not PowerShell):*
   ```
   mkdir C:\MySQLLogs
   icacls C:\MySQLLogs /inheritance:r
   icacls C:\MySQLLogs /grant "SYSTEM:(OI)(CI)F"
   icacls C:\MySQLLogs /grant "Administrators:(OI)(CI)F"
   icacls C:\MySQLLogs /grant "NETWORK SERVICE:(OI)(CI)M"
   ```

### A.4 Edit `my.ini` — Enable Error, General, and Slow Query Logs

1. Open `my.ini` in Notepad **as Administrator**.
2. Locate the `[mysqld]` section. Add or update the following lines (if a key already exists elsewhere in the file, edit it in place rather than duplicating it):
   ```ini
   [mysqld]
   log-error=C:/MySQLLogs/mysql-error.log
   general_log=1
   general_log_file=C:/MySQLLogs/mysql-general.log
   slow_query_log=1
   slow_query_log_file=C:/MySQLLogs/mysql-slow.log
   long_query_time=2
   log_output=FILE
   log_timestamps=SYSTEM
   log_error_verbosity=3
   ```
   Notes:
   - Use forward slashes or escaped backslashes in `my.ini` paths — `C:/MySQLLogs/...` is safest.
   - `long_query_time=2` logs queries slower than 2 seconds; adjust per the client's baseline.
   - `general_log=1` logs **every** statement — confirm with the client that the performance/disk overhead is acceptable before enabling in production (see Notes at the end of this document).
3. Save the file.

### A.5 (Optional) Enable the Audit Log Plugin — MySQL Enterprise / Percona Server Only

Community Edition does not ship this plugin — skip this step if the client runs MySQL Community Server (check via `SELECT VERSION();` — Community builds report `-community` or `-standard` in some editions; if unsure, check with `SHOW PLUGINS;` for `audit_log` availability first).

1. Open a Command Prompt and connect to MySQL:
   ```
   "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p
   ```
2. Check whether the plugin library exists:
   ```sql
   SHOW GLOBAL VARIABLES LIKE 'plugin_dir';
   ```
   Then verify `audit_log.dll` exists in that directory (check in File Explorer).
3. If present, install and configure it:
   ```sql
   INSTALL PLUGIN audit_log SONAME 'audit_log.dll';
   SET GLOBAL audit_log_format = 'JSON';
   SET GLOBAL audit_log_policy = 'ALL';
   ```
4. To persist the plugin across restarts, also add to `my.ini` under `[mysqld]`:
   ```ini
   plugin-load-add=audit_log.dll
   audit_log_format=JSON
   audit_log_file=C:/MySQLLogs/mysql-audit.log
   audit_log_policy=ALL
   audit_log_rotate_on_size=104857600
   ```

### A.6 Restart the MySQL Service

1. Open **Services** (`services.msc`).
2. Right-click the MySQL service → **Restart**.
   *Command-line equivalent (cmd.exe):*
   ```
   net stop MySQL80
   net start MySQL80
   ```
3. Confirm the service returns to **Running** status. If it fails to start:
   - Reopen `my.ini` and check for typos (a single malformed line will prevent startup).
   - Check **Event Viewer** → **Windows Logs** → **Application**, filter by source `MySQL`, for the specific startup error.
   - If needed, restore the backup from A.2 and restart again to return to a known-good state.

### A.7 Confirm Logs Are Being Written

1. In File Explorer, open `C:\MySQLLogs`.
2. Confirm `mysql-error.log` exists and has a recent **Date modified**.
3. Run a test query against the database (via MySQL Workbench, `mysql.exe`, or any application), then refresh the folder — `mysql-general.log` should grow in size and its timestamp should update.
4. `mysql-slow.log` will only populate once a query exceeds `long_query_time` — this can remain empty initially; that is expected.

### A.8 Install and Point Filebeat at the Logs

1. Install Filebeat per the vendor MSI/zip package (this itself may need change-control approval separately — confirm with the client).
2. Edit `C:\Program Files\Filebeat\filebeat.yml` to add an input for the log directory, e.g.:
   ```yaml
   filebeat.inputs:
     - type: filestream
       id: mysql-logs
       enabled: true
       paths:
         - C:\MySQLLogs\*.log
   ```
3. Start the Filebeat service via **Services** console, or:
   ```
   net start filebeat
   ```
4. Confirm with the SIEM/CSOC team that events are arriving (see Part B, Section B.5).

---

## Part B — Manual Validation

Perform these checks after setup, and periodically thereafter (weekly is a reasonable cadence for most environments).

### B.1 MySQL Service Status

1. Open **Services** (`services.msc`).
2. Locate the MySQL service. Confirm **Status = Running** and **Startup Type = Automatic**.
3. **Pass criteria:** Running, Automatic.

### B.2 Log Files Present and Current

1. Open File Explorer to `C:\MySQLLogs`.
2. For each expected file (`mysql-error.log`, `mysql-general.log`, `mysql-slow.log`, and `mysql-audit.log` if the plugin was enabled), check:
   - File exists
   - **Date modified** is recent (within the last 30 minutes for an active database, or since the last known activity)
   - File size is greater than 0 KB (a 0 KB error log after restart is normal briefly; general/slow logs should grow once traffic occurs)
3. **Pass criteria:** Error log always present and non-empty. General/slow logs present and updating in line with actual database activity.

### B.3 Permissions Check

1. Right-click `C:\MySQLLogs` → **Properties** → **Security** tab.
2. Confirm `SYSTEM`, `Administrators`, and the MySQL/Filebeat service accounts are listed with at least Read (Filebeat) / Full Control (SYSTEM, Administrators) access.
3. **Pass criteria:** No unintended broad access (e.g., `Everyone`); required service accounts present.

### B.4 Filebeat Service and Configuration

1. Open **Services** (`services.msc`) and confirm the Filebeat service **Status = Running**.
2. Open `C:\Program Files\Filebeat\filebeat.yml` in Notepad (read-only is fine) and confirm the `C:\MySQLLogs\*.log` path (or equivalent) is present under `filebeat.inputs`.
3. **Pass criteria:** Service running; config references the correct log path.

### B.5 Confirm Events Are Reaching the SIEM

1. Generate a test event: run a benign query against the MySQL instance (e.g., `SELECT 1;` via `mysql.exe` or Workbench), or trigger a deliberate failed login to generate an error-log entry.
2. Note the exact timestamp and hostname.
3. In the SIEM console (Trident SIEM or other), search for the hostname or a distinctive string from the test query within the last 5–10 minutes.
4. **Pass criteria:** The test event is visible in the SIEM within the agreed ingestion SLA (typically under 5 minutes).

### B.6 Recent Errors Check

1. Open **Event Viewer** → **Windows Logs** → **Application**.
2. Filter current log by source, entering `MySQL` and separately `filebeat` in the filter dialog.
3. Review any entries from the last 24 hours at **Error** or **Warning** level.
4. **Pass criteria:** No unresolved errors related to MySQL startup, log writing, or Filebeat harvesting.

### B.7 Sign-Off Checklist

| # | Check | Pass / Fail | Notes |
|---|---|---|---|
| 1 | MySQL service Running / Automatic | | |
| 2 | Error log present and current | | |
| 3 | General log present and updating | | |
| 4 | Slow query log present (may be empty) | | |
| 5 | Audit log present (if plugin enabled) | | |
| 6 | Log directory permissions correct | | |
| 7 | Filebeat service Running | | |
| 8 | Filebeat config references correct log path | | |
| 9 | Test event confirmed visible in SIEM | | |
| 10 | No unresolved errors in Event Viewer (24h) | | |

Record the completed checklist in the client's change-ticket or compliance evidence folder as proof of validation.

---

## Notes for Change-Restricted Environments

- Every step above uses only Windows built-in tools (`services.msc`, File Explorer, Event Viewer, `cmd.exe`, `icacls`, `net start`/`net stop`) or the MySQL client itself — no PowerShell script execution is required at any point.
- If **any** scripting is restricted (including `cmd.exe` batch commands), the `icacls` and `net`/`sc` command-line steps can be substituted with the equivalent GUI actions described inline (Services console for service control, folder Properties → Security for permissions).
- Because `general_log=1` logs every statement, confirm the performance and disk-growth impact with the client before enabling it in production — consider limiting to the slow query log and error log only if the client's risk appetite is lower.
- If MySQL fails to restart after an `my.ini` edit, always restore from the `A.2` backup rather than trying to debug live on a production system under a change window.
- Re-run Part B validation after any subsequent change to MySQL, `my.ini`, or the Filebeat configuration.
