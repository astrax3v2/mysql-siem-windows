<#
.SYNOPSIS
    Validates that MySQL logs on Windows are healthy and ready for SIEM monitoring.

.DESCRIPTION
    Part of the mysql-siem-windows toolkit (astrax3v2/mysql-siem-windows).
    Companion to setup_mysql_logging.ps1. This script checks:
      1. MySQL service is running
      2. Each expected log file exists and is being actively written to
      3. Log files are not stale (no writes beyond an allowed staleness window)
      4. Log file permissions allow the Filebeat service account to read them
      5. Filebeat service is installed, running, and its config references the MySQL log paths
      6. (Optional) Filebeat is actually harvesting the files, via its registry/data status

    Produces a pass/fail summary and returns a non-zero exit code on any failure,
    so it can be wired into a scheduled task or monitoring check.

.PARAMETER LogDirectory
    Directory containing MySQL log files. Default: C:\MySQLLogs

.PARAMETER MySqlServiceName
    Windows service name for MySQL. Default: MySQL80

.PARAMETER FilebeatServiceName
    Windows service name for Filebeat. Default: filebeat

.PARAMETER StalenessThresholdMinutes
    A log file not modified within this many minutes is flagged as stale.
    Default: 30 (tune upward for low-traffic databases).

.PARAMETER FilebeatConfigPath
    Path to filebeat.yml, used to confirm MySQL log paths are actually configured for harvesting.
    Default: C:\Program Files\Filebeat\filebeat.yml

.EXAMPLE
    .\validate_logs.ps1 -LogDirectory "C:\MySQLLogs" -StalenessThresholdMinutes 15

.NOTES
    Run as Administrator for full permission and service checks.
    Exit code 0 = all checks passed. Exit code 1 = one or more checks failed.
    Author: CSOC & SIEM Engineering, Vairav Technology
#>

[CmdletBinding()]
param(
    [string]$LogDirectory = "C:\MySQLLogs",
    [string]$MySqlServiceName = "MySQL80",
    [string]$FilebeatServiceName = "filebeat",
    [int]$StalenessThresholdMinutes = 30,
    [string]$FilebeatConfigPath = "C:\Program Files\Filebeat\filebeat.yml"
)

$ErrorActionPreference = "Continue"
$script:FailureCount = 0
$script:Results = @()

function Add-Result {
    param(
        [string]$Check,
        [ValidateSet("PASS","WARN","FAIL")][string]$Status,
        [string]$Detail
    )
    $script:Results += [PSCustomObject]@{
        Check  = $Check
        Status = $Status
        Detail = $Detail
    }
    if ($Status -eq "FAIL") { $script:FailureCount++ }

    $color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
    }
    Write-Host ("[{0}] {1} — {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n--- $Title ---" -ForegroundColor Cyan
}

# ---------------- Checks ----------------

function Test-MySqlServiceRunning {
    Write-Section "MySQL Service"
    try {
        $svc = Get-Service -Name $MySqlServiceName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Add-Result -Check "MySQL service status" -Status "PASS" -Detail "$MySqlServiceName is Running"
        } else {
            Add-Result -Check "MySQL service status" -Status "FAIL" -Detail "$MySqlServiceName is $($svc.Status)"
        }
    } catch {
        Add-Result -Check "MySQL service status" -Status "FAIL" -Detail "Service '$MySqlServiceName' not found: $($_.Exception.Message)"
    }
}

function Test-LogFilesExistAndFresh {
    Write-Section "MySQL Log Files"

    if (-not (Test-Path $LogDirectory)) {
        Add-Result -Check "Log directory" -Status "FAIL" -Detail "$LogDirectory does not exist. Run setup_mysql_logging.ps1 first."
        return
    }
    Add-Result -Check "Log directory" -Status "PASS" -Detail "$LogDirectory exists"

    $expectedLogs = @{
        "Error log"    = "mysql-error.log"
        "General log"  = "mysql-general.log"
        "Slow query log" = "mysql-slow.log"
        "Audit log (optional)" = "mysql-audit.log"
    }

    foreach ($label in $expectedLogs.Keys) {
        $path = Join-Path $LogDirectory $expectedLogs[$label]
        $isOptional = $label -like "*optional*"

        if (-not (Test-Path $path)) {
            if ($isOptional) {
                Add-Result -Check $label -Status "WARN" -Detail "$path not present (only expected if audit_log plugin is enabled)"
            } else {
                Add-Result -Check $label -Status "FAIL" -Detail "$path not found"
            }
            continue
        }

        $file = Get-Item $path
        $ageMinutes = [math]::Round(((Get-Date) - $file.LastWriteTime).TotalMinutes, 1)

        if ($file.Length -eq 0) {
            Add-Result -Check $label -Status "WARN" -Detail "$path exists but is empty (0 bytes) — may be normal if no matching events yet"
            continue
        }

        if ($ageMinutes -gt $StalenessThresholdMinutes) {
            Add-Result -Check $label -Status "WARN" -Detail "$path last written $ageMinutes min ago (threshold: $StalenessThresholdMinutes min) — verify database has active traffic"
        } else {
            Add-Result -Check $label -Status "PASS" -Detail "$path healthy, $([math]::Round($file.Length/1KB,1)) KB, last write $ageMinutes min ago"
        }
    }
}

function Test-LogFilePermissions {
    Write-Section "Log File Permissions"

    if (-not (Test-Path $LogDirectory)) { return }

    try {
        $acl = Get-Acl $LogDirectory
        $hasSystemFullControl = $acl.Access | Where-Object {
            $_.IdentityReference -match "SYSTEM" -and $_.FileSystemRights -match "FullControl"
        }
        $hasNetworkServiceAccess = $acl.Access | Where-Object {
            $_.IdentityReference -match "NETWORK SERVICE"
        }

        if ($hasSystemFullControl) {
            Add-Result -Check "SYSTEM account access" -Status "PASS" -Detail "SYSTEM has FullControl on $LogDirectory"
        } else {
            Add-Result -Check "SYSTEM account access" -Status "WARN" -Detail "SYSTEM FullControl not detected — verify service account can read logs"
        }

        if ($hasNetworkServiceAccess) {
            Add-Result -Check "Service account read access" -Status "PASS" -Detail "NETWORK SERVICE has explicit access on $LogDirectory"
        } else {
            Add-Result -Check "Service account read access" -Status "WARN" -Detail "No explicit NETWORK SERVICE rule — confirm the account Filebeat runs as can read this path"
        }
    } catch {
        Add-Result -Check "Permission check" -Status "WARN" -Detail "Could not evaluate ACL: $($_.Exception.Message)"
    }
}

function Test-FilebeatInstalled {
    Write-Section "Filebeat Forwarder"

    try {
        $svc = Get-Service -Name $FilebeatServiceName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Add-Result -Check "Filebeat service status" -Status "PASS" -Detail "$FilebeatServiceName is Running"
        } else {
            Add-Result -Check "Filebeat service status" -Status "FAIL" -Detail "$FilebeatServiceName is $($svc.Status) — logs will not reach the SIEM"
        }
    } catch {
        Add-Result -Check "Filebeat service status" -Status "FAIL" -Detail "Service '$FilebeatServiceName' not found. Install Filebeat before going live."
        return
    }

    if (-not (Test-Path $FilebeatConfigPath)) {
        Add-Result -Check "Filebeat config present" -Status "FAIL" -Detail "$FilebeatConfigPath not found"
        return
    }
    Add-Result -Check "Filebeat config present" -Status "PASS" -Detail "$FilebeatConfigPath found"

    $configContent = Get-Content -Path $FilebeatConfigPath -Raw
    $normalizedLogDir = $LogDirectory -replace '\\', '\\\\'

    if ($configContent -match [regex]::Escape($LogDirectory) -or $configContent -match [regex]::Escape($normalizedLogDir)) {
        Add-Result -Check "Filebeat harvesting MySQL logs" -Status "PASS" -Detail "filebeat.yml references $LogDirectory"
    } else {
        Add-Result -Check "Filebeat harvesting MySQL logs" -Status "FAIL" -Detail "filebeat.yml does not appear to reference $LogDirectory — add a filestream/log input for this path"
    }
}

function Test-FilebeatRegistryProgress {
    Write-Section "Filebeat Harvesting Progress"

    $registryPath = "C:\ProgramData\filebeat\registry\filebeat\log.json"
    if (-not (Test-Path $registryPath)) {
        Add-Result -Check "Filebeat registry state" -Status "WARN" -Detail "Registry not found at default path — cannot confirm active harvesting; check a custom path.data location if configured"
        return
    }

    try {
        $registryAge = [math]::Round(((Get-Date) - (Get-Item $registryPath).LastWriteTime).TotalMinutes, 1)
        if ($registryAge -le $StalenessThresholdMinutes) {
            Add-Result -Check "Filebeat registry state" -Status "PASS" -Detail "Registry updated $registryAge min ago — Filebeat is actively processing input"
        } else {
            Add-Result -Check "Filebeat registry state" -Status "WARN" -Detail "Registry stale ($registryAge min) — Filebeat may not be actively harvesting"
        }
    } catch {
        Add-Result -Check "Filebeat registry state" -Status "WARN" -Detail "Could not read registry file: $($_.Exception.Message)"
    }
}

function Test-EventViewerErrors {
    Write-Section "Recent MySQL/Filebeat Errors (Event Log)"

    try {
        $recentErrors = Get-WinEvent -FilterHashtable @{
            LogName   = "Application"
            Level     = 2  # Error
            StartTime = (Get-Date).AddHours(-24)
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.ProviderName -match "MySQL|Filebeat"
        }

        if ($recentErrors) {
            Add-Result -Check "Application event log" -Status "WARN" -Detail "$($recentErrors.Count) MySQL/Filebeat error(s) in the last 24h — review Event Viewer > Application"
        } else {
            Add-Result -Check "Application event log" -Status "PASS" -Detail "No MySQL/Filebeat errors in the last 24h"
        }
    } catch {
        Add-Result -Check "Application event log" -Status "WARN" -Detail "Could not query event log: $($_.Exception.Message)"
    }
}

# ---------------- Main ----------------

Write-Host "===========================================================" -ForegroundColor DarkCyan
Write-Host " MySQL SIEM Log Collector (Windows) — Validation" -ForegroundColor DarkCyan
Write-Host " $(Get-Date)" -ForegroundColor DarkCyan
Write-Host "===========================================================" -ForegroundColor DarkCyan

Test-MySqlServiceRunning
Test-LogFilesExistAndFresh
Test-LogFilePermissions
Test-FilebeatInstalled
Test-FilebeatRegistryProgress
Test-EventViewerErrors

Write-Section "Summary"
$passCount = ($script:Results | Where-Object { $_.Status -eq "PASS" }).Count
$warnCount = ($script:Results | Where-Object { $_.Status -eq "WARN" }).Count
$failCount = ($script:Results | Where-Object { $_.Status -eq "FAIL" }).Count

Write-Host "PASS: $passCount   WARN: $warnCount   FAIL: $failCount"

$reportPath = Join-Path $env:TEMP "mysql_log_validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$script:Results | Export-Csv -Path $reportPath -NoTypeInformation
Write-Host "Detailed report saved to: $reportPath"

if ($script:FailureCount -gt 0) {
    Write-Host "`nRESULT: FAIL — one or more critical checks failed. Logs are NOT ready for SIEM monitoring." -ForegroundColor Red
    exit 1
} elseif ($warnCount -gt 0) {
    Write-Host "`nRESULT: PASS WITH WARNINGS — review warnings above before sign-off." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "`nRESULT: PASS — MySQL logging is healthy and ready for SIEM monitoring." -ForegroundColor Green
    exit 0
}
