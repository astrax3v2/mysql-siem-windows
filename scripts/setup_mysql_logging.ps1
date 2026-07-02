<#
.SYNOPSIS
    Enables and configures MySQL Server logging on Windows for SIEM forwarding.

.DESCRIPTION
    Part of the mysql-siem-windows toolkit (astrax3v2/mysql-siem-windows).
    This script:
      1. Locates the MySQL installation and my.ini configuration file
      2. Backs up the existing configuration
      3. Enables and configures: error log, general query log, slow query log,
         and (if available) the audit_log plugin
      4. Redirects logs to a dedicated, Filebeat-friendly directory
      5. Restarts the MySQL service and confirms logs are being written

.PARAMETER MySqlServiceName
    Name of the Windows service for MySQL. Default: MySQL80

.PARAMETER MySqlRootUser
    MySQL account used to apply runtime/persistent settings. Default: root

.PARAMETER MySqlRootPassword
    Password for MySqlRootUser. If omitted, you will be prompted securely.

.PARAMETER LogDirectory
    Target directory for all MySQL log files. Default: C:\MySQLLogs

.PARAMETER SlowQueryThresholdSeconds
    Queries slower than this many seconds are captured in the slow query log. Default: 2

.PARAMETER EnableAuditLog
    Attempt to enable the audit_log plugin (MySQL Enterprise / Percona Server only).
    Community Edition does not ship this plugin; the script will detect and skip gracefully.

.EXAMPLE
    .\setup_mysql_logging.ps1 -MySqlServiceName "MySQL80" -EnableAuditLog

.NOTES
    Run this script from an elevated (Administrator) PowerShell session.
    Author: CSOC & SIEM Engineering, Vairav Technology
#>

[CmdletBinding()]
param(
    [string]$MySqlServiceName = "MySQL80",
    [string]$MySqlRootUser = "root",
    [SecureString]$MySqlRootPassword,
    [string]$LogDirectory = "C:\MySQLLogs",
    [int]$SlowQueryThresholdSeconds = 2,
    [switch]$EnableAuditLog
)

$ErrorActionPreference = "Stop"
$ScriptStart = Get-Date
$TranscriptPath = Join-Path $env:TEMP "setup_mysql_logging_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $TranscriptPath -Append | Out-Null

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    [OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "    [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "    [FAIL] $Message" -ForegroundColor Red
}

function Assert-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail "This script must be run as Administrator. Re-launch PowerShell elevated and try again."
        Stop-Transcript | Out-Null
        exit 1
    }
}

function Get-MySqlRootPasswordPlain {
    if ($MySqlRootPassword) {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MySqlRootPassword)
        )
    }
    $secure = Read-Host -Prompt "Enter MySQL password for user '$MySqlRootUser'" -AsSecureString
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    )
}

function Find-MySqlInstallation {
    Write-Step "Locating MySQL installation"

    $candidateRoots = @(
        "C:\Program Files\MySQL",
        "C:\Program Files (x86)\MySQL",
        "C:\ProgramData\MySQL"
    )

    $mysqldExe = $null
    foreach ($root in $candidateRoots) {
        if (Test-Path $root) {
            $found = Get-ChildItem -Path $root -Recurse -Filter "mysqld.exe" -ErrorAction SilentlyContinue |
                     Select-Object -First 1
            if ($found) { $mysqldExe = $found.FullName; break }
        }
    }

    if (-not $mysqldExe) {
        # Fall back to the running service's binary path
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$MySqlServiceName'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.PathName) {
            $mysqldExe = ($svc.PathName -replace '"', '').Split(' ')[0]
        }
    }

    if (-not $mysqldExe -or -not (Test-Path $mysqldExe)) {
        Write-Fail "Could not locate mysqld.exe. Verify MySQL is installed and pass -MySqlServiceName explicitly."
        Stop-Transcript | Out-Null
        exit 1
    }

    $installDir = Split-Path (Split-Path $mysqldExe -Parent) -Parent
    $iniCandidates = @(
        (Join-Path $installDir "my.ini"),
        "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini",
        "C:\ProgramData\MySQL\MySQL Server 5.7\my.ini"
    )
    $iniPath = $iniCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $iniPath) {
        Write-Fail "Could not locate my.ini. Locate it manually and re-run with the correct MySqlServiceName."
        Stop-Transcript | Out-Null
        exit 1
    }

    Write-Ok "mysqld.exe found at: $mysqldExe"
    Write-Ok "my.ini found at:     $iniPath"

    return [PSCustomObject]@{
        MysqldPath = $mysqldExe
        IniPath    = $iniPath
        InstallDir = $installDir
    }
}

function Backup-Configuration {
    param([string]$IniPath)

    Write-Step "Backing up existing my.ini"
    $backupPath = "$IniPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -Path $IniPath -Destination $backupPath -Force
    Write-Ok "Backup written to: $backupPath"
    return $backupPath
}

function New-LogDirectorySecure {
    param([string]$Path)

    Write-Step "Preparing log directory: $Path"
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        Write-Ok "Created directory."
    } else {
        Write-Ok "Directory already exists."
    }

    # Grant the MySQL service account and local Administrators full control;
    # remove inherited broad permissions so only intended principals can read audit-relevant logs.
    try {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop inherited rules

        $rules = @(
            (New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")),
            (New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")),
            (New-Object System.Security.AccessControl.FileSystemAccessRule("NETWORK SERVICE", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"))
        )
        foreach ($rule in $rules) { $acl.AddAccessRule($rule) }
        Set-Acl -Path $Path -AclObject $acl
        Write-Ok "Applied restrictive ACLs to log directory."
    } catch {
        Write-WarnMsg "Could not set custom ACLs (non-fatal): $($_.Exception.Message)"
    }
}

function Set-IniValue {
    param(
        [string]$IniPath,
        [string]$Section = "mysqld",
        [string]$Key,
        [string]$Value
    )

    $content = Get-Content -Path $IniPath
    $sectionPattern = "^\[$Section\]"
    $keyPattern = "^\s*$Key\s*="

    $sectionIndex = ($content | Select-String -Pattern $sectionPattern).LineNumber
    if (-not $sectionIndex) {
        # Section doesn't exist — append it
        $content += ""
        $content += "[$Section]"
        $content += "$Key=$Value"
        Set-Content -Path $IniPath -Value $content
        return
    }

    $sectionIndex = $sectionIndex[0]  # 1-based line number of [section] header
    $nextSectionIndex = $null
    for ($i = $sectionIndex; $i -lt $content.Count; $i++) {
        if ($i -gt $sectionIndex - 1 -and $content[$i] -match '^\[.+\]' -and $content[$i] -notmatch $sectionPattern) {
            $nextSectionIndex = $i
            break
        }
    }
    if (-not $nextSectionIndex) { $nextSectionIndex = $content.Count }

    $existingKeyLine = $null
    for ($i = $sectionIndex; $i -lt $nextSectionIndex; $i++) {
        if ($content[$i] -match $keyPattern) { $existingKeyLine = $i; break }
    }

    if ($existingKeyLine) {
        $content[$existingKeyLine] = "$Key=$Value"
    } else {
        $insertAt = $sectionIndex  # right after the [section] header line (0-indexed array, header at sectionIndex-1)
        $content = $content[0..($sectionIndex - 1)] + "$Key=$Value" + $content[$sectionIndex..($content.Count - 1)]
    }

    Set-Content -Path $IniPath -Value $content
}

function Set-LoggingDirectives {
    param(
        [string]$IniPath,
        [string]$LogDirectory,
        [int]$SlowQueryThresholdSeconds
    )

    Write-Step "Writing logging directives to my.ini"

    $errorLog   = Join-Path $LogDirectory "mysql-error.log"
    $generalLog = Join-Path $LogDirectory "mysql-general.log"
    $slowLog    = Join-Path $LogDirectory "mysql-slow.log"

    $directives = @{
        "log-error"                 = $errorLog
        "general_log"               = "1"
        "general_log_file"          = $generalLog
        "slow_query_log"            = "1"
        "slow_query_log_file"       = $slowLog
        "long_query_time"           = "$SlowQueryThresholdSeconds"
        "log_output"                = "FILE"
        "log_timestamps"            = "SYSTEM"
        # Connection/auth-relevant events for SIEM (who connected, from where, auth failures)
        "log_error_verbosity"       = "3"
    }

    foreach ($key in $directives.Keys) {
        Set-IniValue -IniPath $IniPath -Section "mysqld" -Key $key -Value $directives[$key]
        Write-Ok "Set $key = $($directives[$key])"
    }

    return [PSCustomObject]@{
        ErrorLog   = $errorLog
        GeneralLog = $generalLog
        SlowLog    = $slowLog
    }
}

function Test-AuditLogPluginAvailable {
    param([string]$InstallDir)

    $pluginDll = Join-Path $InstallDir "lib\plugin\audit_log.dll"
    return (Test-Path $pluginDll)
}

function Enable-AuditLogPlugin {
    param(
        [string]$IniPath,
        [string]$InstallDir,
        [string]$LogDirectory
    )

    Write-Step "Checking for audit_log plugin (Enterprise / Percona Server only)"

    if (-not (Test-AuditLogPluginAvailable -InstallDir $InstallDir)) {
        Write-WarnMsg "audit_log.dll not found. This is expected on MySQL Community Edition."
        Write-WarnMsg "Skipping audit plugin setup — general/slow/error logs above will remain the SIEM source."
        return $false
    }

    $auditLogFile = Join-Path $LogDirectory "mysql-audit.log"
    Set-IniValue -IniPath $IniPath -Section "mysqld" -Key "plugin-load-add" -Value "audit_log.dll"
    Set-IniValue -IniPath $IniPath -Section "mysqld" -Key "audit_log_format" -Value "JSON"
    Set-IniValue -IniPath $IniPath -Section "mysqld" -Key "audit_log_file" -Value $auditLogFile
    Set-IniValue -IniPath $IniPath -Section "mysqld" -Key "audit_log_policy" -Value "ALL"
    Set-IniValue -IniPath $IniPath -Section "mysqld" -Key "audit_log_rotate_on_size" -Value "104857600"

    Write-Ok "audit_log plugin configured (JSON format) -> $auditLogFile"
    return $true
}

function Restart-MySqlService {
    param([string]$ServiceName)

    Write-Step "Restarting MySQL service: $ServiceName"
    try {
        Restart-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq "Running") {
            Write-Ok "Service is running."
        } else {
            Write-Fail "Service did not return to Running state. Current status: $($svc.Status)"
            Write-Fail "Check Windows Event Viewer > Application log for mysqld errors, and validate my.ini syntax."
            exit 1
        }
    } catch {
        Write-Fail "Failed to restart service: $($_.Exception.Message)"
        Write-Fail "If MySQL fails to start, restore the backup my.ini created earlier and investigate."
        exit 1
    }
}

function Confirm-LogsWriting {
    param([PSCustomObject]$LogPaths)

    Write-Step "Confirming log files are being created and written to"
    Start-Sleep -Seconds 3

    foreach ($prop in @("ErrorLog", "GeneralLog", "SlowLog")) {
        $path = $LogPaths.$prop
        if (Test-Path $path) {
            $info = Get-Item $path
            Write-Ok "$prop present ($([math]::Round($info.Length/1KB,1)) KB) — last write: $($info.LastWriteTime)"
        } else {
            Write-WarnMsg "$prop not yet found at $path — it may appear after the first query/connection."
        }
    }
}

# ---------------- Main ----------------

Assert-Administrator

Write-Host "===========================================================" -ForegroundColor DarkCyan
Write-Host " MySQL SIEM Log Collector (Windows) — Logging Setup" -ForegroundColor DarkCyan
Write-Host "===========================================================" -ForegroundColor DarkCyan

$mysqlInfo = Find-MySqlInstallation
Backup-Configuration -IniPath $mysqlInfo.IniPath | Out-Null
New-LogDirectorySecure -Path $LogDirectory

$logPaths = Set-LoggingDirectives -IniPath $mysqlInfo.IniPath -LogDirectory $LogDirectory -SlowQueryThresholdSeconds $SlowQueryThresholdSeconds

if ($EnableAuditLog) {
    Enable-AuditLogPlugin -IniPath $mysqlInfo.IniPath -InstallDir $mysqlInfo.InstallDir -LogDirectory $LogDirectory | Out-Null
}

Restart-MySqlService -ServiceName $MySqlServiceName
Confirm-LogsWriting -LogPaths $logPaths

Write-Host "`n===========================================================" -ForegroundColor DarkCyan
Write-Host " Setup complete. Next step: install and configure Filebeat," -ForegroundColor DarkCyan
Write-Host " then run validate_logs.ps1 to confirm end-to-end readiness." -ForegroundColor DarkCyan
Write-Host " Log directory: $LogDirectory" -ForegroundColor DarkCyan
Write-Host " Transcript:    $TranscriptPath" -ForegroundColor DarkCyan
Write-Host "===========================================================" -ForegroundColor DarkCyan

Stop-Transcript | Out-Null
