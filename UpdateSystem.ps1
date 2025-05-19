# UpdateSystem.ps1
# PowerShell script to manage Windows updates, Defender updates, non-Store app updates, and Microsoft Store updates at logon
# Compatible with Windows 10 (1809+) and Windows 11

# Initialize logging
$logDir = "C:\ProgramData\SystemUpdateScript\Logs"
$logFile = "$logDir\UpdateScript_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $logFile -Append -ErrorAction SilentlyContinue

# Function to write log messages
function Write-Log {
    param ($Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "$timestamp : $Message" | Out-File $logFile -Append
}

Write-Log "Detecting system information..."
$computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Log "PC Model: $($computerInfo.Manufacturer) $($computerInfo.Model)"
Write-Log "OS: $($osInfo.Caption) (Edition: $($osInfo.OperatingSystemSKU), Version: $($osInfo.Version), Build: $($osInfo.BuildNumber))"

# Check for PSWindowsUpdate module
Write-Log "Checking for PSWindowsUpdate module..."
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    try {
        Install-Module -Name PSWindowsUpdate -Force -ErrorAction Stop
        Write-Log "PSWindowsUpdate module installed."
    } catch {
        Write-Log "Failed to install PSWindowsUpdate module: $_"
        Stop-Transcript
        exit 1
    }
}
Write-Log "PSWindowsUpdate module ready."

# Ensure Windows Update service is running
if ((Get-Service -Name wuauserv).Status -ne 'Running') {
    try {
        Start-Service -Name wuauserv -ErrorAction Stop
        Write-Log "Started Windows Update service."
    } catch {
        Write-Log "Failed to start Windows Update service: $_"
        Stop-Transcript
        exit 1
    }
}

# Check for Windows updates
Write-Log "Checking for Windows updates (including Defender definitions)..."
Write-Log "Running Get-WindowsUpdate..."
$updates = Get-WindowsUpdate -Verbose -ErrorAction SilentlyContinue
$securityUpdates = $updates | Where-Object { $_.Categories -match "Security|Critical" }
$nonSecurityUpdates = $updates | Where-Object { $_.Categories -notmatch "Security|Critical" }

if ($securityUpdates) {
    Write-Log "Found $($securityUpdates.Count) security updates to install automatically:"
    foreach ($update in $securityUpdates) {
        Write-Log "Security Update: $($update.Title) ($($update.KBArticleIDs))"
    }
    $retryCount = 0
    $maxRetries = 3
    while ($retryCount -lt $maxRetries) {
        try {
            $result = Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Verbose -ErrorAction Stop
            Write-Log "Windows Update Result: $result"
            break
        } catch {
            $retryCount++
            Write-Log "Retry $retryCount/$maxRetries failed: $_"
            Start-Sleep -Seconds 60
        }
    }
    if ($retryCount -eq $maxRetries) {
        Write-Log "Failed to install security updates after $maxRetries attempts."
    }
}

if ($nonSecurityUpdates) {
    Write-Log "Found $($nonSecurityUpdates.Count) non-security updates available:"
    foreach ($update in $nonSecurityUpdates) {
        Write-Log "Non-Security Update: $($update.Title) ($($update.KBArticleIDs))"
    }
    Write-Log "Installing non-security updates automatically."
    try {
        $result = Install-WindowsUpdate -AcceptAll -AutoReboot:$false -Verbose -ErrorAction Stop
        Write-Log "Non-Security Update Result: $result"
    } catch {
        Write-Log "Failed to install non-security updates: $_"
    }
}

# Verify no pending updates
$pending = Get-WindowsUpdate -Verbose -ErrorAction SilentlyContinue
if ($pending) {
    Write-Log "Pending updates remain: $pending"
} else {
    Write-Log "All updates installed successfully."
}

# Update Microsoft Defender definitions
Write-Log "Checking for Microsoft Defender definition updates..."
try {
    Write-Log "Running Update-MpSignature to update Defender definitions..."
    Update-MpSignature -Verbose -ErrorAction Stop
    Write-Log "Microsoft Defender definitions updated successfully."
} catch {
    Write-Log "Failed to update Defender definitions: $_"
}

# Check for non-Store app updates via winget
Write-Log "Checking for non-Store app updates via winget..."
try {
    $wingetVersion = winget --version
    Write-Log "winget version: $wingetVersion"
} catch {
    Write-Log "winget not installed or failed: $_"
    $wingetVersion = $null
}

if ($wingetVersion) {
    Write-Log "Checking for existing winget processes..."
    $wingetProcesses = Get-Process -Name "winget" -ErrorAction SilentlyContinue
    if ($wingetProcesses) {
        Write-Log "Terminating existing winget processes..."
        $wingetProcesses | Stop-Process -Force
    }

    $wingetOutput = winget upgrade | Out-String
    $updates = @()
    $lines = $wingetOutput -split "`n"
    foreach ($line in $lines) {
        if ($line -match "^(.+?)\s+([\w\.]+)\s+(\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+)") {
            $updates += [PSCustomObject]@{
                Name      = $matches[1].Trim()
                Id        = $matches[2].Trim()
                Current   = $matches[3].Trim()
                Available = $matches[4].Trim()
            }
        }
    }
    if ($updates) {
        foreach ($update in $updates) {
            Write-Log "Installing $($update.Name) ($($update.Id)) from $($update.Current) to $($update.Available)"
            try {
                winget upgrade --id $update.Id --silent --accept-source-agreements --accept-package-agreements --force | Out-File $logFile -Append
                Write-Log "Successfully updated $($update.Name)"
            } catch {
                Write-Log "Failed to update $($update.Name): $_"
            }
        }
    } else {
        Write-Log "No non-Store app updates available."
    }
}

# Update Microsoft Store apps
Write-Log "Attempting to update Microsoft Store apps..."
try {
    Write-Log "Opening Microsoft Store for updates..."
    Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction Stop
    Write-Log "Microsoft Store launched."
    $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
    if ($storeProcess) {
        Write-Log "Microsoft Store process found (PID: $($storeProcess.Id))."
    } else {
        Write-Log "Warning: Microsoft Store process not found after launch."
    }
    Write-Log "Waiting 120 seconds for Microsoft Store updates to complete..."
    Start-Sleep -Seconds 120
    $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
    if ($storeProcess) {
        Write-Log "Closing Microsoft Store after update wait..."
        Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Microsoft Store app updates completed."
} catch {
    Write-Log "Failed to update Microsoft Store apps: $_"
}

# Check for pending reboot
Write-Log "Checking for pending reboot..."
$rebootRequired = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -or
    Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") {
    $rebootRequired = $true
    Write-Log "Pending reboot: File rename operations detected."
    Write-Log "Reboot required to complete update installation."
    Write-Log "Notifying user of required reboot..."
    $msg = "A reboot is required to complete updates. Please restart your PC soon."
    try {
        msg.exe * $msg -ErrorAction Stop
        Write-Log "User notified of reboot requirement."
    } catch {
        Write-Log "Failed to notify user: $_"
    }
}

# Clean up old logs (keep last 7 days)
Write-Log "Cleaning up old logs..."
Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force
Write-Log "Old logs cleaned up."

# Installation summary
Write-Log "Installation Summary:"
Write-Log "Installed $($securityUpdates.Count) security updates (including Defender definitions)"
Write-Log "Installed $($nonSecurityUpdates.Count) non-security updates"
Write-Log "Updated Microsoft Defender definitions"
Write-Log "Updated Microsoft Store apps"
if ($updates) {
    Write-Log "Updated $($updates.Count) non-Store apps via winget"
} else {
    Write-Log "No non-Store app updates applied"
}
if ($rebootRequired) {
    Write-Log "Reboot required to complete installation"
} else {
    Write-Log "No reboot required"
}

Write-Log "Script completed."
Stop-Transcript
