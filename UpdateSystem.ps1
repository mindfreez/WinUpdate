# Detect in-memory execution (e.g., from Invoke-WebRequest + ScriptBlock)
$IsMemoryExecution = -not $MyInvocation.MyCommand.Path

# Ensure script runs as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logFile = "C:\Logs\WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Write-Output "$(Get-Date): Script started" | Out-File -FilePath $logFile -Append

if (-not $isAdmin) {
    Write-Output "$(Get-Date): Not running as admin" | Out-File -FilePath $logFile -Append
    if ($IsMemoryExecution) {
        Write-Host "Cannot relaunch as Administrator from memory. Please run as Administrator or use Task Scheduler with 'Run with highest privileges'."
        exit 1
    } else {
        Write-Host "Relaunching as Administrator..."
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
        exit
    }
}

Write-Host "Running as Administrator"
Write-Output "$(Get-Date): Running as admin" | Out-File -FilePath $logFile -Append

# Check internet connectivity
Write-Host "Checking internet..."
if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet)) {
    Write-Host "No internet connection."
    Write-Output "$(Get-Date): No internet" | Out-File -FilePath $logFile -Append
    exit 1
}
Write-Output "$(Get-Date): Internet confirmed" | Out-File -FilePath $logFile -Append

# Check disk space
$minFreeGB = 10
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
if ($freeSpaceGB -lt $minFreeGB) {
    Write-Host "Low disk space: $freeSpaceGB GB free"
    Write-Output "$(Get-Date): Low disk space: $freeSpaceGB GB" | Out-File -FilePath $logFile -Append
    exit 1
}
Write-Host "Free disk space: $freeSpaceGB GB"

# Check for PowerShell 7
$pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
if ($PSVersionTable.PSVersion.Major -lt 7 -and $pwshCmd) {
    if ($IsMemoryExecution) {
        Write-Host "Running in PowerShell 5.1 — skipping PowerShell 7 relaunch (in-memory execution)."
        Write-Output "$(Get-Date): Skipped PS7 relaunch due to memory mode" | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "Relaunching in PowerShell 7..."
        Start-Process -FilePath $pwshCmd.Source -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
        exit
    }
}

Write-Output "$(Get-Date): Running in PowerShell $($PSVersionTable.PSVersion)" | Out-File -FilePath $logFile -Append
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

# Ensure NuGet is installed system-wide
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing NuGet provider..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Import-PackageProvider NuGet -Force
}

# Install PSWindowsUpdate module (AllUsers)
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Installing PSWindowsUpdate module system-wide..."
    Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber
}
Import-Module PSWindowsUpdate -Force

# Check and install security updates
Write-Host "Checking for security updates..."
try {
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Download -Install -AutoReboot:$false -Category "Security Updates"
    if ($updates) {
        Write-Host "Security updates installed."
    } else {
        Write-Host "No security updates available."
    }
} catch {
    Write-Host "Error installing updates: $($_.Exception.Message)"
    exit 1
}

# Update Microsoft Defender
Write-Host "Checking for Defender updates..."
if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
    try {
        Update-MpSignature -Verbose
        Write-Host "Defender definitions updated."
    } catch {
        Write-Host "Failed to update Defender: $($_.Exception.Message)"
    }
} else {
    Write-Host "Defender cmdlets not available."
}

# Reboot prompt if needed
Write-Host "Checking for pending reboot..."
$rebootRequired = Get-WURebootStatus -Silent
if ($rebootRequired) {
    $title = "Windows Update"
    $message = "A reboot is required. Reboot now?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Reboot now"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Reboot later"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $choice = $host.UI.PromptForChoice($title, $message, $options, 0)
    if ($choice -eq 0) {
        Restart-Computer -Force
    } else {
        Write-Host "Reboot deferred."
    }
} else {
    Write-Host "No reboot required."
}

# Clean up logs >30 days
Write-Host "Cleaning up logs..."
try {
    Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
    Write-Host "Old logs removed."
} catch {
    Write-Host "Failed log cleanup: $($_.Exception.Message)"
}

Write-Output "$(Get-Date): Script complete" | Out-File -FilePath $logFile -Append
Write-Host "Script complete. Log: $logFile"
