# Ensure script runs as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logFile = "C:\Logs\WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Write-Output "$(Get-Date): Script started, checking admin privileges..." | Out-File -FilePath $logFile -Append

if (-not $isAdmin) {
    Write-Output "$(Get-Date): Not running as admin, attempting to relaunch..." | Out-File -FilePath $logFile -Append
    Write-Host "Relaunching as Administrator..."
    try {
        $scriptPath = $MyInvocation.MyCommand.Definition
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        Write-Output "$(Get-Date): Admin relaunch initiated" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Output "$(Get-Date): Error relaunching as admin: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Failed to relaunch as admin: $($_.Exception.Message)"
        pause
    }
    exit
}

Write-Output "$(Get-Date): Running as admin" | Out-File -FilePath $logFile -Append
Write-Host "Running as Administrator"

# Check internet connectivity
Write-Host "Checking internet connectivity..."
if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet)) {
    Write-Output "$(Get-Date): Error: No internet connection" | Out-File -FilePath $logFile -Append
    Write-Host "No internet connection detected"
    pause
    exit 1
}
Write-Output "$(Get-Date): Internet connection confirmed" | Out-File -FilePath $logFile -Append
Write-Host "Internet connection confirmed"

# Check disk space
$minFreeGB = 10
Write-Host "Checking disk space..."
try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt $minFreeGB) {
        Write-Output "$(Get-Date): Insufficient disk space ($freeSpaceGB GB)" | Out-File -FilePath $logFile -Append
        Write-Host "Insufficient disk space: $freeSpaceGB GB (min $minFreeGB GB required)"
        pause
        exit 1
    }
    Write-Host "Sufficient disk space: $freeSpaceGB GB"
} catch {
    Write-Host "Error checking disk space: $($_.Exception.Message)"
    exit 1
}

# Check for PowerShell 7
$pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $pwshCmd) {
    Write-Host "PowerShell 7 not found. Installing latest version..."
    try {
        $latestVersion = ((Invoke-WebRequest -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing).Content | ConvertFrom-Json).tag_name.TrimStart("v")
        $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestVersion/PowerShell-$latestVersion-win-x64.msi"
        $installerPath = "$env:TEMP\PowerShell-$latestVersion.msi"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait
        Write-Host "PowerShell 7 installed."
    } catch {
        Write-Host "Failed to install PowerShell 7: $($_.Exception.Message)"
        Write-Output "$(Get-Date): PowerShell 7 installation failed: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

# Relaunch in PowerShell 7 if not already running in it
if ($PSVersionTable.PSVersion.Major -lt 7 -and $pwshCmd) {
    Write-Host "Relaunching this script in PowerShell 7..."
    Start-Process -FilePath $pwshCmd.Source -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
    exit
}

Write-Host "Running in PowerShell version: $($PSVersionTable.PSVersion.ToString())"

# Ensure NuGet is installed for system-wide module installation
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing NuGet package provider..."
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Import-PackageProvider -Name NuGet -Force
    } catch {
        Write-Host "Failed to install NuGet provider: $($_.Exception.Message)"
        exit 1
    }
}

# Install PSWindowsUpdate system-wide
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Installing PSWindowsUpdate module system-wide..."
    try {
        Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber
    } catch {
        Write-Host "Error installing PSWindowsUpdate: $($_.Exception.Message)"
        exit 1
    }
}
Import-Module PSWindowsUpdate -Force

# Check and install security updates
Write-Host "Checking for security updates..."
try {
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Download -Install -AutoReboot:$false -Category "Security Updates"
    if ($updates) {
        Write-Host "Security updates installed"
    } else {
        Write-Host "No security updates available"
    }
} catch {
    Write-Host "Error checking/installing updates: $($_.Exception.Message)"
    exit 1
}

# Update Microsoft Defender definitions
Write-Host "Checking for Microsoft Defender updates..."
if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
    try {
        Update-MpSignature -Verbose
        Write-Host "Defender definitions updated."
    } catch {
        Write-Host "Failed to update Defender definitions: $($_.Exception.Message)"
    }
} else {
    Write-Host "Defender not available or unsupported on this system."
}

# Check for pending reboot
Write-Host "Checking for pending reboot..."
$rebootRequired = Get-WURebootStatus -Silent
if ($rebootRequired) {
    $title = "Windows Update"
    $message = "A reboot is required to complete the update installation. Reboot now?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Reboot now"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Reboot later"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $choice = $host.UI.PromptForChoice($title, $message, $options, 0)
    if ($choice -eq 0) {
        Write-Host "Rebooting..."
        Restart-Computer -Force
    } else {
        Write-Host "Reboot postponed."
    }
} else {
    Write-Host "No reboot required."
}

# Clean up logs
Write-Host "Cleaning up old logs..."
try {
    Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
    Write-Host "Old logs cleaned up."
} catch {
    Write-Host "Log cleanup failed: $($_.Exception.Message)"
}

Write-Host "`nScript completed. Log saved to: $logFile"
