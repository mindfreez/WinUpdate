# Detect in-memory execution (e.g., from Invoke-WebRequest + ScriptBlock)
$IsMemoryExecution = -not $MyInvocation.MyCommand.Path

# Ensure script runs as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logFile = "C:\Logs\WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Write-Output "$(Get-Date): Script started" | Out-File -FilePath $logFile -Append
Write-Host "Script started"

if (-not $isAdmin) {
    Write-Output "$(Get-Date): Not running as admin" | Out-File -FilePath $logFile -Append
    Write-Host "Relaunching as Administrator..."
    if ($IsMemoryExecution) {
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-Expression ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mindfreez/WinUpdate/main/UpdateSystem.ps1' -UseBasicParsing).Content)`"" -Verb RunAs
            Write-Output "$(Get-Date): Admin relaunch initiated" | Out-File -FilePath $logFile -Append
        } catch {
            Write-Output "$(Get-Date): Error relaunching as admin: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
            Write-Host "Failed to relaunch as admin: $($_.Exception.Message)"
            pause
        }
    } else {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
        Write-Output "$(Get-Date): Admin relaunch initiated" | Out-File -FilePath $logFile -Append
    }
    exit
}
Write-Output "$(Get-Date): Running as admin" | Out-File -FilePath $logFile -Append
Write-Host "Running as Administrator"

# Check internet connectivity
Write-Output "$(Get-Date): Checking internet connectivity..." | Out-File -FilePath $logFile -Append
Write-Host "Checking internet..."
if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet)) {
    Write-Output "$(Get-Date): No internet" | Out-File -FilePath $logFile -Append
    Write-Host "No internet connection"
    pause
    exit 1
}
Write-Output "$(Get-Date): Internet confirmed" | Out-File -FilePath $logFile -Append
Write-Host "Internet connection confirmed"

# Check disk space
$minFreeGB = 10
Write-Output "$(Get-Date): Checking disk space..." | Out-File -FilePath $logFile -Append
Write-Host "Checking disk space..."
try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt $minFreeGB) {
        Write-Output "$(Get-Date): Low disk space: $freeSpaceGB GB" | Out-File -FilePath $logFile -Append
        Write-Host "Low disk space: $freeSpaceGB GB free"
        pause
        exit 1
    }
    Write-Output "$(Get-Date): Free disk space: $freeSpaceGB GB" | Out-File -FilePath $logFile -Append
    Write-Host "Free disk space: $freeSpaceGB GB"
} catch {
    Write-Output "$(Get-Date): Error checking disk space: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Error checking disk space: $($_.Exception.Message)"
    pause
    exit 1
}

# Check for PowerShell 7
$pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $pwshCmd) {
    Write-Output "$(Get-Date): PowerShell 7 not installed, installing..." | Out-File -FilePath $logFile -Append
    Write-Host "Installing PowerShell 7..."
    try {
        $latestPwshVersion = (Invoke-WebRequest -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing | ConvertFrom-Json).tag_name.TrimStart('v')
        Write-Output "$(Get-Date): Installing PowerShell 7 version $latestPwshVersion" | Out-File -FilePath $logFile -Append
        Write-Host "Installing PowerShell 7 version $latestPwshVersion..."
        $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestPwshVersion/PowerShell-$latestPwshVersion-win-x64.msi"
        $installerPath = "$env:TEMP\PowerShell-$latestPwshVersion.msi"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -ErrorAction Stop
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $installerPath /quiet /norestart" -Wait -ErrorAction Stop
        Write-Output "$(Get-Date): PowerShell 7 installed" | Out-File -FilePath $logFile -Append
        Write-Host "PowerShell 7 installed"
        $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    } catch {
        Write-Output "$(Get-Date): Error installing PowerShell 7: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Error installing PowerShell 7: $($_.Exception.Message)"
        Write-Output "$(Get-Date): Continuing in PowerShell 5.1" | Out-File -FilePath $logFile -Append
        Write-Host "Continuing in PowerShell 5.1"
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7 -and $pwshCmd) {
    Write-Output "$(Get-Date): PowerShell 7 detected, relaunching..." | Out-File -FilePath $logFile -Append
    Write-Host "Relaunching in PowerShell 7..."
    if ($IsMemoryExecution) {
        try {
            Start-Process -FilePath $pwshCmd.Source -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-Expression ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mindfreez/WinUpdate/main/UpdateSystem.ps1' -UseBasicParsing).Content)`"" -Verb RunAs
            Write-Output "$(Get-Date): PowerShell 7 relaunch initiated" | Out-File -FilePath $logFile -Append
        } catch {
            Write-Output "$(Get-Date): Error relaunching in PowerShell 7: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
            Write-Host "Error relaunching in PowerShell 7: $($_.Exception.Message)"
            Write-Output "$(Get-Date): Continuing in PowerShell 5.1" | Out-File -FilePath $logFile -Append
            Write-Host "Continuing in PowerShell 5.1"
        }
    } else {
        Start-Process -FilePath $pwshCmd.Source -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
        Write-Output "$(Get-Date): PowerShell 7 relaunch initiated" | Out-File -FilePath $logFile -Append
    }
    exit
}
Write-Output "$(Get-Date): Running in PowerShell $($PSVersionTable.PSVersion)" | Out-File -FilePath $logFile -Append
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

# Ensure NuGet is installed system-wide
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Output "$(Get-Date): Installing NuGet provider..." | Out-File -FilePath $logFile -Append
    Write-Host "Installing NuGet provider..."
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        Write-Output "$(Get-Date): NuGet provider installed" | Out-File -FilePath $logFile -Append
        Write-Host "NuGet provider installed"
    } catch {
        Write-Output "$(Get-Date): Error installing NuGet: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Error installing NuGet: $($_.Exception.Message)"
        pause
        exit 1
    }
}

# Install PSWindowsUpdate module (AllUsers)
Write-Output "$(Get-Date): Checking PSWindowsUpdate module..." | Out-File -FilePath $logFile -Append
Write-Host "Checking PSWindowsUpdate module..."
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Output "$(Get-Date): Installing PSWindowsUpdate module system-wide..." | Out-File -FilePath $logFile -Append
    Write-Host "Installing PSWindowsUpdate module system-wide..."
    try {
        Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        Write-Output "$(Get-Date): PSWindowsUpdate module installed" | Out-File -FilePath $logFile -Append
        Write-Host "PSWindowsUpdate module installed"
    } catch {
        Write-Output "$(Get-Date): Error installing PSWindowsUpdate: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Error installing PSWindowsUpdate: $($_.Exception.Message)"
        pause
        exit 1
    }
}
Import-Module PSWindowsUpdate -Force -ErrorAction Stop

# Check and install security updates
Write-Output "$(Get-Date): Checking for security updates..." | Out-File -FilePath $logFile -Append
Write-Host "Checking for security updates..."
try {
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Download -Install -AutoReboot:$false -Category "Security Updates" -Verbose *>> $logFile
    if ($updates) {
        Write-Output "$(Get-Date): Security updates installed" | Out-File -FilePath $logFile -Append
        Write-Host "Security updates installed"
    } else {
        Write-Output "$(Get-Date): No security updates available" | Out-File -FilePath $logFile -Append
        Write-Host "No security updates available"
    }
} catch {
    Write-Output "$(Get-Date): Error installing updates: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Error installing updates: $($_.Exception.Message)"
    pause
    exit 1
}

# Update Microsoft Defender
Write-Output "$(Get-Date): Checking for Defender updates..." | Out-File -FilePath $logFile -Append
Write-Host "Checking for Defender updates..."
if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
    try {
        Update-MpSignature -Verbose *>> $logFile
        Write-Output "$(Get-Date): Defender definitions updated" | Out-File -FilePath $logFile -Append
        Write-Host "Defender definitions updated"
    } catch {
        Write-Output "$(Get-Date): Failed to update Defender: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Failed to update Defender: $($_.Exception.Message)"
    }
} else {
    Write-Output "$(Get-Date): Defender cmdlets not available" | Out-File -FilePath $logFile -Append
    Write-Host "Defender cmdlets not available"
}

# Reboot prompt if needed
Write-Output "$(Get-Date): Checking for pending reboot..." | Out-File -FilePath $logFile -Append
Write-Host "Checking for pending reboot..."
$rebootRequired = Get-WURebootStatus -Silent
if ($rebootRequired) {
    Write-Output "$(Get-Date): Reboot required after update installation" | Out-File -FilePath $logFile -Append
    Write-Host "Reboot required after update installation"
    $title = "Windows Update"
    $message = "A reboot is required to complete the update installation. Reboot now?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Reboot now"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Reboot later"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $choice = $host.UI.PromptForChoice($title, $message, $options, 0)
    if ($choice -eq 0) {
        Write-Output "$(Get-Date): User chose to reboot now" | Out-File -FilePath $logFile -Append
        Write-Host "Rebooting now..."
        Restart-Computer -Force
    } else {
        Write-Output "$(Get-Date): User chose to reboot later" | Out-File -FilePath $logFile -Append
        Write-Host "Reboot deferred"
    }
} else {
    Write-Output "$(Get-Date): No reboot required" | Out-File -FilePath $logFile -Append
    Write-Host "No reboot required"
}

# Clean up logs >30 days
Write-Output "$(Get-Date): Cleaning up logs older than 30 days..." | Out-File -FilePath $logFile -Append
Write-Host "Cleaning up old logs..."
try {
    Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
    Write-Output "$(Get-Date): Old logs removed" | Out-File -FilePath $logFile -Append
    Write-Host "Old logs removed"
} catch {
    Write-Output "$(Get-Date): Failed log cleanup: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Failed log cleanup: $($_.Exception.Message)"
}

Write-Output "$(Get-Date): Script complete" | Out-File -FilePath $logFile -Append
Write-Host "Script complete. Log: $logFile"
