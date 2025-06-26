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
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-Expression ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mindfreez/WinUpdate/main/CheckUpdates.ps1' -UseBasicParsing).Content)`"" -Verb RunAs
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
Write-Output "$(Get-Date): Checking internet connectivity..." | Out-File -FilePath $logFile -Append
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
Write-Output "$(Get-Date): Checking disk space..." | Out-File -FilePath $logFile -Append
Write-Host "Checking disk space..."
try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt $minFreeGB) {
        Write-Output "$(Get-Date): Error: Insufficient disk space ($freeSpaceGB GB free, $minFreeGB GB required)" | Out-File -FilePath $logFile -Append
        Write-Host "Insufficient disk space: $freeSpaceGB GB free, $minFreeGB GB required"
        pause
        exit 1
    }
    Write-Output "$(Get-Date): Sufficient disk space ($freeSpaceGB GB)" | Out-File -FilePath $logFile -Append
    Write-Host "Sufficient disk space: $freeSpaceGB GB"
} catch {
    Write-Output "$(Get-Date): Error checking disk space: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Error checking disk space: $($_.Exception.Message)"
    pause
    exit 1
}

# Check PowerShell version and handle PowerShell 7 installation/upgrade
$currentPSVersion = $PSVersionTable.PSVersion.Major
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
Write-Output "$(Get-Date): Checking PowerShell version ($currentPSVersion)..." | Out-File -FilePath $logFile -Append
Write-Host "Checking PowerShell version ($currentPSVersion)..."
if ($currentPSVersion -lt 7) {
    if (Test-Path $pwshPath) {
        Write-Output "$(Get-Date): PowerShell 7 detected, checking version..." | Out-File -FilePath $logFile -Append
        Write-Host "PowerShell 7 detected, checking version..."
        try {
            $pwshVersion = & $pwshPath -Command '$PSVersionTable.PSVersion.ToString()' 2>> $logFile
            Write-Output "$(Get-Date): Current PowerShell 7 version: $pwshVersion" | Out-File -FilePath $logFile -Append
            Write-Host "Current PowerShell 7 version: $pwshVersion"
            $latestPwshVersion = (Invoke-WebRequest -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing | ConvertFrom-Json).tag_name.TrimStart('v')
            Write-Output "$(Get-Date): Latest PowerShell 7 version: $latestPwshVersion" | Out-File -FilePath $logFile -Append
            Write-Host "Latest PowerShell 7 version: $latestPwshVersion"
            if ([version]$pwshVersion -lt [version]$latestPwshVersion) {
                Write-Output "$(Get-Date): Upgrading PowerShell 7 from $pwshVersion to $latestPwshVersion" | Out-File -FilePath $logFile -Append
                Write-Host "Upgrading PowerShell 7 from $pwshVersion to $latestPwshVersion..."
                $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestPwshVersion/PowerShell-$latestPwshVersion-win-x64.msi"
                $installerPath = "$env:TEMP\PowerShell-$latestPwshVersion.msi"
                Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -ErrorAction Stop
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $installerPath /quiet /norestart" -Wait -ErrorAction Stop
                Write-Output "$(Get-Date): PowerShell 7 upgraded to $latestPwshVersion" | Out-File -FilePath $logFile -Append
                Write-Host "PowerShell 7 upgraded to $latestPwshVersion"
            }
            Write-Output "$(Get-Date): Relaunching in PowerShell 7" | Out-File -FilePath $logFile -Append
            Write-Host "Relaunching in PowerShell 7..."
            try {
                Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-Expression ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mindfreez/WinUpdate/main/CheckUpdates.ps1' -UseBasicParsing).Content)`"" -Verb RunAs
                Write-Output "$(Get-Date): PowerShell 7 relaunch initiated" | Out-File -FilePath $logFile -Append
            } catch {
                Write-Output "$(Get-Date): Error relaunching in PowerShell 7: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
                Write-Host "Error relaunching in PowerShell 7: $($_.Exception.Message)"
                Write-Output "$(Get-Date): Continuing in PowerShell 5.1 due to relaunch failure" | Out-File -FilePath $logFile -Append
                Write-Host "Continuing in PowerShell 5.1 due to relaunch failure"
            }
        } catch {
            Write-Output "$(Get-Date): Error during PowerShell 7 version check/upgrade: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
            Write-Host "Error during PowerShell 7 version check/upgrade: $($_.Exception.Message)"
            Write-Output "$(Get-Date): Continuing in PowerShell 5.1 due to version check failure" | Out-File -FilePath $logFile -Append
            Write-Host "Continuing in PowerShell 5.1 due to version check failure"
        }
    } else {
        Write-Output "$(Get-Date): PowerShell 7 not installed, installing latest version..." | Out-File -FilePath $logFile -Append
        Write-Host "PowerShell 7 not installed, installing latest version..."
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
            Write-Output "$(Get-Date): Relaunching in PowerShell 7" | Out-File -FilePath $logFile -Append
            Write-Host "Relaunching in PowerShell 7..."
            Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-Expression ((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mindfreez/WinUpdate/main/CheckUpdates.ps1' -UseBasicParsing).Content)`"" -Verb RunAs
            Write-Output "$(Get-Date): PowerShell 7 relaunch initiated" | Out-File -FilePath $logFile -Append
        } catch {
            Write-Output "$(Get-Date): Error installing PowerShell 7: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
            Write-Host "Error installing PowerShell 7: $($_.Exception.Message)"
            Write-Output "$(Get-Date): Continuing in PowerShell 5.1 due to installation failure" | Out-File -FilePath $logFile -Append
            Write-Host "Continuing in PowerShell 5.1 due to installation failure"
        }
    }
    exit # Ensure PowerShell 5.1 exits after launching PowerShell 7
} else {
    Write-Output "$(Get-Date): Running in PowerShell 7 ($($PSVersionTable.PSVersion.ToString()))" | Out-File -FilePath $logFile -Append
    Write-Host "Running in PowerShell 7 ($($PSVersionTable.PSVersion.ToString()))"
}

# Install PSWindowsUpdate module if not present
Write-Output "$(Get-Date): Checking PSWindowsUpdate module..." | Out-File -FilePath $logFile -Append
Write-Host "Checking PSWindowsUpdate module..."
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Output "$(Get-Date): Installing PSWindowsUpdate module..." | Out-File -FilePath $logFile -Append
    Write-Host "Installing PSWindowsUpdate module..."
    try {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Verbose *>> $logFile
        Write-Output "$(Get-Date): PSWindowsUpdate module installed" | Out-File -FilePath $logFile -Append
        Write-Host "PSWindowsUpdate module installed"
    } catch {
        Write-Output "$(Get-Date): Error installing PSWindowsUpdate: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        Write-Host "Error installing PSWindowsUpdate: $($_.Exception.Message)"
        pause
        exit 1
    }
}

Import-Module PSWindowsUpdate -ErrorAction Stop

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

# Check for Defender updates
Write-Output "$(Get-Date): Checking for Microsoft Defender updates..." | Out-File -FilePath $logFile -Append
Write-Host "Checking for Microsoft Defender updates..."
try {
    if (Get-Module -ListAvailable -Name Defender) {
        Import-Module -Name Defender -ErrorAction Stop
        Update-MpSignature -ErrorAction Stop -Verbose *>> $logFile
        Write-Output "$(Get-Date): Microsoft Defender definitions updated" | Out-File -FilePath $logFile -Append
        Write-Host "Microsoft Defender definitions updated"
    } else {
        Write-Output "$(Get-Date): Defender module not available, skipping Defender updates" | Out-File -FilePath $logFile -Append
        Write-Host "Defender module not available, skipping Defender updates"
    }
} catch {
    Write-Output "$(Get-Date): Failed to update Defender definitions: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Failed to update Defender definitions: $($_.Exception.Message)"
}

# Check if reboot is required
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
    $result = $host.UI.PromptForChoice($title, $message, $options, 0)
    if ($result -eq 0) {
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

# Clean up old logs
Write-Output "$(Get-Date): Cleaning up logs older than 30 days..." | Out-File -FilePath $logFile -Append
Write-Host "Cleaning up old logs..."
try {
    Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
    Write-Output "$(Get-Date): Log cleanup completed" | Out-File -FilePath $logFile -Append
    Write-Host "Log cleanup completed"
} catch {
    Write-Output "$(Get-Date): Error cleaning up logs: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    Write-Host "Error cleaning up logs: $($_.Exception.Message)"
}

Write-Output "$(Get-Date): Script completed" | Out-File -FilePath $logFile -Append
Write-Host "Script completed. Check $logFile for details."
