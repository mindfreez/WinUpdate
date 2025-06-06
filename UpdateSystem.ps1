# LocalUpdateSystem.ps1
# Purpose: Automate Windows Update, Defender definitions, and Microsoft Store updates with logging and reboot handling
# Compatibility: Windows 10 and Windows 11
# Requires: Administrative privileges; automatically installs PSWindowsUpdate if needed
# Notes: Prefers PowerShell 7.x if available; minimizes console output to prevent duplicates

param (
    [bool]$DebugMode = $true
)

$logDir = "$env:ProgramData\SystemUpdateScript\Logs"
$logFile = "$logDir\UpdateScript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$fallbackLogFile = "$env:TEMP\UpdateScript_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$failedUpdates = @()
$installSummary = @()
$psWindowsUpdateAvailable = $false
$successfullyInstalledUpdates = $false

# Ensure log directory exists
try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Log directory created."
    }
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to create log directory $logDir : $($_.Exception.Message)"
    Write-Error "Failed to create log directory: $_"
    exit 1
}

# Start transcript
try {
    Start-Transcript -Path $logFile -Append -Force -ErrorAction Stop
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to start transcript for $logFile : $($_.Exception.Message)"
    Write-Error "Failed to start transcript: $_"
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message,
        [switch]$Verbose
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    if ($Verbose -or $DebugMode) {
        Write-Output $logMessage  # Console output only in DebugMode or with Verbose
    }
    if (-not $Verbose -and -not $DebugMode) {
        Add-Content -Path $fallbackLogFile -Value $logMessage -ErrorAction SilentlyContinue
    }
}

# Function to stop processes that may lock updates
function Stop-LockingProcesses {
    Write-Log "Stopping processes that may lock updates..." -Verbose
    try {
        Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
        Stop-Process -Name "storeapp" -Force -ErrorAction SilentlyContinue
        Write-Log "Locking processes stopped." -Verbose
    } catch {
        Write-Log "Warning: Failed to stop locking processes: $($_.Exception.Message)"
    }
}

# Check PowerShell version and relaunch in PowerShell 7.x if available
Write-Log "Checking PowerShell version..." -Verbose
$currentPSVersion = $PSVersionTable.PSVersion.Major
Write-Log "Current PowerShell version: $currentPSVersion" -Verbose

if ($currentPSVersion -lt 7) {
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if ($pwshPath) {
        Write-Log "PowerShell 7.x found at $pwshPath. Relaunching script in PowerShell 7.x..." -Verbose
        try {
            $scriptPath = $MyInvocation.MyCommand.Path
            Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DebugMode:$DebugMode" -Wait
            Write-Log "Script relaunched in PowerShell 7.x." -Verbose
            exit 0
        } catch {
            Write-Log "Error relaunching in PowerShell 7.x: $_" -Verbose
            Write-Error "Error relaunching in PowerShell 7.x: $_"
        }
    } else {
        Write-Log "PowerShell 7.x not found. Continuing with Windows PowerShell $currentPSVersion." -Verbose
    }
} else {
    Write-Log "Running in PowerShell $currentPSVersion. No relaunch needed." -Verbose
}

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "Error: Script must run with administrative privileges." -Verbose
    Write-Error "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

try {
    # Detect PC Model and OS Details
    Write-Log "Detecting system information..." -Verbose
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $pcModel = "$($computerSystem.Manufacturer) $($computerSystem.Model)"
        $osName = $osInfo.Caption
        $osEdition = if ($osInfo.OSEdition) { $osInfo.OSEdition } else { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID").EditionID }
        $osVersion = $osInfo.Version
        $osBuild = $osInfo.BuildNumber
        Write-Log "PC Model: $pcModel" -Verbose
        Write-Log "OS: $osName (Edition: $osEdition, Version: $osVersion, Build: $osBuild)" -Verbose
    } catch {
        Write-Log "Warning: Failed to detect system information: $($_.Exception.Message)" -Verbose
    }

    # Check internet connectivity
    Write-Log "Checking internet connectivity..." -Verbose
    if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Log "Error: No internet connection detected." -Verbose
        Write-Error "No internet connection detected."
        exit 1
    }

    # Check and install PSWindowsUpdate module
    Write-Log "Checking for PSWindowsUpdate module..." -Verbose
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Installing PSWindowsUpdate module..." -Verbose
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
                Write-Log "NuGet provider installed." -Verbose
            }
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
            Write-Log "PSWindowsUpdate module installed successfully." -Verbose
        } else {
            Write-Log "PSWindowsUpdate module already installed. Skipping installation." -Verbose
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $psWindowsUpdateAvailable = $true
        Write-Log "PSWindowsUpdate module ready." -Verbose
    } catch {
        Write-Log "Error: Failed to install/import PSWindowsUpdate module: $($_.Exception.Message)"
        $failedUpdates += "Failed to install/import module PSWindowsUpdate: $($_.Exception.Message)"
        Write-Error "Failed to install/import PSWindowsUpdate module: $_"
    }

    if ($psWindowsUpdateAvailable) {
        # Limit update attempts to prevent infinite loop
        $maxAttempts = 5
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            Write-Log "Checking for Windows updates (attempt $attempt of $maxAttempts)..." -Verbose
            try {
                Write-Log "Running Get-WindowsUpdate..." -Verbose
                $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop | Where-Object { $_.IsHidden -eq $false }

                if ($updates) {
                    $securityUpdates = @()
                    $nonSecurityUpdates = @()
                    foreach ($update in $updates) {
                        $isSecurityUpdate = $false
                        foreach ($category in $update.Categories) {
                            if ($category.Name -match "Security Updates" -or $category.Name -match "Definition Updates") {
                                $isSecurityUpdate = $true
                                break
                            }
                        }
                        if ($isSecurityUpdate) {
                            $securityUpdates += $update
                        } else {
                            $nonSecurityUpdates += $update
                        }
                    }

                    # Install security updates
                    if ($securityUpdates) {
                        Write-Log "Found $($securityUpdates.Count) security updates to install automatically:" -Verbose
                        foreach ($update in $securityUpdates) {
                            Write-Log "Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                        }
                        Write-Progress -Activity "Installing security updates" -Status "Starting..."
                        Install-WindowsUpdate -KBArticleID ($securityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -Quiet -ErrorAction Stop | Out-Null
                        $successfullyInstalledUpdates = $true
                        $installSummary += "Installed $($securityUpdates.Count) security updates (including Defender definitions)"
                        Write-Progress -Activity "Installing security updates" -Completed
                    } else {
                        Write-Log "No security updates to install via PSWindowsUpdate." -Verbose
                    }

                    # Install non-security updates (auto in DebugMode or non-interactive)
                    if ($nonSecurityUpdates) {
                        Write-Log "Found $($nonSecurityUpdates.Count) non-security updates available:" -Verbose
                        foreach ($update in $nonSecurityUpdates) {
                            Write-Log "Non-Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                        }
                        $installNonSecurity = if ($DebugMode -or -not [Console]::IsInputRedirected) { 'Y' } else { Read-Host "Non-security updates are available. Install them now? (Y/N)" }
                        if ($installNonSecurity -eq 'Y' -or $installNonSecurity -eq 'y') {
                            Write-Progress -Activity "Installing non-security updates" -Status "Starting..."
                            Install-WindowsUpdate -KBArticleID ($nonSecurityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -Quiet -ErrorAction Stop | Out-Null
                            $successfullyInstalledUpdates = $true
                            $installSummary += "Installed $($nonSecurityUpdates.Count) non-security updates"
                            Write-Progress -Activity "Installing non-security updates" -Completed
                        } else {
                            Write-Log "Non-security updates skipped." -Verbose
                        }
                    } else {
                        Write-Log "No non-security updates to install via PSWindowsUpdate." -Verbose
                    }
                } else {
                    Write-Log "No Windows updates to install via PSWindowsUpdate." -Verbose
                    break
                }
            } catch {
                Write-Log "Error: Failed to install Windows updates: $($_.Exception.Message)"
                $failedUpdates += "Failed Windows updates: $($_.Exception.Message)"
                Write-Error "Failed to install Windows updates: $_"
            }
            $attempt++
            Start-Sleep -Seconds 60
        }
    } else {
        Write-Log "PSWindowsUpdate unavailable. Skipping Windows updates." -Verbose
    }

    # Check for Microsoft Defender updates
    Write-Log "Checking for Microsoft Defender definition updates..." -Verbose
    try {
        Import-Module -Name Defender -ErrorAction Stop
        Write-Log "Running Update-MpSignature..." -Verbose
        Update-MpSignature -ErrorAction Stop
        Write-Log "Microsoft Defender definitions updated successfully." -Verbose
        $installSummary += "Updated Microsoft Defender definitions"
    } catch {
        Write-Log "Warning: Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        $failedUpdates += "Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        Write-Error "Failed to update Defender definitions: $_"
    }

    # Update Microsoft Store apps
    if (-not ($failedUpdates -match "Failed to install/import module PSWindowsUpdate")) {
        Write-Log "Attempting to update Microsoft Store apps..." -Verbose
        try {
            Write-Log "Opening Microsoft Store for updates..." -Verbose
            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction Stop
            Write-Log "Microsoft Store launched." -Verbose
            $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
            if ($storeProcess) {
                Write-Log "Microsoft Store process found (PID: $($storeProcess.Id))." -Verbose
            } else {
                Write-Log "Warning: Microsoft Store process not found after launch." -Verbose
            }

            $waitSeconds = 300
            if (-not $DebugMode -and -not [Console]::IsInputRedirected) {
                Write-Log "Waiting $waitSeconds seconds for Microsoft Store updates..." -Verbose
                Start-Sleep -Seconds $waitSeconds
                Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
                Write-Log "Microsoft Store closed after fixed wait." -Verbose
                $installSummary += "Completed Microsoft Store app updates via Store UI"
            } else {
                Write-Log "Debug mode or non-interactive: Waiting $waitSeconds seconds for Microsoft Store updates..." -Verbose
                Start-Sleep -Seconds $waitSeconds
                $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
                if ($storeProcess) {
                    Write-Log "Extending wait by 300 seconds for Microsoft Store updates..." -Verbose
                    Start-Sleep -Seconds 300
                }
                Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
                Write-Log "Microsoft Store closed after update wait." -Verbose
                $installSummary += "Completed Microsoft Store app updates via Store UI"
            }
        } catch {
            Write-Log "Warning: Failed to update Microsoft Store apps: $($_.Exception.Message). Leaving Store open." -Verbose
            $failedUpdates += "Failed to update Microsoft Store apps: $($_.Exception.Message)"
            Write-Error "Failed to update Microsoft Store apps: $_"
            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Skipping Microsoft Store updates due to PSWindowsUpdate failure." -Verbose
    }

    # Check for pending reboot
    Write-Log "Checking for pending reboot..." -Verbose
    $rebootRequired = $false
    try {
        $lastBoot = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
        if ($uptime.Days -ge 30) {
            Write-Log "System has been running for $($uptime.Days) days. Reboot recommended." -Verbose
            $rebootRequired = $true
        }
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            Write-Log "Pending reboot: File rename operations detected." -Verbose
            $rebootRequired = $true
        }
        $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "RebootRequired" -ErrorAction SilentlyContinue
        if ($wuReboot) {
            Write-Log "Pending reboot: Windows Update requires reboot." -Verbose
            $rebootRequired = $true
        }
        $cbsReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Name "RebootPending" -ErrorAction SilentlyContinue
        if ($cbsReboot) {
            Write-Log "Pending reboot: CBS operations pending." -Verbose
            $rebootRequired = $true
        }
    } catch {
        Write-Log "Warning: Failed to check for pending reboot: $($_.Exception.Message)"
    }

    if ($rebootRequired) {
        Write-Log "Reboot required to complete update installation." -Verbose
        if ($DebugMode -or [Console]::IsInputRedirected) {
            Write-Log "Debug mode or non-interactive: Skipping reboot prompt." -Verbose
            Write-Output "A reboot is required to complete update installation. Please reboot manually."
        } else {
            Write-Log "Prompting for reboot confirmation..." -Verbose
            $response = Read-Host "A reboot is required to complete update installation. Reboot now? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "User confirmed reboot. Rebooting now..." -Verbose
                Stop-LockingProcesses
                Restart-Computer -Force
                exit 0
            } else {
                Write-Log "User deferred reboot. Reboot required to complete updates." -Verbose
            }
        }
    } else {
        Write-Log "No reboot required." -Verbose
    }

    # Clean up old logs
    Write-Log "Cleaning up old logs..." -Verbose
    try {
        Get-ChildItem -Path $logDir -Filter "UpdateScript_*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Old logs cleaned up." -Verbose
    } catch {
        Write-Log "Warning: Failed to clean up old logs: $($_.Exception.Message)"
    }

    # Log summary
    Write-Log "Installation Summary:" -Verbose
    foreach ($item in $installSummary) {
        Write-Log $item -Verbose
    }
    if ($failedUpdates) {
        Write-Log "Failed Updates:" -Verbose
        foreach ($failure in $failedUpdates) {
            Write-Log $failure -Verbose
        }
    }

    if ($failedUpdates -match "Failed to install/import module PSWindowsUpdate") {
        Write-Log "Critical failure detected. Exiting with code 1." -Verbose
        Write-Error "Critical failure: PSWindowsUpdate module issue"
        exit 1
    }

    Write-Log "Script completed successfully." -Verbose
    Write-Output "Script completed. Check $logFile for details."
}
catch {
    Write-Log "Critical error in script: $($_.Exception.Message)" -Verbose
    $failedUpdates += "Critical script error: $($_.Exception.Message)"
    Write-Error "Critical script error: $_"
    exit 1
}
finally {
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {
        Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to stop transcript: $($_.Exception.Message)"
    }
    exit 0
}
