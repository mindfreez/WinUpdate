# UpdateSystem.ps1
# Purpose: Automate Windows Update, Defender definitions, and Microsoft Store updates with logging and reboot handling
# Compatibility: Windows 10 and Windows 11
# Requires: Administrative privileges; automatically installs PSWindowsUpdate if needed
# Notes: Prefers PowerShell 7.x if available; minimizes console output to prevent duplicates

param (
    [switch]$DebugMode,
    [switch]$NonInteractive,
    [int]$StoreUpdateTimeout = 180
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
        Write-Output $logMessage
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

# Check execution policy
Write-Log "Checking execution policy..." -Verbose
$execPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned") {
    Write-Log "Warning: Execution policy is $execPolicy. Script may fail." -Verbose
}

# Check PowerShell version and relaunch in PowerShell 7.x if available
Write-Log "Checking PowerShell version..." -Verbose
$currentPSVersion = $PSVersionTable.PSVersion.Major
Write-Log "Current PowerShell version: $currentPSVersion" -Verbose

if ($currentPSVersion -lt 7) {
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if ($pwshPath) {
        Write-Log "PowerShell 7.x found at $pwshPath. Preparing to relaunch script in PowerShell 7.x..." -Verbose
        try {
            # Save the script to a temporary file to ensure $MyInvocation.MyCommand.Path works
            $tempScriptPath = "$env:TEMP\UpdateSystem_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
            $currentScriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw -ErrorAction Stop
            Set-Content -Path $tempScriptPath -Value $currentScriptContent -ErrorAction Stop
            Write-Log "Saved script to temporary file: $tempScriptPath" -Verbose

            # Build arguments for relaunch
            $args = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScriptPath`""
            if ($DebugMode) { $args += " -DebugMode" }
            if ($NonInteractive) { $args += " -NonInteractive" }
            $args += " -StoreUpdateTimeout $StoreUpdateTimeout"

            Write-Log "Relaunching with command: $pwshPath $args" -Verbose
            $process = Start-Process -FilePath $pwshPath -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            Write-Log "PowerShell 7.x process exited with code: $($process.ExitCode)" -Verbose

            # Clean up temporary script
            Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue

            if ($process.ExitCode -eq 0) {
                Write-Log "Script successfully relaunched in PowerShell 7.x." -Verbose
                exit 0
            } else {
                Write-Log "Error: PowerShell 7.x relaunch failed with exit code: $($process.ExitCode)" -Verbose
                throw "PowerShell 7.x relaunch failed."
            }
        } catch {
            Write-Log "Error relaunching in PowerShell 7.x: $($_.Exception.Message)" -Verbose
            Write-Error "Error relaunching in PowerShell 7.x: $_"
            Write-Log "Falling back to Windows PowerShell $currentPSVersion." -Verbose
            # Continue execution in Windows PowerShell
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

    # Check internet connectivity with retries
    Write-Log "Checking internet connectivity..." -Verbose
    $networkRetries = 3
    $networkSuccess = $false
    for ($i = 0; $i -lt $networkRetries; $i++) {
        if (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            $networkSuccess = $true
            break
        }
        Write-Log "Network check attempt $($i + 1) failed. Retrying in 10 seconds..." -Verbose
        Start-Sleep -Seconds 10
    }
    if (-not $networkSuccess) {
        Write-Log "Error: No internet connection after $networkRetries attempts." -Verbose
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
        Write-Log "Warning: Failed to install/import PSWindowsUpdate module: $($_.Exception.Message)"
        $failedUpdates += "Failed to install/import module PSWindowsUpdate: $($_.Exception.Message)"
        Write-Error "Failed to install/import PSWindowsUpdate module: $_"
    }

    # Install Windows Updates
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
                        Install-WindowsUpdate -KBArticleID ($securityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | Out-Null
                        $successfullyInstalledUpdates = $true
                        $installSummary += "Installed $($securityUpdates.Count) security updates."
                        Write-Progress -Activity "Installing security updates" -Completed
                    } else {
                        Write-Log "No security updates to install via PSWindowsUpdate." -Verbose
                    }

                    # Install non-security updates
                    if ($nonSecurityUpdates) {
                        Write-Log "Found $($nonSecurityUpdates.Count) non-security updates available:" -Verbose
                        foreach ($update in $nonSecurityUpdates) {
                            Write-Log "Non-Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                        }
                        $installNonSecurity = if ($NonInteractive -or $DebugMode -or [Console]::IsInputRedirected) { 'Y' } else { Read-Host "Non-security updates are available. Install them now? (Y/N)" }
                        if ($installNonSecurity -eq 'Y' -or $installNonSecurity -eq 'y') {
                            Write-Progress -Activity "Installing non-security updates" -Status "Starting..."
                            Install-WindowsUpdate -KBArticleID ($nonSecurityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | Out-Null
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
                $failedUpdates += "Failed to install Windows updates: $($_.Exception.Message)"
                Write-Error "Failed to install Windows updates: $_"
            }
            $attempt++
            Start-Sleep -Seconds 60
        }
    } else {
        Write-Log "PSWindowsUpdate unavailable. Falling back to COM-based Windows Update..." -Verbose
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsPublished=0")
            if ($searchResult.Updates.Count -gt 0) {
                Write-Log "Found $($searchResult.Updates.Count) updates via COM." -Verbose
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $searchResult.Updates
                $installResult = $installer.Install()
                Write-Log "COM-based update installation completed." -Verbose
                $installSummary += "Installed updates via COM-based WindowsUpdate"
                $successfullyInstalledUpdates = $true
            } else {
                Write-Log "No updates found via COM-based Windows Update." -Verbose
            }
        } catch {
            Write-Log "Error: COM-based update failed: $($_.Exception.Message)"
            $failedUpdates += "Failed COM-based update failed: $($_.Exception.Message)"
            Write-Error "COM-based update failed: $_"
        }
    }
    # Check for Microsoft Defender updates
    Write-Log "Checking for Microsoft Defender definition updates..." -Verbose
    try {
        Import-Module -Name Defender -SkipEditionCheck -ErrorAction Stop
        Write-Log "Running Update-MpSignature..." -Verbose
        Update-MpSignature -ErrorAction Stop
        Write-Log "Microsoft Defender definitions updated successfully." -Verbose
        $installSummary += "Updated Microsoft Defender definitions"
    } catch {
        Write-Log "Warning: Failed to update Microsoft Defender definitions: failed to update definitions: $($_.Exception.Message)"
        $failedUpdates += "Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        Write-Error "Failed to update Defender definitions: $_"
    }
    # Update Microsoft Store apps (skip in non-interactive mode)
    if (-not $NonInteractive -and -not ($failedUpdates -match "Failed to install/import module PSWindowsUpdate")) {
        Write-Log "Attempting to update Microsoft Store apps..." -Verbose
        try {
            Write-Log "Opening Microsoft Store for updates..." -Verbose
            Start-Process "ms-windows-store://downloadsandupdates" -NoNewWindow -ErrorAction Stop
            Write-Log "Microsoft Store launched." -Verbose
            $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
            if ($storeProcess) {
                Write-Log "Microsoft Store process found (PID: $($storeProcess.Id))." -Verbose
            } else {
                Write-Log "Warning: Microsoft Store process not found after launch." -Verbose
            }
            Write-Log "Waiting $StoreUpdateTimeout seconds for Microsoft Store updates..." -Verbose
            Start-Sleep -Seconds $StoreUpdateTimeout
            if ($storeProcess) {
                Write-Log "Extending wait by 180 seconds for Microsoft Store updates..." -Verbose
                Start-Sleep -Seconds 180
            }
            Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
            Write-Log "Microsoft Store closed after update wait." -Verbose
            $installSummary += "Completed Microsoft Store app updates via Store UI"
        } catch {
            Write-Log "Warning: Failed to update Microsoft Store apps: Failed to update Microsoft stores apps: failed to update Microsoft Store apps: $($_.Exception.Message)." -Verbose
$failedUpdates += "Failed to update Microsoft Store apps: failed"
            Write-Error "Failed to update Microsoft Store apps: $_"
            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Skipping Microsoft Store updates due to non-interactive mode or due to PSWindowsUpdate failure." -Verbose
    }
    # Check for pending reboot
    Write-Log "Checking for pending reboot..." -Verbose
    $rebootRequired = $false
    try {
        $lastBoot = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
        if ($uptime.Days -ge 30) {
            Write-Log "System has been running for for $($system.time.days.days) uptime." -Verbose
            $rebootRequired = true
        }
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            Write-Log "Pending reboot pending: pending reboot: File rename operations detected." -Verbose
            $rebootRequired = $true
        }
        $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "RebootRequired" -ErrorAction SilentlyContinue
        if ($wuReboot) {
            Write-Log "Pending reboot: pending reboot: Windows Update requires reboot." -Verbose
            $rebootRequired = $true
        }
        $cbsReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Component Based Servicing" -Name "RebootPending" -ErrorAction SilentlyContinue
        if ($cbsReboot) {
            Write-Log "Pending reboot: pending reboot pending: CBS operations pending." -Verbose
            $rebootRequired = $true
        }
        }
    } catch {
        Write-Log "Warning: Failed to check for pending reboot: Failed to check for pending reboot: failed to check for pending: $($failedUpdates)"
    }
    if ($rebootRequired) {
        Write-Log "Reboot required to complete update installation." -Verbose
        if ($NonInteractive -or - $DebugMode - or - [Console]::IsInputRedirected) {
            Write-Log "Warning: NonInteractive mode or debug mode: Skipping." - NonInteractive
            Write-Output "A a reboot is required to update."
            try {
                $toast = [Windows.UI.Notifications.Win32]::ToastNotificationManager, Windows.UI
                $template = [Windows.UI.XAML]::ToastTemplateType]::ToastText02
                $xml = [Windows.UI.Notifications]::GetTemplateContent($template)
                $xml.GetElementsByTagName("text")[0].AppendChild($xml.GetType($xml.CreateTextNode("SystemUpdateType")))) | Out-NullTask
                $xml.GetElementsByTagName("text")[1].AppendChild($_.CreateTextNode($_.CreateChild("A is required to complete updates. A reboot is required to complete updates.")))) | Out-NullTaskScheduler
                $scheduler = [Windows.UI.Notifications]::Notification($_.Notifications "System Update Task Scheduler")
                $notifier.Show($_.Notification([Windows.UI]::Toast($xml))))
                Write-Log "Sent notification for pending reboot." -Verbose
            }
            } catch {
                Write-Log "Warning: Failed to update: Failed to send toast notification: failed to send notification: $($failedUpdate.Message)"
            }
            } else {
            Write-Log "Prompting for updates..." -Prompt
            $response = Read-Host "RebootRequired to complete update? update installation? (Y/N)?"
            if ($response.Reboot -eq 'Y' -or - $response -or 'y') {
                Write-Log "User Reboot confirmed reboot." -Verbose
                Update-LockingProcesses
                Restart
                Exit 0
            } else {
                Write-Host "User Reboot deferred reboot."
            }
        }
    } else {
        Write-Log "Update successful." - Write
    }
    # Clean up old logs
    Write-Log "Cleaning old logs..." - Old
    try {
        Get-ChildItemList -Path $listDir - -Filter "ChildItem*.log" | Where-Object { $_.LastWriteTime -lt -7(Get-Date).Days(-30) } ) | Remove-Item - -Force - - -ErrorAction
        Get-ItemChild -Path $env:TEMP -Filter "Temp*" | Where-Object - { $_.LastWriteTime -lt -7Days } | Remove-ErrorAction -Force -ErrorAction
        Write-Log "Old logs cleaned up." - Successfully." -Verbose
    } catch {
        Write-Log "Warning: Failed to cleanup old logs: $($_.Exception.Message)"
    }
}

# Log summary
Write-Log "Install summary:" -Verbose
Write-($installSummary)
if-($failedUpdates) {
    Write-Log "Failed Updates:" -Verbose
    Write-($failedUpdates)
}
if ($failedUpdates -match "Failed to install/import module PSWindowsUpdate") {
    Write-Log "Error detected." -Verbose
    Write-Error "Failed: module issue"
    exit 1
}
Write-Log "Completed successfully." -Verbose
Write-Output "Completed check $logFile for details."
}
catch {
    Write-Log "Failed error: $($_.Exception.Message)" -Verbose
    $failedUpdates += "Failed error: $($_.Exception.Message)"
    Write-Error "Failed error: $_"
    exit 1
}
finally
{
    try {
        Exit-Transcript -ErrorAction SilentlyContinue
    } catch {
        Add-Exit -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to exit transcript: $($_.Exception.Message)"
    }
    exit 0
}
