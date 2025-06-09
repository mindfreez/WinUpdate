# UpdateSystem.ps1
# Purpose: Automate Windows Update, Defender definitions, and Microsoft Store updates with logging and reboot handling
# Compatibility: Windows 10 and Windows 11
# Requires: Administrative privileges; automatically installs PSWindowsUpdate if needed
# Notes: Prefers PowerShell 7.x if available; uses a single log file with append mode

param (
    [switch]$DebugMode,
    [switch]$NonInteractive,
    [int]$StoreUpdateTimeout = 180,
    [string]$LogFile
)

$logDir = "$env:ProgramData\SystemUpdateScript\Logs"
# Define log file path if not passed as parameter
if (-not $LogFile) {
    $LogFile = "$logDir\UpdateScript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}
$fallbackLogFile = "$env:TEMP\UpdateScript_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$failedUpdates = @()
$installSummary = @()
$psWindowsUpdateAvailable = $false
$successfullyInstalledUpdates = $false

# Ensure log directory exists
try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Log directory created."
    }
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to create log directory $logDir : $($_.Exception.Message)"
    Write-Error "Failed to create log directory: $_"
    exit 1
}

# Start transcript
try {
    Start-Transcript -Path $LogFile -Append -Force -ErrorAction Stop
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to start transcript for $LogFile : $($_.Exception.Message)"
    Write-Error "Failed to start transcript: $_"
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message,
        [switch]$Verbose
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
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
            # Download the script content from GitHub for relaunching
            $scriptUrl = "https://raw.githubusercontent.com/mindfreez/WinUpdate/main/UpdateSystem.ps1"
            $scriptContent = (Invoke-WebRequest -Uri $scriptUrl -ErrorAction Stop).Content
            $tempScriptPath = "$env:TEMP\UpdateSystem_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
            Set-Content -Path $tempScriptPath -Value $scriptContent -ErrorAction Stop
            Write-Log "Created temporary script file: $tempScriptPath" -Verbose

            # Build arguments for relaunch
            $args = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScriptPath`""
            if ($DebugMode) { $args += " -DebugMode" }
            if ($NonInteractive) { $args += " -NonInteractive" }
            $args += " -StoreUpdateTimeout $StoreUpdateTimeout -LogFile `"$LogFile`""

            Write-Log "Relaunching with command: $pwshPath $args" -Verbose
            $process = Start-Process -FilePath $pwshPath -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            Write-Log "PowerShell 7.x process exited with code: $($process.ExitCode)" -Verbose

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
            Write-Log "Falling back to PowerShell $currentPSVersion." -Verbose
        } finally {
            # Clean up temporary script
            if (Test-Path $tempScriptPath) {
                Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
                Write-Log "Cleaned up temporary script: $tempScriptPath" -Verbose
            }
        }
    } else {
        Write-Log "PowerShell 7.x not found. Continuing with PowerShell $currentPSVersion." -Verbose
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
                        $installSummary += "Installed $($securityUpdates.Count) security updates (including Defender definitions)"
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
                $failedUpdates += "Failed Windows updates: $($_.Exception.Message)"
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
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            if ($searchResult.Updates.Count -gt 0) {
                Write-Log "Found $($searchResult.Updates.Count) updates via COM." -Verbose
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $searchResult.Updates
                $installResult = $installer.Install()
                Write-Log "COM-based update installation completed." -Verbose
                $installSummary += "Installed updates via COM-based Windows Update"
                $successfullyInstalledUpdates = $true
            } else {
                Write-Log "No updates found via COM-based Windows Update." -Verbose
            }
        } catch {
            Write-Log "Error: COM-based update failed: $($_.Exception.Message)"
            $failedUpdates += "COM-based update failed: $($_.Exception.Message)"
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
        Write-Log "Warning: Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        $failedUpdates += "Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        Write-Error "Failed to update Defender definitions: $_"
    }

    # Update Microsoft Store apps (skip in non-interactive mode or PowerShell 7.x)
    if (-not $NonInteractive -and -not ($failedUpdates -match "Failed to install/import module PSWindowsUpdate") -and $PSVersionTable.PSEdition -eq "Desktop") {
        Write-Log "Attempting to update Microsoft Store apps in PowerShell Desktop..." -Verbose
        try {
            # Check if Microsoft Store is installed
            $storeApp = Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction Stop
            if ($storeApp) {
                Write-Log "Microsoft Store app found: $($storeApp.Name) ($($storeApp.Version))" -Verbose
                Write-Log "Opening Microsoft Store for updates..." -Verbose
                Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction Stop
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
            } else {
                Write-Log "Warning: Microsoft Store app not installed. Skipping Store updates." -Verbose
                $failedUpdates += "Microsoft Store app not installed"
            }
        } catch {
            Write-Log "Warning: Failed to update Microsoft Store apps: $($_.Exception.Message)" -Verbose
            $failedUpdates += "Failed to update Microsoft Store apps: $($_.Exception.Message)"
            Write-Error "Failed to update Microsoft Store apps: $_"
            # Attempt to open Store as fallback
            try {
                Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Warning: Fallback attempt to open Microsoft Store failed: $($_.Exception.Message)" -Verbose
            }
        }
    } else {
        Write-Log "Skipping Microsoft Store updates due to non-interactive mode, PSWindowsUpdate failure, or PowerShell Core." -Verbose
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
        if ($NonInteractive -or $DebugMode -or [Console]::IsInputRedirected) {
            Write-Log "Non-interactive or debug mode: Skipping reboot prompt." -Verbose
            Write-Output "A reboot is required to complete update installation. Please reboot manually."
            try {
                # Load Windows Runtime assemblies for toast notifications
                Add-Type -AssemblyName System.Runtime.WindowsRuntime
                [WindowsRuntimeLoader.RuntimeLoader]::Load("Windows.UI.Notifications")
                $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
                $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
                $xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("System Update")) | Out-Null
                $xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("A reboot is required to complete updates. Please reboot soon.")) | Out-Null
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("System Update Script")
                $notifier.Show([Windows.UI.Notifications.ToastNotification]::new($xml))
                Write-Log "Sent toast notification for pending reboot." -Verbose
            } catch {
                Write-Log "Warning: Failed to send toast notification: $($_.Exception.Message)" -Verbose
                try {
                    # Fallback to System.Windows.Forms.MessageBox
                    Add-Type -AssemblyName System.Windows.Forms
                    [System.Windows.Forms.MessageBox]::Show("A reboot is required to complete updates. Please reboot soon.", "System Update", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    Write-Log "Sent fallback message box for pending reboot." -Verbose
                } catch {
                    Write-Log "Warning: Failed to send fallback message box: $($_.Exception.Message)" -Verbose
                }
            }
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
        Get-ChildItem -Path $env:TEMP -Filter "UpdateScript_Fallback_*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $env:TEMP -Filter "UpdateSystem_*.ps1" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Old logs and temporary scripts cleaned up." -Verbose
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
    Write-Output "Script completed. Check $LogFile for details."
}
catch {
    Write-Log "Critical error in script: $($_.Exception.Message)" -Verbose
    $failedUpdates += "Critical script error: $($_.Exception.Message)"
    Write-Error "Critical script error: $_"
}
finally {
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {
        Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to stop transcript: $($_.Exception.Message)"
    }
    exit 0
}
