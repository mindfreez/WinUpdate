# UpdateSystem.ps1
# Purpose: Automate Windows Update, Defender definitions, and Microsoft Store updates with logging and reboot handling
# Compatibility: Windows 10 and Windows 11
# Requires: Administrative privileges; automatically installs PSWindowsUpdate if needed
# Notes: Prefers PowerShell 7.x if available; uses a single log file with append mode

param (
    [switch]$DebugMode,
    [switch]$NonInteractive,
    [switch]$SecurityOnly,
    [switch]$FeatureUpdatesOnly,
    [switch]$NonSecurityOnly,
    [int]$StoreUpdateTimeout = 180,
    [int]$MinFreeGB = 10,
    [string]$LogFile
)

$logDir = "$env:ProgramData\SystemUpdateScript\Logs"
if (-not $LogFile) {
    $LogFile = "$logDir\UpdateScript_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(New-Guid).log"
}
$fallbackLogFile = "$env:TEMP\UpdateScript_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$failedUpdates = @()
$installSummary = @()
$psWindowsUpdateAvailable = $false
$successfullyInstalledUpdates = $false

# Validate LogFile parameter
if ($LogFile -match '[<>|]') {
    Write-Error "Invalid characters in LogFile parameter."
    exit 1
}

# Validate StoreUpdateTimeout
if ($StoreUpdateTimeout -lt 30) {
    $StoreUpdateTimeout = 30
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Warning: StoreUpdateTimeout set to minimum of 30 seconds."
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message,
        [switch]$Verbose
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    try {
        [System.IO.File]::AppendAllText($LogFile, "$logMessage`n", [System.Text.Encoding]::UTF8)
    } catch {
        try {
            [System.IO.File]::AppendAllText($fallbackLogFile, "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error writing to main log: $($_.Exception.Message)`n", [System.Text.Encoding]::UTF8)
        } catch {
            # Suppress further errors to prevent infinite loop
        }
    }
    if ($Verbose -or $DebugMode) {
        Write-Output $logMessage
    }
    try {
        if (-not $Verbose -and -not $DebugMode) {
            [System.IO.File]::AppendAllText($fallbackLogFile, "$logMessage`n", [System.Text.Encoding]::UTF8)
        }
    } catch {
        # Suppress errors
    }
}

# Ensure log directory exists and handle file locks with retry
try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Log "Log directory created." -Verbose
    } else {
        $maxAttempts = 3
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            if (Test-Path $LogFile) {
                try {
                    [System.IO.FileStream]::new($LogFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None).Dispose()
                    break
                } catch {
                    if ($attempt -eq $maxAttempts - 1) {
                        $LogFile = "$logDir\UpdateScript_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(New-Guid).log"
                        Write-Log "Log file locked after $maxAttempts attempts. Switched to new log file: $LogFile" -Verbose
                    }
                    Start-Sleep -Seconds 1
                    $attempt++
                }
            } else {
                break
            }
        }
    }
} catch {
    [System.IO.File]::AppendAllText($fallbackLogFile, "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to create or access log directory $logDir : $($_.Exception.Message)`n")
    Write-Error "Failed to create or access log directory: $_"
    exit 1
}

# Function to clean Windows Update cache
function Clear-WindowsUpdateCache {
    Write-Log "Clearing Windows Update cache..." -Verbose
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction Stop
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        Write-Log "Windows Update cache cleared successfully." -Verbose
    } catch {
        Write-Log "Warning: Failed to clear Windows Update cache: $($_.Exception.Message)"
        $failedUpdates += "Failed to clear Windows Update cache: $($_.Exception.Message)"
    }
}

# Function to check disk space
function Test-DiskSpace {
    param (
        [string]$Drive = "C:",
        [int]$MinFreeGB
    )
    Write-Log "Checking disk space on $Drive..." -Verbose
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'"
        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        Write-Log "Free disk space: $freeSpaceGB GB" -Verbose
        if ($freeSpaceGB -lt $MinFreeGB) {
            Write-Log "Error: Insufficient disk space ($freeSpaceGB GB free, $MinFreeGB GB required)." -Verbose
            throw "Insufficient disk space for updates."
        }
        Write-Log "Sufficient disk space available." -Verbose
        return $true
    } catch {
        Write-Log "Error checking disk space: $($_.Exception.Message)"
        $failedUpdates += "Failed to check disk space: $($_.Exception.Message)"
        return $false
    }
}

# Start transcript
try {
    Start-Transcript -Path $LogFile -Append -Force -ErrorAction Stop
    Write-Log "Transcript started successfully." -Verbose
} catch {
    Write-Log "Error: Failed to start transcript for $LogFile : $($_.Exception.Message)" -Verbose
    Write-Error "Failed to start transcript: $_"
}

# Check and bypass execution policy
try {
    $execPolicy = Get-ExecutionPolicy -Scope CurrentUser
    Write-Log "Checking execution policy: $execPolicy" -Verbose
    if ($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned") {
        Write-Log "Attempting to bypass execution policy..." -Verbose
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Log "Execution policy bypassed for this process." -Verbose
    }
} catch {
    Write-Log "Error bypassing execution policy: $($_.Exception.Message)" -Verbose
    Write-Error "Failed to bypass execution policy: $_"
    exit 1
}

# Check PowerShell version and relaunch in PowerShell 7.x if available
Write-Log "Checking PowerShell version..." -Verbose
$currentPSVersion = $PSVersionTable.PSVersion.Major
Write-Log "Current PowerShell version: $currentPSVersion" -Verbose

if ($currentPSVersion -lt 7) {
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if ($pwshPath -and (Test-Path $pwshPath) -and $PSCommandPath) {
        Write-Log "PowerShell 7.x found at $pwshPath. Relaunching script in PowerShell 7.x..." -Verbose
        try {
            $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            if ($DebugMode) { $args += " -DebugMode" }
            if ($NonInteractive) { $args += " -NonInteractive" }
            if ($SecurityOnly) { $args += " -SecurityOnly" }
            if ($FeatureUpdatesOnly) { $args += " -FeatureUpdatesOnly" }
            if ($NonSecurityOnly) { $args += " -NonSecurityOnly" }
            $args += " -StoreUpdateTimeout $StoreUpdateTimeout -MinFreeGB $MinFreeGB -LogFile `"$LogFile`""
            Write-Log "Relaunching with command: $pwshPath $args" -Verbose
            $process = Start-Process -FilePath $pwshPath -ArgumentList $args -Wait -PassThru -ErrorAction Stop
            Write-Log "PowerShell 7.x process exited with code: $($process.ExitCode)" -Verbose
            exit $process.ExitCode
        } catch {
            Write-Log "Error relaunching in PowerShell 7.x: $($_.Exception.Message)" -Verbose
            [System.IO.File]::AppendAllText($fallbackLogFile, "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error relaunching in PowerShell 7.x: $($_.Exception.Message)`n")
            Write-Log "Falling back to PowerShell $currentPSVersion." -Verbose
        }
    } else {
        Write-Log "PowerShell 7.x not found or invalid script path ($PSCommandPath). Continuing with PowerShell $currentPSVersion." -Verbose
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

    # Check disk space
    $dynamicMinFreeGB = $MinFreeGB
    if ($FeatureUpdatesOnly) {
        $dynamicMinFreeGB = [Math]::Max($MinFreeGB, 20)
    }
    if (-not (Test-DiskSpace -Drive "C:" -MinFreeGB $dynamicMinFreeGB)) {
        Write-Log "Error: Stopping due to insufficient disk space." -Verbose
        exit 1
    }

    # Clear Windows Update cache
    Clear-WindowsUpdateCache

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
        $maxInstallAttempts = 3
        $installAttempt = 0
        while ($installAttempt -lt $maxInstallAttempts -and -not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            try {
                if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
                    Write-Log "NuGet provider installed." -Verbose
                }
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Write-Log "PSWindowsUpdate module installed successfully." -Verbose
                break
            } catch {
                $installAttempt++
                Write-Log "Attempt $installAttempt to install PSWindowsUpdate failed: $($_.Exception.Message)" -Verbose
                if ($installAttempt -eq $maxInstallAttempts) {
                    Write-Log "Warning: Failed to install PSWindowsUpdate after $maxInstallAttempts attempts." -Verbose
                    $failedUpdates += "Failed to install PSWindowsUpdate: $($_.Exception.Message)"
                }
                Start-Sleep -Seconds 10
            }
        }
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            $psWindowsUpdateAvailable = $true
            Write-Log "PSWindowsUpdate module ready." -Verbose
        }
    } catch {
        Write-Log "Warning: Failed to import PSWindowsUpdate module: $($_.Exception.Message)"
        $failedUpdates += "Failed to import PSWindowsUpdate: $($_.Exception.Message)"
    }

    # Install Windows Updates
    if ($psWindowsUpdateAvailable) {
        $maxAttempts = 5
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            Write-Log "Checking for Windows updates (attempt $attempt of $maxAttempts)..." -Verbose
            try {
                $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop | Where-Object { $_.IsHidden -eq $false }
                if ($updates) {
                    $securityUpdates = @()
                    $nonSecurityUpdates = @()
                    $featureUpdates = @()
                    foreach ($update in $updates) {
                        $isSecurityUpdate = $false
                        $isFeatureUpdate = $false
                        foreach ($category in $update.Categories) {
                            if ($category.Name -match "Security Updates|Definition Updates") {
                                $isSecurityUpdate = $true
                                break
                            }
                            if ($category.Name -match "Feature Packs" -or $update.Title -match "version 24H2") {
                                $isFeatureUpdate = $true
                            }
                        }
                        if ($isFeatureUpdate) {
                            $featureUpdates += $update
                        } elseif ($isSecurityUpdate) {
                            $securityUpdates += $update
                        } else {
                            $nonSecurityUpdates += $update
                        }
                    }

                    $filteredUpdates = @()
                    if ($SecurityOnly -and $securityUpdates) {
                        $filteredUpdates = $securityUpdates
                    } elseif ($FeatureUpdatesOnly -and $featureUpdates) {
                        $filteredUpdates = $featureUpdates
                    } elseif ($NonSecurityOnly -and $nonSecurityUpdates) {
                        $filteredUpdates = $nonSecurityUpdates
                    } else {
                        $filteredUpdates = $updates
                    }

                    if ($filteredUpdates) {
                        if ($securityUpdates -and (-not $FeatureUpdatesOnly -and -not $NonSecurityOnly)) {
                            Write-Log "Found $($securityUpdates.Count) security updates to install:" -Verbose
                            foreach ($update in $securityUpdates) {
                                Write-Log "Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                            }
                            Write-Progress -Activity "Installing security updates" -Status "Starting..."
                            Install-WindowsUpdate -KBArticleID ($securityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop -Verbose | Out-Null
                            $successfullyInstalledUpdates = $true
                            $installSummary += "Installed $($securityUpdates.Count) security updates"
                            Write-Progress -Activity "Installing security updates" -Completed
                        }

                        if ($featureUpdates -and (-not $SecurityOnly -and -not $NonSecurityOnly)) {
                            Write-Log "Found $($featureUpdates.Count) feature updates to install:" -Verbose
                            foreach ($update in $featureUpdates) {
                                Write-Log "Feature Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                            }
                            Write-Progress -Activity "Installing feature updates" -Status "Starting..."
                            try {
                                Install-WindowsUpdate -KBArticleID ($featureUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop -Verbose | Out-Null
                                $successfullyInstalledUpdates = $true
                                $installSummary += "Installed $($featureUpdates.Count) feature updates"
                            } catch {
                                Write-Log "Error: Failed to install feature updates: $($_.Exception.Message)" -Verbose
                                $failedUpdates += "Failed feature updates: $($_.Exception.Message)"
                                Write-Log "Falling back to Windows Update Assistant..." -Verbose
                                try {
                                    $assistantUrl = "https://go.microsoft.com/fwlink/?LinkID=799445"
                                    $assistantPath = "$env:TEMP\WindowsUpdateAssistant.exe"
                                    Invoke-WebRequest -Uri $assistantUrl -OutFile $assistantPath -ErrorAction Stop
                                    Start-Process -FilePath $assistantPath -ArgumentList "/quietinstall /skipeula /auto upgrade" -Wait -ErrorAction Stop
                                    Write-Log "Windows Update Assistant executed successfully." -Verbose
                                    $installSummary += "Attempted feature update via Windows Update Assistant"
                                    $successfullyInstalledUpdates = $true
                                } catch {
                                    Write-Log "Error: Failed to run Windows Update Assistant: $($_.Exception.Message)" -Verbose
                                    $failedUpdates += "Failed Windows Update Assistant: $($_.Exception.Message)"
                                }
                            }
                            Write-Progress -Activity "Installing feature updates" -Completed
                        }

                        if ($nonSecurityUpdates -and (-not $SecurityOnly -and -not $FeatureUpdatesOnly)) {
                            Write-Log "Found $($nonSecurityUpdates.Count) non-security updates:" -Verbose
                            foreach ($update in $nonSecurityUpdates) {
                                Write-Log "Non-Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                            }
                            $installNonSecurity = if ($NonInteractive -or $DebugMode -or [Console]::IsInputRedirected) { 'Y' } else { Read-Host "Install non-security updates? (Y/N)" }
                            if ($installNonSecurity -eq 'Y' -or $installNonSecurity -eq 'y') {
                                Write-Progress -Activity "Installing non-security updates" -Status "Starting..."
                                Install-WindowsUpdate -KBArticleID ($nonSecurityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop -Verbose | Out-Null
                                $successfullyInstalledUpdates = $true
                                $installSummary += "Installed $($nonSecurityUpdates.Count) non-security updates"
                                Write-Progress -Activity "Installing non-security updates" -Completed
                            } else {
                                Write-Log "Non-security updates skipped." -Verbose
                            }
                        }
                    } else {
                        Write-Log "No updates matching specified criteria." -Verbose
                        break
                    }
                } else {
                    Write-Log "No Windows updates to install via PSWindowsUpdate." -Verbose
                    break
                }
            } catch {
                Write-Log "Error: Failed to install Windows updates: $($_.Exception.Message)"
                $failedUpdates += "Failed Windows updates: $($_.Exception.Message)"
                try {
                    Write-Log "Attempting to uninstall problematic updates..." -Verbose
                    $history = Get-WUHistory -Last 10 | Where-Object { $_.Result -eq "Failed" }
                    foreach ($update in $history) {
                        Uninstall-WindowsUpdate -KBArticleID $update.KB -ErrorAction Stop
                        Write-Log "Uninstalled problematic update: $($update.KB)" -Verbose
                    }
                } catch {
                    Write-Log "Warning: Failed to uninstall updates: $($_.Exception.Message)" -Verbose
                }
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
                $securityUpdates = $searchResult.Updates | Where-Object { $_.Categories | Where-Object { $_.Name -match "Security Updates|Definition Updates" } }
                $otherUpdates = $searchResult.Updates | Where-Object { $_.Categories | Where-Object { $_.Name -notmatch "Security Updates|Definition Updates" } }
                if ($securityUpdates -and (-not $FeatureUpdatesOnly -and -not $NonSecurityOnly)) {
                    Write-Log "Installing $($securityUpdates.Count) security updates via COM..." -Verbose
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $securityUpdates
                    $installResult = $installer.Install()
                    Write-Log "COM-based security update installation result: $($installResult.ResultCode)" -Verbose
                    $installSummary += "Installed $($securityUpdates.Count) security updates via COM"
                    $successfullyInstalledUpdates = $true
                }
                if ($otherUpdates -and (-not $SecurityOnly -and -not $FeatureUpdatesOnly) -and ($NonInteractive -or $DebugMode -or [Console]::IsInputRedirected)) {
                    Write-Log "Installing $($otherUpdates.Count) non-security updates via COM..." -Verbose
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $otherUpdates
                    $installResult = $installer.Install()
                    Write-Log "COM-based non-security update installation result: $($installResult.ResultCode)" -Verbose
                    $installSummary += "Installed $($otherUpdates.Count) non-security updates via COM"
                    $successfullyInstalledUpdates = $true
                } else {
                    Write-Log "Skipped $($otherUpdates.Count) non-security updates via COM." -Verbose
                }
            } else {
                Write-Log "No updates found via COM-based Windows Update." -Verbose
            }
        } catch {
            Write-Log "Error: COM-based update failed: $($_.Exception.Message)"
            $failedUpdates += "COM-based update failed: $($_.Exception.Message)"
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
    }

    # Update Microsoft Store apps
    if (-not $NonInteractive) {
        Write-Log "Updating Microsoft Store apps..." -Verbose
        try {
            $namespace = "root\cimv2\mdm\dmmap"
            $class = "MDM_EnterpriseModernAppManagement_AppManagement01"
            $session = Get-CimInstance -Namespace $namespace -ClassName $class -ErrorAction Stop
            $result = $session | Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop
            if ($result.ReturnValue -eq 0) {
                Write-Log "Microsoft Store app updates triggered successfully." -Verbose
                $installSummary += "Triggered Microsoft Store app updates"
            } else {
                Write-Log "Warning: Store update scan failed with code: $($result.ReturnValue)" -Verbose
                $failedUpdates += "Store update scan failed: $($result.ReturnValue)"
            }
        } catch {
            Write-Log "Warning: Failed to update Microsoft Store apps: $($_.Exception.Message)" -Verbose
            $failedUpdates += "Failed to update Microsoft Store apps: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Skipping Microsoft Store updates." -Verbose
    }

    # Check for pending reboot
    Write-Log "Checking for pending reboot..." -Verbose
    $rebootRequired = $false
    try {
        $lastBoot = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
        if ($uptime.Days -ge 30) {
            Write-Log "System uptime: $($uptime.Days) days. Reboot recommended." -Verbose
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

    # Initialize Event Log source
    if (-not [System.Diagnostics.EventLog]::SourceExists("System Update Script")) {
        New-EventLog -LogName Application -Source "System Update Script" -ErrorAction SilentlyContinue
    }

    if ($rebootRequired) {
        Write-Log "Reboot required to complete update installation." -Verbose
        if ($NonInteractive -or $DebugMode -or [Console]::IsInputRedirected) {
            Write-Log "Non-interactive mode: Skipping reboot." -Verbose
            Write-Output "A reboot is required to complete update installation. Please reboot manually."
            try {
                Add-Type -AssemblyName System.Runtime.WindowsRuntime
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
                    Add-Type -AssemblyName System.Windows.Forms
                    [System.Windows.Forms.MessageBox]::Show("A reboot is required to complete updates. Please reboot soon.", "System Update", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    Write-Log "Sent fallback message box for pending reboot." -Verbose
                } catch {
                    Write-Log "Warning: Failed to send fallback message box: $($_.Exception.Message)" -Verbose
                    try {
                        Write-EventLog -LogName Application -Source "System Update Script" -EntryType Warning -EventId 1 -Message "A reboot is required to complete updates. Please reboot soon." -ErrorAction Stop
                        Write-Log "Wrote to Event Log for pending reboot." -Verbose
                    } catch {
                        Write-Log "Error: Failed to write to Event Log: $($_.Exception.Message)" -Verbose
                    }
                }
            }
        } else {
            Write-Log "Prompting for reboot..." -Verbose
            $response = Read-Host "A reboot is required to complete update installation. Reboot now? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "Rebooting now..." -Verbose
                Restart-Computer -Force
                exit 0
            } else {
                Write-Log "Reboot deferred." -Verbose
            }
        }
    } else {
        Write-Log "No reboot required." -Verbose
    }

    # Cleanup old logs
    Write-Log "Cleaning up old logs..." -Verbose
    try {
        Get-ChildItem -Path $logDir -Filter "*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $env:TEMP -Filter "UpdateScript_Fallback_*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Old logs cleaned up successfully." -Verbose
    } catch {
        Write-Log "Warning: Failed to clean up old logs: $($_.Exception.Message)" -Verbose
    }

    # Send failure report email (disabled until configured)
    # if ($failedUpdates) {
    #     try {
    #         $smtpParams = @{
    #             SmtpServer = "smtp.example.com"
    #             From = "script@example.com"
    #             To = "admin@example.com"
    #             Subject = "UpdateSystem.ps1 Failure Report"
    #             Body = "Failed updates:\n$($failedUpdates | Out-String)"
    #         }
    #         Send-MailMessage @smtpParams -ErrorAction Stop
    #         Write-Log "Sent failure report email." -Verbose
    #     } catch {
    #         Write-Log "Warning: Failed to send failure report email: $($_.Exception.Message)" -Verbose
    #     }
    # }

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
        Write-Log "Error: Critical failure detected. Exiting with code 1." -Verbose
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
        Write-Log "Transcript stopped successfully." -Verbose
    } catch {
        [System.IO.File]::AppendAllText($fallbackLogFile, "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to stop transcript: $($_.Exception.Message)`n")
    }
    exit 0
}
