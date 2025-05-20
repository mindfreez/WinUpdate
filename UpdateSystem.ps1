# UpdateSystem.ps1
# Requires -RunAsAdministrator

param (
    [switch]$DebugMode
)

$logDir = "$env:ProgramData\SystemUpdateScript\Logs"
$logFile = "$logDir\UpdateScript_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$fallbackLogFile = "$env:TEMP\UpdateScript_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$failedUpdates = @()
$installSummary = @()
$psWindowsUpdateAvailable = $false
$successfullyInstalledUpdates = $false

# Ensure log directory exists
try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to create log directory $logDir : $($_.Exception.Message)"
}

# Start transcript
try {
    Start-Transcript -Path $logFile -Append -Force -ErrorAction Stop
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to start transcript for $logFile : $($_.Exception.Message)"
}

function Write-Log {
    param($Message, [switch]$Verbose)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Output $logMessage
    if ($Verbose -or $DebugMode) {
        [Console]::WriteLine($logMessage)
    }
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    } catch {
        Add-Content -Path $fallbackLogFile -Value $logMessage
    }
}

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

try {
    # Detect PC Model and OS Details
    Write-Log "Detecting system information..." -Verbose
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $pcModel = "$($computerSystem.Manufacturer) $($computerSystem.Model)"
        $osName = $osInfo.Caption
        # Fallback for OS edition if OSEdition is not available
        $osEdition = if ($osInfo.OSEdition) { $osInfo.OSEdition } else { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID").EditionID }
        $osVersion = $osInfo.Version
        $osBuild = $osInfo.BuildNumber
        Write-Log "PC Model: $pcModel" -Verbose
        Write-Log "OS: $osName (Edition: $osEdition, Version: $osVersion, Build: $osBuild)" -Verbose
    } catch {
        Write-Log "Warning: Failed to detect system information: $($_.Exception.Message)" -Verbose
    }

    Write-Log "Checking for PSWindowsUpdate module..." -Verbose
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Installing PSWindowsUpdate module..." -Verbose
            Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $psWindowsUpdateAvailable = $true
        Write-Log "PSWindowsUpdate module ready." -Verbose
    } catch {
        Write-Log "Error: Failed to install/import PSWindowsUpdate module: $($_.Exception.Message)"
        $failedUpdates += "Failed to install/import module PSWindowsUpdate: $($_.Exception.Message)"
    }

    if ($psWindowsUpdateAvailable) {
        Write-Log "Checking for Windows updates (including Defender definitions)..." -Verbose
        try {
            Write-Log "Running Get-WindowsUpdate..." -Verbose
            $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop

            if ($updates) {
                # Separate security and non-security updates
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

                # Install security updates automatically
                if ($securityUpdates) {
                    Write-Log "Found $($securityUpdates.Count) security updates to install automatically:" -Verbose
                    foreach ($update in $securityUpdates) {
                        Write-Log "Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                    }
                    Write-Progress -Activity "Installing security updates" -Status "Starting..."
                    Install-WindowsUpdate -KBArticleID ($securityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | ForEach-Object {
                        Write-Log "Install-WindowsUpdate Output: $_" -Verbose
                    }
                    $successfullyInstalledUpdates = $true
                    $installSummary += "Installed $($securityUpdates.Count) security updates (including Defender definitions)"
                    Write-Progress -Activity "Installing security updates" -Completed
                } else {
                    Write-Log "No security updates to install via PSWindowsUpdate." -Verbose
                }

                # Prompt for non-security updates
                if ($nonSecurityUpdates) {
                    Write-Log "Found $($nonSecurityUpdates.Count) non-security updates available:" -Verbose
                    foreach ($update in $nonSecurityUpdates) {
                        Write-Log "Non-Security Update: $($update.Title) (KB$($update.KBArticleIDs))" -Verbose
                    }
                    if ($DebugMode) {
                        Write-Log "Debug mode: Skipping non-security update prompt. Assuming 'Yes' for installation." -Verbose
                        $installNonSecurity = 'Y'
                    } else {
                        Write-Log "Prompting user for non-security update installation..." -Verbose
                        $installNonSecurity = Read-Host "Non-security updates are available. Install them now? (Y/N)"
                    }
                    if ($installNonSecurity -eq 'Y' -or $installNonSecurity -eq 'y') {
                        Write-Progress -Activity "Installing non-security updates" -Status "Starting..."
                        Install-WindowsUpdate -KBArticleID ($nonSecurityUpdates | ForEach-Object { $_.KBArticleIDs }) -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | ForEach-Object {
                            Write-Log "Install-WindowsUpdate Output: $_" -Verbose
                        }
                        $successfullyInstalledUpdates = $true
                        $installSummary += "Installed $($nonSecurityUpdates.Count) non-security updates"
                        Write-Progress -Activity "Installing non-security updates" -Completed
                    } else {
                        Write-Log "User declined installation of non-security updates." -Verbose
                    }
                } else {
                    Write-Log "No non-security updates to install via PSWindowsUpdate." -Verbose
                }
            } else {
                Write-Log "No Windows updates to install via PSWindowsUpdate." -Verbose
            }
        } catch {
            Write-Log "Error: Failed to install Windows updates: $($_.Exception.Message)"
            $failedUpdates += "Failed Windows updates: $($_.Exception.Message)"
        }
    } else {
        Write-Log "PSWindowsUpdate unavailable. Skipping Windows updates." -Verbose
    }

    # Explicitly check for Microsoft Defender updates
    Write-Log "Checking for Microsoft Defender definition updates..." -Verbose
    try {
        Import-Module -Name Defender -ErrorAction Stop
        Write-Log "Running Update-MpSignature to update Defender definitions..." -Verbose
        Update-MpSignature -ErrorAction Stop
        Write-Log "Microsoft Defender definitions updated successfully." -Verbose
        $installSummary += "Updated Microsoft Defender definitions"
    } catch {
        Write-Log "Warning: Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
        $failedUpdates += "Failed to update Microsoft Defender definitions: $($_.Exception.Message)"
    }

    # Check for non-Store app updates via winget
    Write-Log "Checking for non-Store app updates via winget..." -Verbose
    try {
        # Log winget version for debugging
        $wingetVersion = (winget --version) -replace '^v', ''
        Write-Log "winget version: $wingetVersion" -Verbose

        # Check winget version for compatibility
        if ($wingetVersion -lt "1.2") {
            Write-Log "Warning: winget version $wingetVersion may lack features required for reliable updates. Consider updating winget." -Verbose
        }

        # Ensure no background winget processes are running
        Write-Log "Checking for existing winget processes..." -Verbose
        $wingetProcess = Get-Process -Name "winget" -ErrorAction SilentlyContinue
        if ($wingetProcess) {
            Write-Log "Found existing winget process (PID: $($wingetProcess.Id)). Terminating..." -Verbose
            Stop-Process -Name "winget" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
        }

        # Run winget upgrade
        Write-Log "Running winget upgrade..." -Verbose
        $wingetOutput = winget upgrade --source winget --accept-source-agreements --include-unknown | Out-String
        $wingetLogFile = "$logDir\winget_raw_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Add-Content -Path $wingetLogFile -Value $wingetOutput -ErrorAction SilentlyContinue
        Write-Log "Raw winget output saved to: $wingetLogFile" -Verbose

        if ($wingetOutput -match "No installed package found matching input criteria" -or $wingetOutput -match "No applicable updates found") {
            Write-Log "No non-Store app updates available." -Verbose
        } else {
            $updatesList = @()
            $lines = $wingetOutput -split "`n"
            $parsingUpdates = $false
            foreach ($line in $lines) {
                $line = $line.Trim()
                # Skip progress bars, empty lines, or non-update lines
                if ($line -match "^[\sΓûêΓûÆ-]+" -or $line -eq "" -or $line -like "*KB / *" -or $line -like "*%") {
                    continue
                }
                # Detect start of updates table (after header separator)
                if ($line -like "*---*") {
                    $parsingUpdates = $true
                    continue
                }
                # Parse update lines after header
                if ($parsingUpdates -and $line -match "^(.+?)\s{2,}(.+?)\s{2,}(.+?)\s{2,}(.+?)$" -and $matches) {
                    $name = $matches[1].Trim()
                    $id = $matches[2].Trim()
                    $currentVersion = $matches[3].Trim()
                    $availableVersion = $matches[4].Trim()
                    Write-Log "Debug: Parsed line - Name: '$name', ID: '$id', Current: '$currentVersion', Available: '$availableVersion'" -Verbose
                    # Skip header or invalid lines
                    if ($name -and $id -and $name -notmatch "^Name$" -and $id -notmatch "^Id$" -and $id -match "^[\w\.]+" -and $line -notmatch "upgrades available" -and $line -notmatch "package\(s\) have version numbers") {
                        $updatesList += [PSCustomObject]@{
                            Name = $name
                            Id = $id
                            CurrentVersion = $currentVersion
                            AvailableVersion = $availableVersion
                        }
                    }
                }
            }
            if ($updatesList.Count -gt 0) {
                Write-Log "Found $($updatesList.Count) non-Store app updates to install:" -Verbose
                foreach ($update in $updatesList) {
                    Write-Log "Name: $($update.Name), ID: $($update.Id), Current: $($update.CurrentVersion), Available: $($update.AvailableVersion)" -Verbose
                }
                $index = 0
                foreach ($update in $updatesList) {
                    Write-Progress -Activity "Installing non-Store app updates" -Status "Update $index of $($updatesList.Count) ($($update.Name))" -PercentComplete (($index / $updatesList.Count) * 100)
                    $retryCount = 0
                    $maxRetries = 2
                    $success = $false
                    while ($retryCount -lt $maxRetries -and -not $success) {
                        try {
                            Write-Log "Attempting to install $($update.Name) ($($update.Id))..." -Verbose
                            $installOutput = winget upgrade --id $update.Id --source winget --accept-source-agreements --accept-package-agreements --exact --force --silent --timeout 300 | Out-String
                            Write-Log "Installed $($update.Name) ($($update.Id)): $installOutput" -Verbose
                            $installSummary += "Installed non-Store update: $($update.Name) ($($update.Id))"
                            $success = $true
                        } catch {
                            $retryCount++
                            Write-Log "Warning: Failed to install $($update.Name) ($($update.Id)) (Attempt $retryCount/$maxRetries): $($_.Exception.Message)" -Verbose
                            if ($retryCount -eq $maxRetries) {
                                Write-Log "Error: Max retries reached for $($update.Name) ($($update.Id))." -Verbose
                                $failedUpdates += "Failed non-Store update $($update.Id): $($_.Exception.Message)"
                            }
                            Start-Sleep -Seconds 5
                        }
                    }
                    $index++
                }
                Write-Progress -Activity "Installing non-Store app updates" -Completed
            } else {
                Write-Log "No valid non-Store app updates parsed from winget output." -Verbose
            }
        }
    } catch {
        Write-Log "Warning: Failed to process non-Store app updates: $($_.Exception.Message)" -Verbose
        $failedUpdates += "Failed non-Store app updates: $($_.Exception.Message)"
    }

    # Firefox fallback if winget update fails
    if ($failedUpdates -match "Mozilla.Firefox") {
        Write-Log "Attempting Firefox internal updater as fallback..." -Verbose
        try {
            $firefoxPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe" -ErrorAction SilentlyContinue)."(default)"
            if ($firefoxPath) {
                Start-Process -FilePath $firefoxPath -ArgumentList "--check-for-update" -ErrorAction Stop
                Write-Log "Launched Firefox internal updater." -Verbose
            } else {
                Write-Log "Warning: Firefox executable not found for fallback update." -Verbose
            }
        } catch {
            Write-Log "Warning: Failed to launch Firefox updater: $($_.Exception.Message)" -Verbose
        }
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

            $waitSeconds = 300  # 5 minutes
            if (-not $DebugMode) {
                Write-Log "Waiting $waitSeconds seconds for Microsoft Store updates (non-Debug mode)..." -Verbose
                Start-Sleep -Seconds $waitSeconds
                Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
                Write-Log "Microsoft Store closed after fixed wait." -Verbose
                $installSummary += "Completed Microsoft Store app updates via Store UI"
            } else {
                # Debug mode: Allow extended wait with user prompt
                Write-Log "Waiting $waitSeconds seconds for Microsoft Store updates to complete..." -Verbose
                Start-Sleep -Seconds $waitSeconds
                $storeProcess = Get-Process -Name "WinStore.App" -ErrorAction SilentlyContinue
                $extendWait = $false
                if ($storeProcess) {
                    Write-Log "Debug mode: Assuming user wants to extend wait for Microsoft Store updates." -Verbose
                    $extendWait = $true
                }
                if ($extendWait) {
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
            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Skipping Microsoft Store updates due to critical PSWindowsUpdate failure." -Verbose
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
        if ($DebugMode) {
            Write-Log "Debug mode: Skipping reboot prompt for visibility." -Verbose
            [Console]::WriteLine("A reboot is required to complete update installation. Please reboot manually.")
        } else {
            Write-Log "Prompting for reboot confirmation..." -Verbose
            $response = Read-Host "A reboot is required to complete update installation. Reboot now? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "User confirmed reboot. Rebooting now..." -Verbose
                Stop-LockingProcesses
                Restart-Computer -Force
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
        Get-ChildItem -Path $logDir -Filter "UpdateScript_Transcript_*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Old logs cleaned up." -Verbose
    } catch {
        Write-Log "Warning: Failed to clean up old logs: $($_.Exception.Message)"
    }

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
        throw "Critical failure: PSWindowsUpdate module issue"
    }

    Write-Log "Script completed." -Verbose
}
catch {
    Write-Log "Critical error in script: $($_.Exception.Message)" -Verbose
    $failedUpdates += "Critical script error: $($_.Exception.Message)"
}
finally {
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {
        Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to stop transcript: $($_.Exception.Message)"
    }
    if ($DebugMode) {
        Write-Log "Debug mode: Script execution complete." -Verbose
    }
}
