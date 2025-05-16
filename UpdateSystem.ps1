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

try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Add-Content -Path $fallbackLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error: Failed to create log directory $logDir : $($_.Exception.Message)"
}

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
        Write-Log "Checking for Windows updates..." -Verbose
        try {
            Write-Log "Running Get-WindowsUpdate..." -Verbose
            $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -ErrorAction Stop
            if ($updates) {
                Write-Log "Found $($updates.Count) Windows updates to install." -Verbose
                Write-Progress -Activity "Installing Windows updates" -Status "Starting..."
                Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | ForEach-Object { Write-Log $_ -Verbose }
                $successfullyInstalledUpdates = $true
                $installSummary += "Installed $($updates.Count) Windows updates"
                Write-Progress -Activity "Installing Windows updates" -Completed
            } else {
                Write-Log "No Windows updates to install." -Verbose
            }
        } catch {
            Write-Log "Error: Failed to install Windows updates: $($_.Exception.Message)"
            $failedUpdates += "Failed Windows updates: $($_.Exception.Message)"
        }
    } else {
        Write-Log "PSWindowsUpdate unavailable. Skipping Windows updates." -Verbose
    }

    Write-Log "Checking for non-Store app updates via winget..." -Verbose
    try {
        $wingetOutput = winget upgrade --source winget --accept-source-agreements | Out-String
        Write-Log "Raw winget upgrade output: $wingetOutput"
        if ($wingetOutput -match "No applicable updates found") {
            Write-Log "No non-Store app updates available." -Verbose
        } else {
            $updatesList = $wingetOutput -split "`n" | ForEach-Object {
                $line = $_.Trim()
                if ($line -match "^(.+?)\s{2,}(.+?)\s{2,}(.+?)\s{2,}(.+?)$" -and $matches) {
                    $name = if ($matches[1]) { $matches[1].Trim() } else { $null }
                    $id = if ($matches[2]) { $matches[2].Trim() } else { $null }
                    if ($name -and $id -and $name -notmatch "^Name$" -and $id -notmatch "^Id$" -and $id -match "^[\w\.]+" -and $name -notlike "*---*") {
                        [PSCustomObject]@{
                            Name = $name
                            Id   = $id
                            CurrentVersion = if ($matches[3]) { $matches[3].Trim() } else { "Unknown" }
                            AvailableVersion = if ($matches[4]) { $matches[4].Trim() } else { "Unknown" }
                        }
                    }
                }
            } | Where-Object { $_ -ne $null }
            if ($updatesList) {
                Write-Log "Parsed non-Store app updates:" -Verbose
                foreach ($update in $updatesList) {
                    Write-Log "Name: $($update.Name), ID: $($update.Id), Current: $($update.CurrentVersion), Available: $($update.AvailableVersion)" -Verbose
                }
                Write-Log "Found $($updatesList.Count) non-Store app updates to install." -Verbose
                $index = 0
                foreach ($update in $updatesList) {
                    Write-Progress -Activity "Installing non-Store app updates" -Status "Update $index of $($updatesList.Count)" -PercentComplete (($index / $updatesList.Count) * 100)
                    try {
                        $installOutput = winget upgrade --id $update.Id --source winget --accept-source-agreements --accept-package-agreements --exact --force --silent | Out-String
                        Write-Log "Installed $($update.Name) ($($update.Id)): $installOutput" -Verbose
                        $installSummary += "Installed non-Store update: $($update.Name) ($($update.Id))"
                    } catch {
                        Write-Log "Warning: Failed to install $($update.Name) ($($update.Id)): $($_.Exception.Message)"
                        $failedUpdates += "Failed non-Store update $($update.Id): $($_.Exception.Message)"
                    }
                    $index++
                }
                Write-Progress -Activity "Installing non-Store app updates" -Completed
            } else {
                Write-Log "No valid non-Store app updates parsed from winget output." -Verbose
            }
        }
    } catch {
        Write-Log "Warning: Failed to process non-Store app updates: $($_.Exception.Message)"
        $failedUpdates += "Failed non-Store app updates: $($_.Exception.Message)"
    }

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
            Start-Sleep -Seconds 120
            try {
                Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
                Write-Log "Microsoft Store closed after update wait." -Verbose
                $installSummary += "Completed Microsoft Store app updates via Store UI"
            } catch {
                Write-Log "Warning: Failed to close Microsoft Store: $($_.Exception.Message)"
            }
        } catch {
            Write-Log "Warning: Failed to update Microsoft Store apps: $($_.Exception.Message). Leaving Store open." -Verbose
            $failedUpdates += "Failed to update Microsoft Store apps: $($_.Exception.Message)"
            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Skipping Microsoft Store updates due to critical PSWindowsUpdate failure." -Verbose
    }

    Write-Log "Checking for pending reboot..." -Verbose
    $rebootRequired = $false
    try {
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

    if ($rebootRequired -and $successfullyInstalledUpdates) {
        Write-Log "Critical updates installed. Reboot required." -Verbose
        if ($DebugMode) {
            Write-Log "Debug mode: Skipping automatic reboot prompt for visibility." -Verbose
            [Console]::WriteLine("A reboot is required to complete update installation. Please reboot manually.")
        } else {
            Write-Log "Interactive mode: Prompting for reboot confirmation..." -Verbose
            $response = Read-Host "A reboot is required to complete update installation. Reboot now? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "User confirmed reboot. Rebooting now..." -Verbose
                Stop-LockingProcesses
                Restart-Computer -Force
            } else {
                Write-Log "User deferred reboot. Reboot required to complete updates." -Verbose
            }
        }
    } elseif ($rebootRequired) {
        Write-Log "Pending reboot detected, but no critical updates installed. Reboot recommended." -Verbose
    } else {
        Write-Log "No reboot required." -Verbose
    }

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
        [Console]::WriteLine("Script execution complete. Press any key to continue...")
        $null = Read-Host
    }
}
