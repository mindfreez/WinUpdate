# Ensure script runs as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Relaunching as Administrator..."
    $logFile = "C:\Logs\WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Output "$(Get-Date): Relaunching as Administrator" | Out-File -FilePath $logFile -Append
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Log file setup
$logFile = "C:\Logs\WindowsUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Write-Output "$(Get-Date): Script started" | Out-File -FilePath $logFile -Append

# Check PowerShell version and handle PowerShell 7 installation/upgrade
$currentPSVersion = $PSVersionTable.PSVersion.Major
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"

if ($currentPSVersion -lt 7) {
    # Check if PowerShell 7 is installed
    if (Test-Path $pwshPath) {
        Write-Output "$(Get-Date): PowerShell 7 detected, checking version..." | Out-File -FilePath $logFile -Append
        $pwshVersion = & $pwshPath -Command '$PSVersionTable.PSVersion.ToString()'
        $latestPwshVersion = (Invoke-WebRequest -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing | ConvertFrom-Json).tag_name.TrimStart('v')

        if ([version]$pwshVersion -lt [version]$latestPwshVersion) {
            Write-Output "$(Get-Date): Upgrading PowerShell 7 from $pwshVersion to $latestPwshVersion" | Out-File -FilePath $logFile -Append
            # Download and install latest PowerShell 7
            $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestPwshVersion/PowerShell-$latestPwshVersion-win-x64.msi"
            $installerPath = "$env:TEMP\PowerShell-$latestPwshVersion.msi"
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $installerPath /quiet /norestart" -Wait
            Write-Output "$(Get-Date): PowerShell 7 upgraded to $latestPwshVersion" | Out-File -FilePath $logFile -Append
        }
        # Relaunch in PowerShell 7
        Write-Output "$(Get-Date): Relaunching in PowerShell 7" | Out-File -FilePath $logFile -Append
        Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    } else {
        Write-Output "$(Get-Date): PowerShell 7 not installed, installing latest version..." | Out-File -FilePath $logFile -Append
        # Install PowerShell 7
        $latestPwshVersion = (Invoke-WebRequest -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing | ConvertFrom-Json).tag_name.TrimStart('v')
        $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestPwshVersion/PowerShell-$latestPwshVersion-win-x64.msi"
        $installerPath = "$env:TEMP\PowerShell-$latestPwshVersion.msi"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $installerPath /quiet /norestart" -Wait
        Write-Output "$(Get-Date): PowerShell 7 installed" | Out-File -FilePath $logFile -Append
        # Relaunch in PowerShell 7
        Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
} else {
    Write-Output "$(Get-Date): Running in PowerShell 7 ($($PSVersionTable.PSVersion.ToString()))" | Out-Fil
e -FilePath $logFile -Append
}

# Install PSWindowsUpdate module if not present
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Output "$(Get-Date): Installing PSWindowsUpdate module..." | Out-File -FilePath $logFile -Append
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Verbose *>> $logFile
}

Import-Module PSWindowsUpdate

# Check and install security updates
Write-Output "$(Get-Date): Checking for security updates..." | Out-File -FilePath $logFile -Append
$updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Download -Install -AutoReboot:$false -Category "Security Updates" -Verbose *>> $logFile

if ($updates) {
    Write-Output "$(Get-Date): Security updates installed" | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$(Get-Date): No security updates available" | Out-File -FilePath $logFile -Append
}

# Check if reboot is required
$rebootRequired = Get-WURebootStatus -Silent
if ($rebootRequired) {
    Write-Output "$(Get-Date): Reboot required after update installation" | Out-File -FilePath $logFile -Append
    # Prompt user for reboot
    $title = "Windows Update"
    $message = "A reboot is required to complete the update installation. Reboot now?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Reboot now"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Reboot later"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.UI.PromptForChoice($title, $message, $options, 0)

    if ($result -eq 0) {
        Write-Output "$(Get-Date): User chose to reboot now" | Out-File -FilePath $logFile -Append
        Restart-Computer -Force
    } else {
        Write-Output "$(Get-Date): User chose to reboot later" | Out-File -FilePath $logFile -Append
    }
} else {
    Write-Output "$(Get-Date): No reboot required" | Out-File -FilePath $logFile -Append
}

Write-Output "$(Get-Date): Script completed" | Out-File -FilePath $logFile -Append
