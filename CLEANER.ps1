# Run as Administrator

Write-Output "Clearing system..."

# Function to safely delete registry keys/values
function Remove-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

# --- Clear Run Dialog History ---
Remove-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" "*"

# --- Clear Open/Save Dialog History ---
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" -Recurse -Force -ErrorAction SilentlyContinue

# --- Clear PowerShell History ---
$psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistory) { Remove-Item $psHistory -Force -ErrorAction SilentlyContinue }

# --- Clear CMD History ---
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" -Name "AutoRun" -ErrorAction SilentlyContinue

# --- Clear Explorer Typed Paths ---
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name * -ErrorAction SilentlyContinue

# --- Clear Recently Used Files (Recent Items) ---
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) { Remove-Item "$recentPath\*" -Force -ErrorAction SilentlyContinue }

# --- Clear Quick Access and Jump List History ---
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Force -ErrorAction SilentlyContinue

# --- Clear Thumbnail Cache ---
$thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
Get-ChildItem $thumbCache -Include "*thumbcache*" -File -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# --- Clear Prefetch Files ---
$prefetchPath = "C:\Windows\Prefetch"
if (Test-Path $prefetchPath) { Remove-Item "$prefetchPath\*" -Force -ErrorAction SilentlyContinue }

# --- Clear Temp Files ---
Get-ChildItem "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- Clear USB History ---
$usbPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
    "HKLM:\SYSTEM\CurrentControlSet\Enum\USB",
    "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
)
foreach ($path in $usbPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Clear Windows Search History ---
Remove-Item "$env:APPDATA\Microsoft\Windows\Search\Data\Applications\Windows\*.db" -Force -ErrorAction SilentlyContinue

# --- (Optional) Clear Event Logs ---
# Uncomment if you want to wipe logs
# wevtutil el | ForEach-Object { wevtutil cl "$_" }

Write-Output "cleanup completed successfully."
