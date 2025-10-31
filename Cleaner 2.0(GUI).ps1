# ============================================================
# Windows Cleanup Tool (Auto-Elevated)
# ============================================================

# --- Auto Elevate if not running as Administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Write-Host "Requesting administrative privileges..."
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Create form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Cleanup Tool"
$form.Size = New-Object System.Drawing.Size(400, 580)
$form.StartPosition = "CenterScreen"

# --- Define checkboxes ---
$checkboxes = @()
$tasks = @(
    "Clear Run Dialog History",
    "Clear Open/Save Dialog History",
    "Clear PowerShell History",
    "Clear CMD History",
    "Clear Explorer Typed Paths",
    "Clear Recent Items",
    "Clear Quick Access / Jump Lists",
    "Clear Thumbnail Cache",
    "Clear Prefetch Files",
    "Clear Temp Files",
    "Clear USB History",
    "Clear Windows Search History",
    "Clear Event Logs",
    "Clear ConHost History"
)

# --- Add checkboxes dynamically ---
for ($i = 0; $i -lt $tasks.Count; $i++) {
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $tasks[$i]
    $cb.AutoSize = $true
    $cb.Location = New-Object System.Drawing.Point(20, (20 + ($i * 25)))
    $form.Controls.Add($cb)
    $checkboxes += $cb
}

# --- Add Progress Bar ---
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0
$progressBar.Size = New-Object System.Drawing.Size(340, 20)
$progressBar.Location = New-Object System.Drawing.Point(20, 400)
$form.Controls.Add($progressBar)

# --- Add Output Label ---
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = ""
$outputLabel.AutoSize = $true
$outputLabel.Location = New-Object System.Drawing.Point(20, 430)
$form.Controls.Add($outputLabel)

# --- Add Run Button ---
$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = "Run Cleanup"
$runButton.Width = 100
$runButton.Height = 30
$runButton.Location = New-Object System.Drawing.Point(140, 480)
$form.Controls.Add($runButton)

# ============================================================
# Cleanup logic
# ============================================================
$runButton.Add_Click({
    $runButton.Enabled = $false
    foreach ($cb in $checkboxes) { $cb.Enabled = $false }
    $outputLabel.Text = "Running cleanup..."
    $form.Refresh()

    function Remove-RegistryValue {
        param ([string]$Path, [string]$Name)
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        }
    }

    $selected = $checkboxes | Where-Object { $_.Checked }
    $total = $selected.Count
    if ($total -eq 0) {
        $outputLabel.Text = "No cleanup options selected."
        foreach ($cb in $checkboxes) { $cb.Enabled = $true }
        $runButton.Enabled = $true
        return
    }

    # Handle ConHost separately (run last)
    $conHostSelected = $checkboxes[13].Checked
    if ($conHostSelected) { $total -= 1 }

    $step = if ($total -gt 0) { [math]::Floor(100 / ($total + 1)) } else { 100 }
    $progressBar.Value = 0

    # --- Run all except ConHost cleanup first ---
    for ($i = 0; $i -lt $checkboxes.Count; $i++) {
        if (-not $checkboxes[$i].Checked -or $i -eq 13) { continue }

        switch ($i) {
            0 { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue }
            1 { Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" -Recurse -Force -ErrorAction SilentlyContinue }
            2 { $psHistories = @(
                    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
                    "$env:USERPROFILE\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
                )
                foreach ($file in $psHistories) { if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue } } }
            3 { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" -Name "AutoRun" -ErrorAction SilentlyContinue }
            4 { $typedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
                if (Test-Path $typedPath) {
                    Get-ItemProperty -Path $typedPath | ForEach-Object {
                        $_.PSObject.Properties.Name | ForEach-Object {
                            if ($_ -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                                Remove-ItemProperty -Path $typedPath -Name $_ -ErrorAction SilentlyContinue
                            }
                        }
                    }
                } }
            5 { $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
                if (Test-Path $recentPath) { Remove-Item "$recentPath\*" -Force -ErrorAction SilentlyContinue } }
            6 { Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Force -ErrorAction SilentlyContinue }
            7 { $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
                Get-ChildItem $thumbCache -Include "*thumbcache*" -File -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
            8 { $prefetchPath = "C:\Windows\Prefetch"
                if (Test-Path $prefetchPath) { Remove-Item "$prefetchPath\*" -Force -ErrorAction SilentlyContinue } }
            9 { Get-ChildItem "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Get-ChildItem "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
            10 { $usbPaths = @("HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR","HKLM:\SYSTEM\CurrentControlSet\Enum\USB","HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR")
                 foreach ($path in $usbPaths) { if (Test-Path $path) { Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } } }
            11 { Remove-Item "$env:APPDATA\Microsoft\Windows\Search\Data\Applications\Windows\*.db" -Force -ErrorAction SilentlyContinue }
            12 { Start-Process -FilePath "cmd.exe" -ArgumentList '/c for /F "tokens=*" %1 in (''wevtutil.exe el'') DO wevtutil.exe cl "%1"' -Verb RunAs -WindowStyle Hidden -Wait }
        }

        $progressBar.Value = [math]::Min(100, $progressBar.Value + $step)
        $form.Refresh()
        Start-Sleep -Milliseconds 300
    }

    # --- Run Clear ConHost History last (if selected) ---
    if ($conHostSelected) {
        $outputLabel.Text = "Finalizing: Clearing ConHost History..."
        $form.Refresh()

        $historyPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
        if (Test-Path $historyPath) {
            Remove-Item $historyPath -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Stop other PowerShell and ConHost instances (except this one)
        Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
        Get-Process -Name "conhost" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                if ($_.Parent.Id -ne $PID) {
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue | Out-Null
                }
            } catch {}
        }

        # Recreate empty history file
        if (-not (Test-Path $historyPath)) {
            New-Item -Path $historyPath -ItemType File -Force | Out-Null
        } else {
            Set-Content -Path $historyPath -Value "" -Force -ErrorAction SilentlyContinue
        }

        $progressBar.Value = 100
    }

    $outputLabel.Text = "Cleanup completed successfully."
    foreach ($cb in $checkboxes) { $cb.Enabled = $true }
    $runButton.Enabled = $true
})

# --- Show form ---
[void]$form.ShowDialog()
