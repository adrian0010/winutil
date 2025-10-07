# Windows Utility Script
# --- Elevation Check: restart as admin if not already ---
# Handle both local and remote invocations for elevation
$scriptUrl = 'https://raw.githubusercontent.com/adrian0010/winutil/refs/heads/main/install-apps.ps1'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSCommandPath) {
        $argList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $PSCommandPath
        )
    } else {
        $argList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-Command', "iex (irm '$scriptUrl')"
        )
    }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    exit
}


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- App install map (order matters) ---
$appMap = @{
    'Google Chrome'        = 'install --silent --accept-source-agreements --accept-package-agreements --id Google.Chrome'
    'Adobe Acrobat Reader' = 'install --silent --accept-source-agreements --accept-package-agreements --id Adobe.Acrobat.Reader.64-bit'
    'TeamViewer'           = 'install --silent --accept-source-agreements --accept-package-agreements --id TeamViewer.TeamViewer'
    'AnyDesk'              = 'install --silent --accept-source-agreements --accept-package-agreements --id AnyDesk.AnyDesk'
    'WinRAR'               = 'install --silent --accept-source-agreements --accept-package-agreements --id RARLab.WinRAR'
    'VLC Media Player'     = 'install --silent --accept-source-agreements --accept-package-agreements --id VideoLAN.VLC'
    'OpenOffice'           = 'install --silent --accept-source-agreements --accept-package-agreements --id Apache.OpenOffice'
    'Malwarebytes'         = 'install --silent --accept-source-agreements --accept-package-agreements --id Malwarebytes.Malwarebytes'
    'ESET Nod32'           = 'install --silent --accept-source-agreements --accept-package-agreements --id ESET.Nod32'
}

# Explicit ordering for GUI
$appList = @(
    'Google Chrome',
    'Adobe Acrobat Reader',
    'TeamViewer',
    'AnyDesk',
    'WinRAR',
    'VLC Media Player',
    'OpenOffice',
    'Malwarebytes',
    'ESET Nod32'
)

# --- Tweak actions and helpers (grouped with System Tweaks tab) ---
function Remove-TempFiles {
    Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}

function Set-DarkMode {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name 'AppsUseLightTheme' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $key -Name 'SystemUsesLightTheme' -Value 0 -Type DWord -Force
}

function Set-LightMode {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name 'AppsUseLightTheme' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $key -Name 'SystemUsesLightTheme' -Value 1 -Type DWord -Force
}

# Disable Microsoft telemetry and related content delivery settings
function Set-DisableTelemetry {
    # Data collection policy
    $dcKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    if (-not (Test-Path $dcKey)) { New-Item -Path $dcKey -Force | Out-Null }
    Set-ItemProperty -Path $dcKey -Name 'AllowTelemetry' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $dcKey -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Type DWord -Force

    # ContentDeliveryManager settings (suggestions / preinstalled app features)
    $cdm = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    if (-not (Test-Path $cdm)) { New-Item -Path $cdm -Force | Out-Null }
    $cdmValues = @{
        'ContentDeliveryAllowed' = 0
        'OemPreInstalledAppsEnabled' = 0
        'PreInstalledAppsEnabled' = 0
        'PreInstalledAppsEverEnabled' = 0
        'SilentInstalledAppsEnabled' = 0
        'SubscribedContent-338387Enabled' = 0
        'SubscribedContent-338388Enabled' = 0
        'SubscribedContent-338389Enabled' = 0
        'SubscribedContent-353698Enabled' = 0
        'SystemPaneSuggestionsEnabled' = 0
        'EnableFeeds' = 0
        'ShellFeedsTaskbarViewMode' = 2
        'ScoobeSystemSettingEnabled' = 0
    }
    foreach ($name in $cdmValues.Keys) {
        Set-ItemProperty -Path $cdm -Name $name -Value $cdmValues[$name] -Type DWord -Force
    }

    # Disable diagnostic tracking services if present
    $svcNames = @('DiagTrack','dmwappushservice')
    foreach ($s in $svcNames) {
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {}
            try { Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
        }
    }

    # Remove AutoLogger diagtrack listener and lock folder
    $autoLoggerDir = Join-Path $env:PROGRAMDATA 'Microsoft\Diagnosis\ETLLogs\AutoLogger'
    $etl = Join-Path $autoLoggerDir 'AutoLogger-Diagtrack-Listener.etl'
    if (Test-Path $etl) { Remove-Item $etl -ErrorAction SilentlyContinue }
    if (Test-Path $autoLoggerDir) {
        & icacls $autoLoggerDir '/deny' 'SYSTEM:(OI)(CI)F' | Out-Null
    }
}

# Disable Windows consumer features (prevents automatic installation of suggested apps/links)
function Set-DisableWindowsConsumerFeatures {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    # Set DisableWindowsConsumerFeatures = 1 (DWORD)
    Set-ItemProperty -Path $key -Name 'DisableWindowsConsumerFeatures' -Value 1 -Type DWord -Force
}

# --- Build GUI ---
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Toolkit'
$form.Size = [Drawing.Size]::New(620,420)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)

# --- Tab 1: Install Apps ---
$tabApps = New-Object System.Windows.Forms.TabPage 'Install Apps'
$tabs.TabPages.Add($tabApps)

$clbApps = New-Object System.Windows.Forms.CheckedListBox
$clbApps.CheckOnClick = $true      # Require explicit checking, no double-click activation
$clbApps.ItemHeight = 24           # Add spacing between items
$clbApps.Location = [Drawing.Point]::New(10,10)
$clbApps.Size     = [Drawing.Size]::New(580,260)
$appList | ForEach-Object { $clbApps.Items.Add($_) }
$tabApps.Controls.Add($clbApps)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text     = 'Install Selected'
$btnInstall.Size     = [Drawing.Size]::New(140,35)
$btnInstall.Location = [Drawing.Point]::New(240,290)
$tabApps.Controls.Add($btnInstall)

$btnInstall.Add_Click({
    if ($clbApps.CheckedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Please check at least one application to install.','No Selection',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        [System.Windows.Forms.MessageBox]::Show('winget not found. Please install App Installer first.','Error',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    foreach ($app in $clbApps.CheckedItems) {
        $args = $appMap[$app]
        if ($null -eq $args) {
            Write-Host "[WARN] No installation mapping for '$app'" -ForegroundColor Yellow
            continue
        }
        Start-Process -FilePath 'winget' -ArgumentList $args -NoNewWindow -Wait
    }
    [System.Windows.Forms.MessageBox]::Show('Selected applications have been installed.','Done',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
})

# --- Tab 2: System Tweaks (two-column layout) ---
$tabTweaks = New-Object System.Windows.Forms.TabPage 'System Tweaks'
$tabs.TabPages.Add($tabTweaks)

# Left column: list of tweaks to run
$panelLeft = New-Object System.Windows.Forms.Panel
$panelLeft.Location = [Drawing.Point]::New(10,10)
$panelLeft.Size     = [Drawing.Size]::New(300,340)
$panelLeft.BorderStyle = 'FixedSingle'
$tabTweaks.Controls.Add($panelLeft)

$lblLeft = New-Object System.Windows.Forms.Label
$lblLeft.Text = 'Tweaks'
$lblLeft.Location = [Drawing.Point]::New(8,8)
$lblLeft.AutoSize = $true
$panelLeft.Controls.Add($lblLeft)

$clbTweaks = New-Object System.Windows.Forms.CheckedListBox
$clbTweaks.CheckOnClick = $true
$clbTweaks.Location = [Drawing.Point]::New(8,34)
$clbTweaks.Size     = [Drawing.Size]::New(280,240)
$clbTweaks.ItemHeight = 20
$panelLeft.Controls.Add($clbTweaks)

# Populate tweaks (names used as keys)
$tweakList = @(
    'Remove Temporary Files',
    'Disable Windows Consumer Features',
    'Disable Telemetry'
)
foreach ($t in $tweakList) { $clbTweaks.Items.Add($t) }

$btnRunTweaks = New-Object System.Windows.Forms.Button
$btnRunTweaks.Text = 'Run Selected Tweaks'
$btnRunTweaks.Size = [Drawing.Size]::New(160,34)
$btnRunTweaks.Location = [Drawing.Point]::New(70,285)
$panelLeft.Controls.Add($btnRunTweaks)

# Right column: preferences with detection
$panelRight = New-Object System.Windows.Forms.Panel
$panelRight.Location = [Drawing.Point]::New(330,10)
$panelRight.Size     = [Drawing.Size]::New(270,340)
$panelRight.BorderStyle = 'FixedSingle'
$tabTweaks.Controls.Add($panelRight)

$lblRight = New-Object System.Windows.Forms.Label
$lblRight.Text = 'Preferences'
$lblRight.Location = [Drawing.Point]::New(8,8)
$lblRight.AutoSize = $true
$panelRight.Controls.Add($lblRight)

# Dark Mode preference: checkbox reflects current system setting and toggles it when changed
$chkDarkPref = New-Object System.Windows.Forms.CheckBox
$chkDarkPref.Text = 'Dark Mode'
$chkDarkPref.AutoSize = $true
$chkDarkPref.Location = [Drawing.Point]::New(8,40)
$panelRight.Controls.Add($chkDarkPref)

function Get-IsDarkMode {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    if (-not (Test-Path $key)) { return $false }
    $apps = Get-ItemProperty -Path $key -Name 'AppsUseLightTheme' -ErrorAction SilentlyContinue
    if ($null -eq $apps) { return $false }
    return ($apps.AppsUseLightTheme -eq 0)
}

# Initialize preference controls based on current system state
$chkDarkPref.Checked = Get-IsDarkMode

$chkDarkPref.Add_CheckedChanged({
    if ($chkDarkPref.Checked) {
    Set-DarkMode
    } else {
    Set-LightMode
    }
})

# Classic Right-Click Menu preference
$chkClassicContext = New-Object System.Windows.Forms.CheckBox
$chkClassicContext.Text = 'Classic Right-Click Menu'
$chkClassicContext.AutoSize = $true
$chkClassicContext.Location = [Drawing.Point]::New(8,70)
$panelRight.Controls.Add($chkClassicContext)

function Get-IsClassicContext {
    $key = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
    return (Test-Path $key)
}

# Initialize classic context checkbox
$chkClassicContext.Checked = Get-IsClassicContext

$chkClassicContext.Add_CheckedChanged({
    $key = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
    if ($chkClassicContext.Checked) {
        try {
            New-Item -Path $key -Name 'InprocServer32' -Force -Value '' | Out-Null
        } catch {
            # ignore
        }
        # Restart Explorer to apply change
        $process = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue }
    } else {
        try { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        # Restart Explorer to apply change
        $process = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue }
    }
})

# Run selected tweaks: map names to actions
$btnRunTweaks.Add_Click({
    if ($clbTweaks.CheckedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Please select at least one tweak to run.','No Selection',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    foreach ($item in $clbTweaks.CheckedItems) {
        switch ($item) {
            'Remove Temporary Files' {
                try {
                    Remove-TempFiles
                    Write-Host "[TWEAK] Remove Temporary Files -> completed successfully"
                } catch {
                    Write-Host "[TWEAK] Remove Temporary Files -> FAILED: $_" -ForegroundColor Red
                }
            }
            'Disable Windows Consumer Features' {
                try {
                    Set-DisableWindowsConsumerFeatures
                    Write-Host "[TWEAK] Disable Windows Consumer Features -> registry value set to 1 (HKLM)"
                } catch {
                    Write-Host "[TWEAK] Disable Windows Consumer Features -> FAILED: $_" -ForegroundColor Red
                }
            }
            'Disable Telemetry' {
                try {
                    Set-DisableTelemetry
                    Write-Host "[TWEAK] Disable Telemetry -> registry and services updated"
                } catch {
                    Write-Host "[TWEAK] Disable Telemetry -> FAILED: $_" -ForegroundColor Red
                }
            }
            # no longer supporting a separate "Apply Dark Mode Preference" tweak; preference is controlled via the right panel
            default { Write-Host "[TWEAK] Unknown tweak: $item" -ForegroundColor Yellow }
        }
    }
    Write-Host "[TWEAK] Selected tweaks processing finished at $(Get-Date -Format o)"
})

# Show the form

[void] $form.ShowDialog()

