<#
.SYNOPSIS
  All-in-one GUI for installing apps and performing system tweaks.
.DESCRIPTION
  Tab 1: Install selected applications via winget.
  Tab 2: System Tweaks – remove temporary files and toggle Dark Mode.

USAGE:
  To run locally:
    . .\Windows-Toolkit.ps1

  To run directly from GitHub/Gist (if hosted as raw URL):
    powershell -NoProfile -ExecutionPolicy Bypass -Command \
      "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/main/Windows-Toolkit.ps1')"

  Or shorter within PowerShell:
    iex (irm 'https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/main/Windows-Toolkit.ps1')

.NOTES
  - Run PowerShell as Administrator for system tasks.
  - Ensure winget is available for app installs.
#>

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
    'ESET Node32'          = 'install --silent --accept-source-agreements --accept-package-agreements --id ESET.Nod32'
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
    'Eset Node32'
)

# --- Tweak actions ---
function Remove-TempFiles {
    Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$Env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
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

# --- Build GUI ---
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Toolkit'
$form.Size = [Drawing.Size]::New(450,400)
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
$clbApps.Size     = [Drawing.Size]::New(410,260)
foreach ($app in $appList) {
    $clbApps.Items.Add($app)
}
$tabApps.Controls.Add($clbApps)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text     = 'Install Selected'
$btnInstall.Size     = [Drawing.Size]::New(140,35)
$btnInstall.Location = [Drawing.Point]::New(155,290)
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
        Start-Process -FilePath 'winget' -ArgumentList $appMap[$app] -NoNewWindow -Wait
    }
    [System.Windows.Forms.MessageBox]::Show('Selected applications have been installed.','Done',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
})

# --- Tab 2: System Tweaks ---
$tabTweaks = New-Object System.Windows.Forms.TabPage 'System Tweaks'
$tabs.TabPages.Add($tabTweaks)

# Remove Temporary Files checkbox + button
$chkTemp = New-Object System.Windows.Forms.CheckBox
$chkTemp.Text = 'Remove Temporary Files'
$chkTemp.AutoSize = $true
$chkTemp.Location = [Drawing.Point]::New(10,20)
$tabTweaks.Controls.Add($chkTemp)

$btnClean = New-Object System.Windows.Forms.Button
$btnClean.Text     = 'Clean Temp'
$btnClean.Size     = [Drawing.Size]::New(100,30)
$btnClean.Location = [Drawing.Point]::New(10,60)  # Increased spacing from checkbox
$tabTweaks.Controls.Add($btnClean)

$btnClean.Add_Click({
    if (-not $chkTemp.Checked) {
        [System.Windows.Forms.MessageBox]::Show('Please check "Remove Temporary Files" first.','No Selection',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    Remove-TempFiles
    [System.Windows.Forms.MessageBox]::Show('Temporary files removed.','Done',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
})

# Dark Mode toggle
$chkDarkMode = New-Object System.Windows.Forms.CheckBox
$chkDarkMode.Text = 'Dark Mode'
$chkDarkMode.AutoSize = $true
$chkDarkMode.Location = [Drawing.Point]::New(10,110)  # Increased spacing below Clean Temp
$tabTweaks.Controls.Add($chkDarkMode)

$chkDarkMode.Add_CheckedChanged({
    if ($chkDarkMode.Checked) {
        Set-DarkMode
        [System.Windows.Forms.MessageBox]::Show('Dark Mode applied.','Done',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
    } else {
        Set-LightMode
        [System.Windows.Forms.MessageBox]::Show('Light Mode applied.','Done',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Show the form

[void] $form.ShowDialog()
