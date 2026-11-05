$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcut = $ws.CreateShortcut("$desktop\USB-Sentry.lnk")

# Resolve project path dynamically from script location
$projectDir = $PSScriptRoot
if (-not $projectDir) {
    $projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$mainScript = Join-Path $projectDir "main.py"

# Locate pythonw.exe or python.exe
$pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonw) {
    $pythonw = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if (-not $pythonw) {
    $pythonw = "pythonw.exe"
}

$shortcut.TargetPath = $pythonw
$shortcut.Arguments = "`"$mainScript`""
$shortcut.WorkingDirectory = $projectDir
$shortcut.Description = 'USB-Sentry - Intelligent USB Security & Data Loss Prevention System'
$shortcut.Save()
Write-Host "Desktop shortcut created successfully at: $desktop\USB-Sentry.lnk"
