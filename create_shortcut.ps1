$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcut = $ws.CreateShortcut("$desktop\USB-Sentry.lnk")
$shortcut.TargetPath = "pythonw.exe"
$shortcut.Arguments = '"C:\Users\aman7\OneDrive\Desktop\new project\USB-Sentry\main.py"'
$shortcut.WorkingDirectory = 'C:\Users\aman7\OneDrive\Desktop\new project\USB-Sentry'
$shortcut.Description = 'USB-Sentry - Intelligent USB Security & Data Loss Prevention System'
$shortcut.Save()
Write-Host "Desktop shortcut created successfully!"
