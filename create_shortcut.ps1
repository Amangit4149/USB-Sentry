$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcut = $ws.CreateShortcut("$desktop\Smart USB Guardian.lnk")
$shortcut.TargetPath = "pythonw.exe"
$shortcut.Arguments = '"C:\Users\aman7\OneDrive\Desktop\new project\SmartUSBGuardian\main.py"'
$shortcut.WorkingDirectory = 'C:\Users\aman7\OneDrive\Desktop\new project\SmartUSBGuardian'
$shortcut.Description = 'Smart USB Guardian - USB Tracking System'
$shortcut.Save()
Write-Host "Desktop shortcut created successfully!"
