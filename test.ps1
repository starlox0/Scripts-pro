# Variables
$serverIP = "192.168.60.45"
$port = "1111"
$downloadPath = "$env:USERPROFILE\Downloads"
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Files to download
$files = @("CIS-CAT.zip", "kpym.exe")

# Create download folder if not exists
if (!(Test-Path $downloadPath)) {
    New-Item -ItemType Directory -Path $downloadPath | Out-Null
}

# Download files
foreach ($file in $files) {
    $url = "http://$serverIP`:$port/$file"
    $destination = Join-Path $downloadPath $file
    Invoke-WebRequest -Uri $url -OutFile $destination
    Write-Output "Downloaded: $file"
}

# Unzip CIS-CAT.zip
$zipFile = Join-Path $downloadPath "CIS-CAT.zip"
$extractPath = Join-Path $downloadPath "CIS-CAT"
Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force

# Create shortcut for Assessor-GUI.exe
$targetExe = Join-Path $extractPath "Assessor-GUI.exe"
$shortcutPath = Join-Path $desktopPath "Assessor-GUI.lnk"

$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetExe
$shortcut.WorkingDirectory = $extractPath
$shortcut.Save()

Write-Output "Shortcut created on Desktop for Assessor-GUI.exe"
