# Package TraceVault Windows Collector as a standalone executable using PyInstaller
$ErrorActionPreference = "Stop"
& "$PSScriptRoot\.venv\Scripts\pip.exe" install pyinstaller
& "$PSScriptRoot\.venv\Scripts\pyinstaller.exe" --onefile --name tracevault-collector "$PSScriptRoot\tracevault_collector\__main__.py"
