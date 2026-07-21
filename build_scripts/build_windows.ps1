Write-Host "Cleaning old builds..."
Remove-Item -Recurse -Force build -ErrorAction Ignore
Remove-Item -Recurse -Force dist -ErrorAction Ignore

Write-Host "Running PyInstaller..."
.venv\Scripts\pyinstaller.exe build_scripts\AegisICS.spec --noconfirm

Write-Host "Build complete. Artifact is in dist\AegisICS"
