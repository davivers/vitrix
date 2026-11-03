# Builds a ready-to-push template repository (vitrix init + git init + first commit).
# Usage: powershell -File scripts\make-template-repo.ps1 [-Dir ..\vitrix-detections-template]
param([string]$Dir = "..\vitrix-detections-template")
$ErrorActionPreference = "Stop"
if ((Test-Path $Dir) -and (Get-ChildItem $Dir -Force | Select-Object -First 1)) { throw "$Dir exists and is not empty" }
if (-not (Get-Command vitrix -ErrorAction SilentlyContinue)) { throw "vitrix not on PATH (activate the venv)" }
vitrix init $Dir
if ($LASTEXITCODE) { throw "vitrix init failed" }
Push-Location $Dir
try {
  git init -q -b main
  git add -A
  git -c user.name="Vitrix" -c user.email="vitrix@users.noreply.github.com" commit -q -m "Initial commit from vitrix init"
  Write-Host @"

Template repo ready in $(Get-Location)
Next:
  1. Create an EMPTY repo on GitHub: davivers/vitrix-detections-template (no README/license).
  2. git remote add origin https://github.com/davivers/vitrix-detections-template.git
     git push -u origin main
  3. GitHub -> repo Settings -> General -> tick "Template repository".
"@
} finally { Pop-Location }
