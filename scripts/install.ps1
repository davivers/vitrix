# Install Vitrix into .venv (Python 3.10-3.14). Usage: scripts\install.ps1 [-Target <pip target>]
#   Default target is this repository (".[api]"); pass e.g. "vitrix[api] @ git+https://github.com/davivers/vitrix".
param([string]$Target = "", [string]$Venv = ".venv")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Target) { $Target = "$root[api]" }

$py = $null
foreach ($c in @(@("py", "-3.14"), @("py", "-3.13"), @("py", "-3.12"), @("py", "-3.11"), @("py", "-3.10"), @("python"), @("python3"))) {
  if (-not (Get-Command $c[0] -ErrorAction SilentlyContinue)) { continue }
  $extra = @($c | Select-Object -Skip 1)
  $ErrorActionPreference = "Continue"  # the py launcher writes to stderr when a version is missing
  & $c[0] @extra -c "import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,14) else 1)" 2>$null
  $ErrorActionPreference = "Stop"
  if ($LASTEXITCODE -eq 0) { $py = $c; break }
}
if (-not $py) { Write-Error "Vitrix needs Python 3.10 to 3.14 (3.15 has no PyYAML wheel yet). Install one and re-run."; exit 1 }
$pyExe = $py[0]; $pyArgs = @($py | Select-Object -Skip 1)
Write-Host "Using $(& $pyExe @pyArgs --version) -> $Venv"
& $pyExe @pyArgs -m venv $Venv
& "$Venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "$Venv\Scripts\python.exe" -m pip install $Target
if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed"; exit 1 }
Write-Host @"

Vitrix installed. Next:
  $Venv\Scripts\Activate.ps1
  vitrix init my-detections
  cd my-detections; vitrix serve      # http://127.0.0.1:8000
"@
