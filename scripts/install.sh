#!/usr/bin/env sh
# Install Vitrix into ./.venv (Python 3.10-3.14). Usage: scripts/install.sh [pip-target]
#   pip-target defaults to the repo this script lives in (".[api]"); pass e.g.
#   "vitrix[api] @ git+https://github.com/davivers/vitrix" to install from GitHub.
set -eu
root=$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })
target=${1:-"$root[api]"}
venv=${VITRIX_VENV:-.venv}

py=""
for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,14) else 1)' 2>/dev/null; then
    py=$c; break
  fi
done
if [ -z "$py" ]; then
  echo "error: Vitrix needs Python 3.10 to 3.14 (3.15 has no PyYAML wheel yet). Install one and re-run." >&2
  exit 1
fi
echo "Using $($py --version) -> $venv"
"$py" -m venv "$venv"
if [ -x "$venv/bin/python" ]; then vpy="$venv/bin/python"; act=". $venv/bin/activate"; else vpy="$venv/Scripts/python"; act="$venv/Scripts/Activate.ps1  (Git Bash: . $venv/Scripts/activate)"; fi
"$vpy" -m pip install --quiet --upgrade pip
"$vpy" -m pip install "$target"
cat <<MSG

Vitrix installed. Next:
  $act
  vitrix init my-detections
  cd my-detections && vitrix serve      # http://127.0.0.1:8000
MSG
