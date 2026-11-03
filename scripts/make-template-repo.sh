#!/usr/bin/env bash
# Builds a ready-to-push template repository (vitrix init + git init + first commit).
# Usage: scripts/make-template-repo.sh [dir]   (default: ../vitrix-detections-template)
set -euo pipefail
dir="${1:-../vitrix-detections-template}"
if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then echo "error: $dir exists and is not empty" >&2; exit 1; fi
command -v vitrix >/dev/null || { echo "error: vitrix not on PATH (activate the venv)" >&2; exit 1; }
vitrix init "$dir"
cd "$dir"
git init -q -b main
git add -A
git -c user.name="${GIT_AUTHOR_NAME:-Vitrix}" -c user.email="${GIT_AUTHOR_EMAIL:-vitrix@users.noreply.github.com}" commit -q -m "Initial commit from vitrix init"
cat <<MSG

Template repo ready in $(pwd)
Next:
  1. Create an EMPTY repo on GitHub: davivers/vitrix-detections-template (no README/license).
  2. git remote add origin https://github.com/davivers/vitrix-detections-template.git
     git push -u origin main
  3. GitHub -> repo Settings -> General -> tick "Template repository".
MSG
