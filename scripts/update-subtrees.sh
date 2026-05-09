#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

declare -A PREFIXES=(
  [msengine]="msengine"
  [workbench]="workbench"
  [plugins]="plugins"
  [engines]="engines"
)

declare -A REPOS=(
  [msengine]="git@github.com:eris-ot/marlinspike-msengine.git"
  [workbench]="git@github.com:eris-ot/marlinspike-workbench.git"
  [plugins]="git@github.com:eris-ot/marlinspike-plugins.git"
  [engines]="git@github.com:eris-ot/marlinspike-engines.git"
)

usage() {
  cat <<'EOF'
Usage:
  scripts/update-subtrees.sh add <component> [branch]
  scripts/update-subtrees.sh pull <component> [branch]
  scripts/update-subtrees.sh push <component> [branch]
  scripts/update-subtrees.sh status

Components:
  msengine
  workbench
  plugins
  engines

Notes:
  - The MarlinSpike suite vendors component repos using git subtree, not submodules.
  - Run from the suite repo root or let the script relocate itself there.
  - Default branch is main.
EOF
}

component_check() {
  local component="${1:-}"
  if [[ -z "${PREFIXES[$component]:-}" ]]; then
    echo "Unknown component: $component" >&2
    usage
    exit 1
  fi
}

cmd_add() {
  local component="$1"
  local branch="${2:-main}"
  component_check "$component"
  git subtree add --prefix="${PREFIXES[$component]}" "${REPOS[$component]}" "$branch" --squash
}

cmd_pull() {
  local component="$1"
  local branch="${2:-main}"
  component_check "$component"
  git subtree pull --prefix="${PREFIXES[$component]}" "${REPOS[$component]}" "$branch" --squash
}

cmd_push() {
  local component="$1"
  local branch="${2:-main}"
  component_check "$component"
  git subtree push --prefix="${PREFIXES[$component]}" "${REPOS[$component]}" "$branch"
}

cmd_status() {
  for component in msengine workbench plugins engines; do
    printf '%-10s prefix=%s repo=%s\n' "$component" "${PREFIXES[$component]}" "${REPOS[$component]}"
  done
}

ACTION="${1:-}"

case "$ACTION" in
  add)
    cmd_add "${2:-}" "${3:-main}"
    ;;
  pull)
    cmd_pull "${2:-}" "${3:-main}"
    ;;
  push)
    cmd_push "${2:-}" "${3:-main}"
    ;;
  status)
    cmd_status
    ;;
  *)
    usage
    exit 1
    ;;
esac
