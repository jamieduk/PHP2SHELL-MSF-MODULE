#!/usr/bin/env bash
#
# install.sh - install the php2shell exposure scanner into a Metasploit Framework
#              installation (tested on Kali Purple).
#
# It copies:
#   php2shell_exposure.rb           -> <msf-root>/modules/auxiliary/scanner/http/
#   spec/php2shell_exposure_spec.rb -> <msf-root>/spec/modules/auxiliary/scanner/http/
#
# Detection is anchored to the msfconsole on PATH so the module always lands in
# the tree that console actually reads. If that tree is not writable (the usual
# case for a system or snap package) the module goes into the matching per-user
# directory instead:
#   normal package: ~/.msf4/modules/auxiliary/scanner/http/
#   snap package:   ~/snap/metasploit-framework/common/.msf4/modules/auxiliary/scanner/http/
#
# Pass --verify to confirm through msfconsole that the module loads.
#
# This script is additive and non-destructive: any existing copy of the module
# is backed up (with a .bak-<timestamp> suffix) before being replaced.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_SRC="${SCRIPT_DIR}/php2shell_exposure.rb"
SPEC_SRC="${SCRIPT_DIR}/spec/php2shell_exposure_spec.rb"

MODULE_REL="modules/auxiliary/scanner/http"
SPEC_REL="spec/modules/auxiliary/scanner/http"
MODULE_NAME="php2shell_exposure.rb"
SPEC_NAME="php2shell_exposure_spec.rb"

usage() {
  cat <<'EOF'
Usage: install.sh [--user | --system] [--verify] [--help]

  --user      Always install into the active console's per-user path.
  --system    Require a system install (run with sudo); fails if not writable.
  --verify    After installing, launch msfconsole and confirm the module loads.
  (default)   Auto-detect the framework used by the msfconsole on PATH and
              prefer its system tree, falling back to its per-user directory.

Environment:
  MSF_ROOT=/path/to/metasploit-framework   Force a specific framework root.
  MSF_USER_ROOT=/path/to/.msf4             Force a specific per-user directory.

Examples:
  ./install.sh
  ./install.sh --user
  ./install.sh --verify
  sudo MSF_ROOT=/opt/metasploit-framework ./install.sh --system

Note: snap-installed Metasploit is read-only and confined. Its per-user
directory is ~/snap/metasploit-framework/common/.msf4, not ~/.msf4.
EOF
}

MODE="auto"
VERIFY=false
for arg in "$@"; do
  case "$arg" in
    --help|-h) usage; exit 0 ;;
    --user) MODE="user" ;;
    --system) MODE="system" ;;
    --verify) VERIFY=true ;;
    *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }

# --- Sanity checks -----------------------------------------------------------

if [[ ! -f "$MODULE_SRC" ]]; then
  err "Cannot find module source: $MODULE_SRC"
  err "Run install.sh from the directory that contains php2shell_exposure.rb."
  exit 1
fi

if ! command -v ruby >/dev/null 2>&1; then
  err "ruby was not found on PATH; install Ruby before continuing."
  exit 1
fi

log "Validating module syntax with ruby -c ..."
if ruby -c "$MODULE_SRC" >/dev/null; then
  ok "Module syntax OK"
else
  err "Module failed syntax check; aborting."
  exit 1
fi

# --- Locate the Metasploit Framework root ------------------------------------
#
# The active msfconsole is the only thing that matters: installing into a
# different (even writable) framework tree is exactly what causes a silent
# "Failed to load module". So detection starts from the msfconsole on PATH and
# resolves the tree that binary belongs to.

MSF_CONSOLE_PATH="$(command -v msfconsole 2>/dev/null || true)"

# Resolve the framework tree used by the msfconsole on PATH.
detect_console_root() {
  local p i

  [[ -n "$MSF_CONSOLE_PATH" ]] || return 1

  # Snap launchers are symlinks to /usr/bin/snap, so map them to the framework
  # bundled inside the snap (the "current" symlink tracks the installed rev).
  if [[ "$MSF_CONSOLE_PATH" == /snap/* ]]; then
    for p in \
      "/snap/metasploit-framework/current/opt/metasploit-framework/embedded/framework" \
      "/snap/metasploit-framework/current/usr/share/metasploit-framework"; do
      if [[ -d "$p/$MODULE_REL" ]]; then
        printf '%s\n' "$p"
        return 0
      fi
    done
    return 1
  fi

  # Normal install: resolve symlinks/wrappers and look for the modules tree in
  # the launcher's directory or one of its parents.
  p="$(readlink -f "$MSF_CONSOLE_PATH" 2>/dev/null || printf '%s\n' "$MSF_CONSOLE_PATH")"
  i=0
  while [[ -n "$p" && "$p" != '/' && "$i" -lt 6 ]]; do
    if [[ -d "$p/$MODULE_REL" ]]; then
      printf '%s\n' "$p"
      return 0
    fi
    p="$(dirname "$p")"
    i=$((i + 1))
  done

  return 1
}

# Fallback for when msfconsole is not on PATH (e.g. installing ahead of time).
detect_known_root() {
  local c
  for c in \
    "/usr/share/metasploit-framework" \
    "/opt/metasploit-framework" \
    "$HOME/metasploit-framework" \
    "/snap/metasploit-framework/current/opt/metasploit-framework/embedded/framework" \
    "/snap/metasploit-framework/current/usr/share/metasploit-framework"; do
    if [[ -n "$c" && -d "$c/$MODULE_REL" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# The per-user root is tied to the framework tree. The confined snap process
# sees HOME as ~/snap/metasploit-framework/common, so its ~/.msf4 lives there;
# a module placed in the real ~/.msf4 is invisible to it.
detect_user_root() {
  local root="${1:-}"

  [[ -n "${MSF_USER_ROOT:-}" ]] && { printf '%s\n' "$MSF_USER_ROOT"; return 0; }

  if [[ "$root" == /snap/* || "$MSF_CONSOLE_PATH" == /snap/* ]]; then
    printf '%s\n' "${HOME}/snap/metasploit-framework/common/.msf4"
    return 0
  fi

  printf '%s\n' "${HOME}/.msf4"
}

ACTIVE_ROOT="$(detect_console_root || true)"

if [[ -n "${MSF_ROOT:-}" ]]; then
  if [[ ! -d "$MSF_ROOT/$MODULE_REL" ]]; then
    err "MSF_ROOT=$MSF_ROOT is not a Metasploit framework tree (no $MODULE_REL)."
    exit 1
  fi
  if [[ -n "$ACTIVE_ROOT" && "$MSF_ROOT" != "$ACTIVE_ROOT" ]]; then
    warn "MSF_ROOT=$MSF_ROOT differs from the tree used by msfconsole ($ACTIVE_ROOT)."
    warn "The active console will not load a module installed into the other tree."
  fi
  MSF_DETECTED_ROOT="$MSF_ROOT"
else
  MSF_DETECTED_ROOT="${ACTIVE_ROOT:-$(detect_known_root || true)}"
fi

if [[ -z "$MSF_DETECTED_ROOT" ]]; then
  warn "Could not locate a Metasploit framework tree; using the per-user path only."
else
  log "Using framework tree: $MSF_DETECTED_ROOT"
  if [[ -n "$MSF_CONSOLE_PATH" ]]; then
    log "Active console:       $MSF_CONSOLE_PATH"
  fi
fi

USER_ROOT="$(detect_user_root "$MSF_DETECTED_ROOT")"

SYSTEM_MODS=""
SYSTEM_SPECS=""
if [[ -n "$MSF_DETECTED_ROOT" ]]; then
  [[ -w "$MSF_DETECTED_ROOT/$MODULE_REL" ]] && SYSTEM_MODS="$MSF_DETECTED_ROOT/$MODULE_REL"
  if [[ -d "$MSF_DETECTED_ROOT/spec" && -w "$MSF_DETECTED_ROOT/spec" ]]; then
    SYSTEM_SPECS="$MSF_DETECTED_ROOT/$SPEC_REL"
  fi
fi

case "$MODE" in
  system)
    if [[ -z "$SYSTEM_MODS" ]]; then
      err "System install requested but no writable framework modules dir was found."
      err "Detected framework root: ${MSF_DETECTED_ROOT:-<none>}"
      err "Re-run with sudo, or set MSF_ROOT=/path/to/metasploit-framework."
      exit 1
    fi
    MODS_DIR="$SYSTEM_MODS"
    SPECS_DIR="${SYSTEM_SPECS:-}"
    RSPEC_ROOT="${MSF_DETECTED_ROOT}"
    ;;
  user)
    MODS_DIR="$USER_ROOT/$MODULE_REL"
    SPECS_DIR="$USER_ROOT/$SPEC_REL"
    RSPEC_ROOT="${MSF_DETECTED_ROOT:-}"
    ;;
  auto)
    if [[ -n "$SYSTEM_MODS" ]]; then
      MODS_DIR="$SYSTEM_MODS"
      SPECS_DIR="${SYSTEM_SPECS:-}"
      RSPEC_ROOT="${MSF_DETECTED_ROOT}"
    else
      warn "No writable system framework modules dir found; installing for the current user."
      MODS_DIR="$USER_ROOT/$MODULE_REL"
      SPECS_DIR="$USER_ROOT/$SPEC_REL"
      RSPEC_ROOT="${MSF_DETECTED_ROOT:-}"
    fi
    ;;
esac

# --- Install -----------------------------------------------------------------

backup_if_exists() {
  local target="$1" stamp
  if [[ -e "$target" ]]; then
    stamp="$(date +%Y%m%d%H%M%S)"
    cp -p "$target" "${target}.bak-${stamp}"
    warn "Existing file backed up to ${target}.bak-${stamp}"
  fi
}

log "Installing module -> $MODS_DIR/$MODULE_NAME"
mkdir -p "$MODS_DIR"
backup_if_exists "$MODS_DIR/$MODULE_NAME"
install -m 0644 "$MODULE_SRC" "$MODS_DIR/$MODULE_NAME"
ok "Module installed."

if [[ -f "$SPEC_SRC" && -n "${SPECS_DIR:-}" ]]; then
  log "Installing spec -> $SPECS_DIR/$SPEC_NAME"
  mkdir -p "$SPECS_DIR"
  backup_if_exists "$SPECS_DIR/$SPEC_NAME"
  install -m 0644 "$SPEC_SRC" "$SPECS_DIR/$SPEC_NAME"
  ok "Spec installed."
fi

# --- Verify ------------------------------------------------------------------
#
# The most common failure mode is a module that is installed correctly but into
# a tree the active console never reads. Ask msfconsole directly so a mismatch
# is reported now instead of surfacing later as "Failed to load module".

verify_install() {
  local out

  if ! command -v msfconsole >/dev/null 2>&1; then
    warn "msfconsole is not on PATH; skipping module-load verification."
    return 0
  fi

  log "Verifying with msfconsole ($MSF_CONSOLE_PATH) ..."
  out="$(msfconsole -q -x 'search php2shell_exposure; exit' 2>&1 || true)"

  if printf '%s\n' "$out" | grep -q 'php2shell_exposure'; then
    ok "Verified: msfconsole sees auxiliary/scanner/http/php2shell_exposure"
    return 0
  fi

  err "Verification failed: msfconsole does not see the module."
  err "Installed into: $MODS_DIR/$MODULE_NAME"
  err "Active console: $MSF_CONSOLE_PATH"
  err "Framework tree: ${MSF_DETECTED_ROOT:-<not detected>}"
  err "If a different Metasploit is in use, re-run with MSF_ROOT pointing at"
  err "the tree that '$(command -v msfconsole)' belongs to."
  printf '%s\n' "$out" | sed 's/^/    /'
  return 1
}

if [[ "$VERIFY" == true ]]; then
  echo
  if ! verify_install; then
    err "The files were copied but the install could not be verified."
    exit 1
  fi
fi

# --- Next steps --------------------------------------------------------------

echo
ok "Installation complete."
echo
echo "  Module:  $MODS_DIR/$MODULE_NAME"
if [[ -n "$MSF_CONSOLE_PATH" ]]; then
  echo "  Console: $MSF_CONSOLE_PATH"
fi
echo
echo "Next steps:"
echo "  1. Start Metasploit:   msfconsole"
echo "  2. Load the module:    use auxiliary/scanner/http/php2shell_exposure"
echo "  3. Review options:     show options"

if [[ "$MODS_DIR" == "$USER_ROOT"* ]]; then
  echo
  echo "  Installed into the user module path ($USER_ROOT). Metasploit loads this"
  echo "  automatically. If the module does not appear, run 'reload_all' inside"
  echo "  msfconsole, or restart msfconsole."
fi

if [[ "$VERIFY" != true ]]; then
  echo
  echo "  Re-run with --verify to confirm msfconsole loads the module."
fi

if [[ -f "$SPEC_SRC" && -n "${RSPEC_ROOT:-}" && -n "${SPECS_DIR:-}" ]]; then
  echo
  echo "  Run the tests from the framework tree:"
  echo "    cd $RSPEC_ROOT"
  if [[ -x "$(dirname "$RSPEC_ROOT")/bin/rspec" ]]; then
    echo "    $(dirname "$RSPEC_ROOT")/bin/rspec -I spec $SPECS_DIR/$SPEC_NAME"
  elif [[ -f "$RSPEC_ROOT/Gemfile" ]]; then
    echo "    bundle exec rspec $SPECS_DIR/$SPEC_NAME"
  else
    echo "    rspec $SPECS_DIR/$SPEC_NAME"
  fi
fi
echo
warn "Only scan systems you are explicitly authorised to test."
