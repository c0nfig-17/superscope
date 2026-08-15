#!/usr/bin/env bash
#
# install.sh — one command to get superscope ready.
#
#   ./install.sh
#
# It installs, idempotently:
#   * Python deps (PyYAML)
#   * a local Go toolchain, ONLY if `go` isn't already on PATH
#   * subfinder, nuclei, subzy, notify  (via `go install`)
#   * seeds config.yaml from the example
#
# Nothing is installed system-wide and nothing needs sudo: the Go toolchain
# goes in ~/.local/go and the tool binaries in ~/go/bin. Any tool that still
# fails to install is reported; superscope just skips that stage at runtime.
set -u

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOROOT_LOCAL="$HOME/.local/go"
export GOBIN="${GOBIN:-$HOME/go/bin}"

info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }

# --- platform ---------------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"    # linux | darwin
case "$(uname -m)" in
  x86_64|amd64)   ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *) ARCH="" ;;
esac

fetch() {  # fetch <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else err "need curl or wget"; return 1; fi
}

# --- Python -----------------------------------------------------------------
install_python() {
  info "Installing Python dependencies…"
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user -q -r "$INSTALL_DIR/requirements.txt" \
      && ok "Python deps installed" \
      || warn "pip install failed — install PyYAML manually (pip3 install pyyaml)"
  else
    warn "pip3 not found — install Python 3 + PyYAML manually"
  fi
}

# --- Go toolchain (only if missing) ----------------------------------------
ensure_go() {
  if command -v go >/dev/null 2>&1; then
    ok "Go already installed ($(go version | awk '{print $3}'))"
    return 0
  fi
  if [[ -x "$GOROOT_LOCAL/bin/go" ]]; then
    export PATH="$GOROOT_LOCAL/bin:$PATH"
    ok "Using local Go at $GOROOT_LOCAL"
    return 0
  fi
  if [[ -z "$ARCH" ]]; then
    warn "Unsupported CPU arch ($(uname -m)); install Go manually from https://go.dev/dl/"
    return 1
  fi
  info "Go not found — installing a local copy (no sudo, into $GOROOT_LOCAL)…"
  local ver tarball url tmp
  ver="$(fetch_go_version)" || { warn "could not determine latest Go version"; return 1; }
  tarball="${ver}.${OS}-${ARCH}.tar.gz"
  url="https://go.dev/dl/${tarball}"
  tmp="$(mktemp -d)"
  if ! fetch "$url" "$tmp/$tarball"; then
    warn "failed to download $url — install Go manually from https://go.dev/dl/"
    rm -rf "$tmp"; return 1
  fi
  mkdir -p "$HOME/.local"
  rm -rf "$GOROOT_LOCAL"
  tar -C "$HOME/.local" -xzf "$tmp/$tarball"   # extracts to ~/.local/go
  rm -rf "$tmp"
  export PATH="$GOROOT_LOCAL/bin:$PATH"
  command -v go >/dev/null 2>&1 && ok "Installed $(go version | awk '{print $3}')" || { warn "Go install failed"; return 1; }
}

fetch_go_version() {  # prints e.g. go1.23.4
  local tmp; tmp="$(mktemp)"
  if fetch "https://go.dev/VERSION?m=text" "$tmp"; then
    head -n1 "$tmp"; rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"; return 1
}

# --- Go tools ---------------------------------------------------------------
GOTOOLS_ORDER=(subfinder nuclei subzy notify)
declare -A GOTOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [notify]="github.com/projectdiscovery/notify/cmd/notify@latest"
)

install_gotools() {
  export PATH="$GOBIN:$PATH"
  if ! command -v go >/dev/null 2>&1; then
    warn "No Go toolchain — skipping subfinder/nuclei/subzy/notify."
    warn "Install Go, re-run ./install.sh, or install them manually."
    return
  fi
  for t in "${GOTOOLS_ORDER[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t already installed"; continue; fi
    info "Installing $t…"
    if go install "${GOTOOLS[$t]}"; then ok "$t installed"; else warn "failed to install $t"; fi
  done
}

# --- nuclei templates -------------------------------------------------------
update_templates() {
  if command -v nuclei >/dev/null 2>&1; then
    info "Updating official Nuclei templates…"
    nuclei -update-templates >/dev/null 2>&1 && ok "Nuclei templates updated" || warn "template update skipped"
  fi
}

# --- config -----------------------------------------------------------------
seed_config() {
  if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
    cp "$INSTALL_DIR/config.yaml.example" "$INSTALL_DIR/config.yaml"
    ok "Seeded config.yaml"
  else
    ok "config.yaml already present — left untouched"
  fi
}

install_python
ensure_go
install_gotools
update_templates
seed_config

# --- PATH hint --------------------------------------------------------------
NEED_PATH=()
case ":$PATH:" in *":$GOBIN:"*) ;; *) NEED_PATH+=("$GOBIN") ;; esac
if [[ -x "$GOROOT_LOCAL/bin/go" ]]; then
  case ":$PATH:" in *":$GOROOT_LOCAL/bin:"*) ;; *) NEED_PATH+=("$GOROOT_LOCAL/bin") ;; esac
fi

echo
ok "Done."
if [[ ${#NEED_PATH[@]} -gt 0 ]]; then
  warn "Add this to your shell rc (~/.bashrc or ~/.zshrc) so the tools stay on PATH:"
  printf '    export PATH="$PATH:%s"\n' "$(IFS=:; echo "${NEED_PATH[*]}")"
fi
cat <<'EOF'

Next steps:
  1. Two Notify provider-configs (one webhook each):
       ~/.config/notify/findings.yaml   (Nuclei findings)
       ~/.config/notify/takeover.yaml   (subzy takeovers — different webhook)
  2. Point superscope at them:
       export SUPERSCOPE_NOTIFY_FINDINGS=~/.config/notify/findings.yaml
       export SUPERSCOPE_NOTIFY_TAKEOVER=~/.config/notify/takeover.yaml
  3. Preview the plan:   python3 -m superscope --dry-run
  4. Run it:             python3 -m superscope
EOF
