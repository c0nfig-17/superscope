#!/usr/bin/env bash
#
# install.sh — set up superscope and the external binaries it drives.
#
# Installs (idempotently):
#   * Python deps (PyYAML, tldextract)
#   * subfinder, nuclei, subzy, notify  (via `go install`)
#
# Everything is best-effort: a tool that fails to install is reported, and
# superscope will simply skip that stage at runtime with an install hint.
set -u

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOBIN="${GOBIN:-$HOME/go/bin}"

info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# --- Python -----------------------------------------------------------------
install_python() {
  info "Installing Python dependencies…"
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user -r "$INSTALL_DIR/requirements.txt" \
      && ok "Python deps installed" \
      || warn "pip install failed — install PyYAML manually"
  else
    warn "pip3 not found — install Python 3 and PyYAML manually"
  fi
}

# --- Go tools ---------------------------------------------------------------
declare -A GOTOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [notify]="github.com/projectdiscovery/notify/cmd/notify@latest"
)

install_gotools() {
  if ! command -v go >/dev/null 2>&1; then
    warn "Go toolchain not found. Install Go (https://go.dev/dl/) then re-run,"
    warn "or install these manually:"
    for t in "${!GOTOOLS[@]}"; do warn "  go install ${GOTOOLS[$t]}"; done
    return
  fi
  for t in "${!GOTOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      ok "$t already installed"
      continue
    fi
    info "Installing $t…"
    if go install "${GOTOOLS[$t]}"; then
      ok "$t installed"
    else
      warn "failed to install $t"
    fi
  done
  case ":$PATH:" in
    *":$GOBIN:"*) ;;
    *) warn "Add \$GOBIN to PATH:  export PATH=\"\$PATH:$GOBIN\"" ;;
  esac
}

# --- config -----------------------------------------------------------------
seed_config() {
  if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
    cp "$INSTALL_DIR/config.yaml.example" "$INSTALL_DIR/config.yaml"
    ok "Seeded config.yaml (edit it, then wire up your Notify provider-configs)"
  else
    ok "config.yaml already present — left untouched"
  fi
}

install_python
install_gotools
seed_config

cat <<'EOF'

Next steps:
  1. Update nuclei templates:            nuclei -update-templates   (optional)
  2. Create two Notify provider-configs (one per webhook), e.g.:
       ~/.config/notify/findings.yaml    (Nuclei findings)
       ~/.config/notify/takeover.yaml    (subzy takeovers — different webhook)
  3. Point superscope at them, either in config.yaml or via env:
       export SUPERSCOPE_NOTIFY_FINDINGS=~/.config/notify/findings.yaml
       export SUPERSCOPE_NOTIFY_TAKEOVER=~/.config/notify/takeover.yaml
  4. Dry-run first:                       python3 -m superscope --dry-run
  5. Go:                                  python3 -m superscope
EOF
