#!/usr/bin/env bash
###############################################################################
# setup-security-tools.sh
#
# Automated setup for a fresh Linode (Ubuntu 22.04/24.04) server:
#   1. Claude Code – AI coding agent CLI (native installer)
#   2. Gastown   – multi-agent workspace manager (Go)
#   3. Slither   – Solidity static analyzer (Python/pip)
#   4. Aderyn    – Solidity static analyzer (Rust/cyfrinup)
#   5. Tamarin Prover – security protocol verifier (Homebrew/Linuxbrew)
#   6. TLA+      – formal specification & model checking (Java jar + wrappers)
#   7. CodeQL    – GitHub semantic code analysis (binary bundle)
#
# Usage:
#   chmod +x setup-security-tools.sh
#   sudo ./setup-security-tools.sh        # run as root or with sudo
#
# After completion, log out and back in (or `source ~/.bashrc`) to pick up
# all PATH changes.
###############################################################################
set -euo pipefail

# ---------- colour helpers ---------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }

# ---------- sanity checks ----------------------------------------------------
# Ensure we're running under bash (not sh/dash)
if [ -z "${BASH_VERSION:-}" ]; then
  err "This script must be run with bash, not sh."
  err "Usage:  sudo bash setup-security-tools.sh"
  err "   or:  chmod +x setup-security-tools.sh && sudo ./setup-security-tools.sh"
  exit 1
fi

if [[ $(id -u) -ne 0 ]]; then
  err "Please run as root:  sudo ./setup-security-tools.sh"
  exit 1
fi

###############################################################################
# 0. CREATE 'conductor' USER + SSH HARDENING
###############################################################################
CONDUCTOR="conductor"

info "=== Setting up '${CONDUCTOR}' user ==="

# --- Prompt for password -----------------------------------------------------
while true; do
  read -rsp "Enter password for '${CONDUCTOR}': " CONDUCTOR_PASS
  echo
  read -rsp "Confirm password: " CONDUCTOR_PASS_CONFIRM
  echo
  if [[ "${CONDUCTOR_PASS}" == "${CONDUCTOR_PASS_CONFIRM}" ]]; then
    if [[ -z "${CONDUCTOR_PASS}" ]]; then
      err "Password cannot be empty."
      continue
    fi
    break
  else
    err "Passwords do not match. Try again."
  fi
done

# --- Prompt for SSH public key -----------------------------------------------
echo ""
info "Paste the SSH public key for '${CONDUCTOR}' (single line, e.g. ssh-ed25519 AAAA...):"
read -r SSH_PUB_KEY

if [[ -z "${SSH_PUB_KEY}" ]]; then
  err "SSH public key cannot be empty. Aborting."
  exit 1
fi

# Validate it looks like an SSH key
if ! echo "${SSH_PUB_KEY}" | grep -qE '^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2) '; then
  warn "That doesn't look like a standard SSH public key, but proceeding anyway."
fi

# --- Create user -------------------------------------------------------------
if id "${CONDUCTOR}" &>/dev/null; then
  warn "User '${CONDUCTOR}' already exists. Updating password and SSH key."
  echo "${CONDUCTOR}:${CONDUCTOR_PASS}" | chpasswd
else
  info "Creating user '${CONDUCTOR}'..."
  useradd -m -s /bin/bash -G sudo "${CONDUCTOR}"
  echo "${CONDUCTOR}:${CONDUCTOR_PASS}" | chpasswd
fi

# --- Add to sudoers (passwordless sudo for convenience, remove NOPASSWD if you prefer) ---
cat > "/etc/sudoers.d/${CONDUCTOR}" <<EOF
${CONDUCTOR} ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 "/etc/sudoers.d/${CONDUCTOR}"
info "'${CONDUCTOR}' added to sudoers (NOPASSWD)."

# --- Set up SSH key ----------------------------------------------------------
CONDUCTOR_HOME=$(eval echo "~${CONDUCTOR}")
CONDUCTOR_SSH="${CONDUCTOR_HOME}/.ssh"
mkdir -p "${CONDUCTOR_SSH}"
echo "${SSH_PUB_KEY}" > "${CONDUCTOR_SSH}/authorized_keys"
chmod 700 "${CONDUCTOR_SSH}"
chmod 600 "${CONDUCTOR_SSH}/authorized_keys"
chown -R "${CONDUCTOR}:${CONDUCTOR}" "${CONDUCTOR_SSH}"
info "SSH public key installed for '${CONDUCTOR}'."

# --- Harden SSHD: disable password auth, disable root login -----------------
SSHD_CONFIG="/etc/ssh/sshd_config"

info "Hardening SSH configuration..."

# Back up original config
cp "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.$(date +%s)"

# Function to set or add an sshd_config directive
set_sshd_option() {
  local key="$1" value="$2"
  if grep -qE "^\s*#?\s*${key}\b" "${SSHD_CONFIG}"; then
    sed -i "s/^\s*#\?\s*${key}\b.*/${key} ${value}/" "${SSHD_CONFIG}"
  else
    echo "${key} ${value}" >> "${SSHD_CONFIG}"
  fi
}

set_sshd_option "PasswordAuthentication"  "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "UsePAM"                  "yes"
set_sshd_option "PermitRootLogin"         "no"
set_sshd_option "PubkeyAuthentication"    "yes"
set_sshd_option "KbdInteractiveAuthentication" "no"

# Also drop an override in sshd_config.d (Ubuntu 22.04+ uses this)
if [[ -d /etc/ssh/sshd_config.d ]]; then
  cat > /etc/ssh/sshd_config.d/99-hardened.conf <<EOF
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF
fi

# Restart SSH (systemd)
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || warn "Could not restart sshd — please restart manually."

info "SSH hardened: password auth disabled, root login disabled."
warn "IMPORTANT: Test SSH key login as '${CONDUCTOR}' in a NEW terminal before closing this session!"

# --- Use conductor as the target user for all tool installs ------------------
REAL_USER="${CONDUCTOR}"
REAL_HOME="${CONDUCTOR_HOME}"

info "All tools will be installed for user: ${REAL_USER}"

# ---------- system packages --------------------------------------------------
info "Updating system and installing base dependencies..."
apt-get update -qq
apt-get install -y -qq \
  build-essential curl wget git unzip tar zstd jq \
  python3 python3-pip python3-venv python3-dev \
  software-properties-common ca-certificates \
  graphviz tmux

###############################################################################
# 1. CLAUDE CODE (native installer — no Node.js required)
###############################################################################
info "=== Installing Claude Code ==="

sudo -u "${REAL_USER}" bash -c '
  curl -fsSL https://claude.ai/install.sh | bash
'

# Ensure PATH includes Claude Code binary location
if ! grep -q ".claude/bin" "${REAL_HOME}/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.claude/bin:$HOME/.local/bin:$PATH"' >> "${REAL_HOME}/.bashrc"
fi

info "Claude Code installed. Run 'claude' to authenticate."

###############################################################################
# 2. GASTOWN
###############################################################################
info "=== Installing Gastown ==="

# Gastown needs Go and Node.js
# --- Go ---
GO_VERSION="1.23.6"
if ! command -v go &>/dev/null; then
  info "Installing Go ${GO_VERSION}..."
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
fi

# Ensure Go is on PATH for this script and persistently
export PATH="/usr/local/go/bin:${REAL_HOME}/go/bin:${PATH}"
cat > /etc/profile.d/go.sh <<'EOF'
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
EOF

info "Go version: $(go version)"

# --- Node.js (LTS via NodeSource) ---
if ! command -v node &>/dev/null; then
  info "Installing Node.js 22 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi
info "Node version: $(node --version)"

# --- Install Gastown via go install ---
info "Installing Gastown (go install)..."
sudo -u "${REAL_USER}" bash -c "
  export PATH='/usr/local/go/bin:\$HOME/go/bin:\$PATH'
  cd \$HOME
  go install github.com/steveyegge/gastown/cmd/gt@latest
"

info "Gastown installed."

###############################################################################
# 3. SLITHER
###############################################################################
info "=== Installing Slither ==="

# Install in a venv to avoid conflicts with system Python packages
SLITHER_VENV="/opt/slither-venv"
python3 -m venv "${SLITHER_VENV}"
"${SLITHER_VENV}/bin/pip" install --upgrade pip
"${SLITHER_VENV}/bin/pip" install slither-analyzer solc-select

# Symlink binaries to /usr/local/bin so they're on PATH for all users
ln -sf "${SLITHER_VENV}/bin/slither" /usr/local/bin/slither
ln -sf "${SLITHER_VENV}/bin/solc-select" /usr/local/bin/solc-select
ln -sf "${SLITHER_VENV}/bin/solc" /usr/local/bin/solc

# Install a default solc version
sudo -u "${REAL_USER}" bash -c '
  export PATH="/usr/local/bin:$PATH"
  solc-select install 0.8.24 && solc-select use 0.8.24
' || warn "solc-select setup may need manual 'solc-select use <version>'"

info "Slither version: $(slither --version 2>/dev/null || echo 'check PATH')"

###############################################################################
# 4. ADERYN (via official installer)
###############################################################################
info "=== Installing Aderyn ==="

sudo -u "${REAL_USER}" bash -c '
  cd $HOME
  curl --proto "=https" --tlsv1.2 -LsSf https://github.com/cyfrin/aderyn/releases/latest/download/aderyn-installer.sh | sh
'

info "Aderyn installed."

###############################################################################
# 5. TAMARIN PROVER (via Linuxbrew)
###############################################################################
info "=== Installing Tamarin Prover ==="

# Install Linuxbrew if not present
if ! sudo -u "${REAL_USER}" bash -c 'command -v brew' &>/dev/null; then
  info "Installing Homebrew (Linuxbrew)..."
  sudo -u "${REAL_USER}" bash -c '
    cd $HOME
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  '
fi

# Set up brew env for the user
BREW_PREFIX="/home/linuxbrew/.linuxbrew"
if [[ ! -d "${BREW_PREFIX}" ]]; then
  BREW_PREFIX="${REAL_HOME}/.linuxbrew"
fi

BREW_SHELLENV="eval \"\$(${BREW_PREFIX}/bin/brew shellenv)\""

# Add to bashrc if not already there
if ! grep -q "brew shellenv" "${REAL_HOME}/.bashrc" 2>/dev/null; then
  echo "${BREW_SHELLENV}" >> "${REAL_HOME}/.bashrc"
fi

info "Installing Tamarin via brew (this may take 30-60 min for first build)..."
sudo -u "${REAL_USER}" bash -c "
  cd \$HOME
  eval \"\$(${BREW_PREFIX}/bin/brew shellenv)\"
  brew install tamarin-prover/tap/tamarin-prover
  brew install tamarin-prover/tap/maude graphviz
"

info "Tamarin Prover installed."

###############################################################################
# 6. TLA+ (TLC model checker + PlusCal translator + Community Modules)
###############################################################################
info "=== Installing TLA+ Tools ==="

# TLA+ needs Java 11+
if ! command -v java &>/dev/null; then
  info "Installing OpenJDK 17..."
  apt-get install -y -qq openjdk-17-jre-headless
fi
info "Java version: $(java --version 2>&1 | head -1)"

TLA_DIR="/opt/tlaplus"
mkdir -p "${TLA_DIR}"

# Download tla2tools.jar (latest stable release)
TLA2TOOLS_URL=$(curl -sL https://api.github.com/repos/tlaplus/tlaplus/releases/latest \
  | jq -r '.assets[] | select(.name == "tla2tools.jar") | .browser_download_url' \
  | head -1)

if [[ -z "${TLA2TOOLS_URL}" || "${TLA2TOOLS_URL}" == "null" ]]; then
  # Fallback to known stable
  TLA2TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
fi

info "Downloading tla2tools.jar..."
wget -q "${TLA2TOOLS_URL}" -O "${TLA_DIR}/tla2tools.jar"

# Download Community Modules (extra operators used by many specs)
info "Downloading TLA+ Community Modules..."
wget -q "https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar" \
  -O "${TLA_DIR}/CommunityModules-deps.jar"

# Create convenience wrapper scripts
cat > /usr/local/bin/tlc <<'WRAPPER'
#!/usr/bin/env bash
# TLC model checker wrapper
exec java -XX:+UseParallelGC -cp /opt/tlaplus/tla2tools.jar:/opt/tlaplus/CommunityModules-deps.jar tlc2.TLC "$@"
WRAPPER
chmod +x /usr/local/bin/tlc

cat > /usr/local/bin/pcal <<'WRAPPER'
#!/usr/bin/env bash
# PlusCal-to-TLA+ translator wrapper
exec java -cp /opt/tlaplus/tla2tools.jar pcal.trans "$@"
WRAPPER
chmod +x /usr/local/bin/pcal

cat > /usr/local/bin/tla-sany <<'WRAPPER'
#!/usr/bin/env bash
# TLA+ parser/syntax checker wrapper
exec java -cp /opt/tlaplus/tla2tools.jar tla2sany.SANY "$@"
WRAPPER
chmod +x /usr/local/bin/tla-sany

cat > /usr/local/bin/tla-repl <<'WRAPPER'
#!/usr/bin/env bash
# TLA+ REPL wrapper
exec java -cp /opt/tlaplus/tla2tools.jar:/opt/tlaplus/CommunityModules-deps.jar tlc2.REPL "$@"
WRAPPER
chmod +x /usr/local/bin/tla-repl

info "TLA+ installed. Tools: tlc, pcal, tla-sany, tla-repl"

###############################################################################
# 7. CODEQL
###############################################################################
info "=== Installing CodeQL CLI ==="

CODEQL_DIR="/opt/codeql"
mkdir -p "${CODEQL_DIR}"

# Fetch latest bundle release URL from GitHub
info "Fetching latest CodeQL bundle..."
CODEQL_URL=$(curl -sL https://api.github.com/repos/github/codeql-action/releases/latest \
  | jq -r '.assets[] | select(.name | test("codeql-bundle-linux64.tar.zst")) | .browser_download_url' \
  | head -1)

if [[ -z "${CODEQL_URL}" || "${CODEQL_URL}" == "null" ]]; then
  # Fallback to tar.gz if zst not found
  CODEQL_URL=$(curl -sL https://api.github.com/repos/github/codeql-action/releases/latest \
    | jq -r '.assets[] | select(.name | test("codeql-bundle-linux64.tar.gz")) | .browser_download_url' \
    | head -1)
  info "Downloading CodeQL bundle (tar.gz)..."
  wget -q "${CODEQL_URL}" -O /tmp/codeql-bundle.tar.gz
  tar -xzf /tmp/codeql-bundle.tar.gz -C "${CODEQL_DIR}" --strip-components=0
  rm /tmp/codeql-bundle.tar.gz
else
  info "Downloading CodeQL bundle (tar.zst)..."
  wget -q "${CODEQL_URL}" -O /tmp/codeql-bundle.tar.zst
  zstd -d /tmp/codeql-bundle.tar.zst -o /tmp/codeql-bundle.tar
  tar -xf /tmp/codeql-bundle.tar -C "${CODEQL_DIR}" --strip-components=0
  rm /tmp/codeql-bundle.tar.zst /tmp/codeql-bundle.tar
fi

# Add to system PATH
cat > /etc/profile.d/codeql.sh <<EOF
export PATH="${CODEQL_DIR}/codeql:\$PATH"
EOF
export PATH="${CODEQL_DIR}/codeql:${PATH}"

info "CodeQL version: $(${CODEQL_DIR}/codeql/codeql version 2>/dev/null || echo 'check install')"

###############################################################################
# PATH summary for user's .bashrc
###############################################################################
BASHRC_BLOCK='
# --- Security Tools (auto-added by setup-security-tools.sh) ---
export PATH="$HOME/.claude/bin:$PATH"
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
export PATH="$HOME/.cargo/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"
export PATH="/opt/codeql/codeql:$PATH"
'

if ! grep -q "setup-security-tools.sh" "${REAL_HOME}/.bashrc" 2>/dev/null; then
  echo "${BASHRC_BLOCK}" >> "${REAL_HOME}/.bashrc"
  chown "${REAL_USER}:${REAL_USER}" "${REAL_HOME}/.bashrc"
fi

###############################################################################
# Summary
###############################################################################
echo ""
info "============================================"
info "  Installation complete!"
info "============================================"
echo ""
info "User setup:"
info "  User '${CONDUCTOR}' created with sudo (NOPASSWD)"
info "  SSH key-only auth enabled, password auth DISABLED"
info "  Root login DISABLED"
echo ""
warn "⚠  TEST SSH LOGIN BEFORE CLOSING THIS SESSION:"
warn "    ssh ${CONDUCTOR}@<this-server-ip>"
echo ""
info "Installed tools (for user '${CONDUCTOR}'):"
info "  1. Claude Code → claude"
info "  2. Gastown     → gt"
info "  3. Slither     → slither"
info "  4. Aderyn      → aderyn"
info "  5. Tamarin     → tamarin-prover"
info "  6. TLA+        → tlc, pcal, tla-sany, tla-repl"
info "  7. CodeQL      → codeql"
echo ""
warn "After logging in as '${CONDUCTOR}', run:"
warn "  source ~/.bashrc"
warn "  claude          # to authenticate Claude Code"
echo ""
info "Quick verification commands:"
echo "  claude --version"
echo "  gt --version"
echo "  slither --version"
echo "  aderyn --version"
echo "  tamarin-prover --help"
echo "  tlc -h"
echo "  codeql version"
echo ""
