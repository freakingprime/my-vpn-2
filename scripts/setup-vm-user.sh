#!/usr/bin/env bash
set -euo pipefail

# Sets up a locked-down, proxy-only SSH user on a GCE or Oracle Cloud VM.
# - No sudo access
# - Shell set to /usr/sbin/nologin (no interactive shell)
# - authorized_keys restricted to TCP port forwarding only (no shell/exec/PTY/agent)
#
# Usage:
#   sudo bash setup-vm-user.sh <username> "<public_key>"
# Example:
#   sudo bash setup-vm-user.sh nasproxy "ssh-ed25519 AAAA... my-vpn-2"

PROXY_USER="${1:-nasproxy}"
PUB_KEY="${2:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: Please run as root (e.g. sudo bash $0 ...)" >&2
  exit 1
fi

if [[ -z "${PUB_KEY}" ]]; then
  echo "Paste the contents of your .pub key (e.g. id_rsa.pub) and press Enter:"
  read -r PUB_KEY
fi

PUB_KEY="$(echo "${PUB_KEY}" | tr -d '\r\n' | xargs)"
if [[ -z "${PUB_KEY}" ]]; then
  echo "ERROR: Public key cannot be empty." >&2
  exit 1
fi

# Strip any existing leading options if user pasted an already-restricted key
if [[ "${PUB_KEY}" =~ ^(ssh-|ecdsa-sha2-|sk-) ]]; then
  CLEAN_KEY="${PUB_KEY}"
else
  CLEAN_KEY="$(echo "${PUB_KEY}" | grep -oE '(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) .+' || true)"
fi

if [[ -z "${CLEAN_KEY}" ]]; then
  echo "ERROR: Could not recognize a valid SSH public key." >&2
  exit 1
fi

NOLOGIN_BIN="/usr/sbin/nologin"
if [[ ! -x "${NOLOGIN_BIN}" ]]; then
  NOLOGIN_BIN="/sbin/nologin"
fi

if ! id "${PROXY_USER}" >/dev/null 2>&1; then
  useradd -m -s "${NOLOGIN_BIN}" "${PROXY_USER}"
  echo "Created user '${PROXY_USER}' with shell ${NOLOGIN_BIN}."
else
  usermod -s "${NOLOGIN_BIN}" "${PROXY_USER}"
  echo "Updated existing user '${PROXY_USER}' shell to ${NOLOGIN_BIN}."
fi

HOME_DIR="$(getent passwd "${PROXY_USER}" | cut -d: -f6)"
SSH_DIR="${HOME_DIR}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
touch "${AUTH_KEYS}"

RESTRICTED_LINE="restrict,port-forwarding ${CLEAN_KEY}"
if ! grep -Fq "${CLEAN_KEY}" "${AUTH_KEYS}"; then
  printf '%s\n' "${RESTRICTED_LINE}" >> "${AUTH_KEYS}"
  echo "Added restricted public key to ${AUTH_KEYS}."
else
  echo "Public key already present in ${AUTH_KEYS} (verifying options manually is recommended)."
fi

chown -R "${PROXY_USER}:${PROXY_USER}" "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chmod 600 "${AUTH_KEYS}"

# Ensure sshd allows TCP forwarding
if grep -qiE '^\s*AllowTcpForwarding\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  echo "WARNING: AllowTcpForwarding appears to be disabled in sshd_config!"
  echo "Enable 'AllowTcpForwarding yes' (or 'local') for user '${PROXY_USER}' and reload sshd."
else
  echo "sshd AllowTcpForwarding check: OK."
fi

echo ""
echo "Done! User '${PROXY_USER}' is restricted to port-forwarding only."
echo "Set GCE_USER=${PROXY_USER} or OCI_USER=${PROXY_USER} in your .env file."
