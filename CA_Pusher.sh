#!/usr/bin/env bash
# push_ca_trust_to_clusterB_ubuntu.sh
#
# Run this on Cluster A.
#
# Given:
#   --clients <file>   : list of Cluster B client IPs/hosts/FQDNs (one per line)
#   --ca <dir>         : the *directory* created by your Cluster A CA creation tool
#                        (i.e. the same --out-dir you used there, e.g. /root/qumulo-tls)
#
# This script:
#   1) pulls the CA cert from: <dir>/ca/ca.crt.pem
#   2) prompts for SSH username
#   3) prompts for SSH auth method (key or password)
#   4) prompts for the remote sudo password (user is NOT passwordless sudoer)
#   5) copies the CA cert to each client
#   6) installs it into the system trust store: Ubuntu/Debian
#      (/usr/local/share/ca-certificates, update-ca-certificates) or
#      RHEL/Rocky/Alma (/etc/pki/ca-trust/source/anchors, update-ca-trust)
#   7) proves the refreshed system bundle contains it (skip with --no-verify)
#
# Requirements (on Cluster A):
#   - bash, ssh, scp, openssl
#   - OPTIONAL: sshpass (only if using password-based SSH)
#       sudo apt-get update && sudo apt-get install -y sshpass
#
# Usage:
#   ./CA_Pusher.sh \
#     --clients ./clusterB_hosts.txt \
#     --ca ./qumulo-tls
#
# Clients file format:
#   One host/IP/FQDN per line. Blank lines and lines starting with # are ignored.
#
# Security notes:
# - The sudo password is read from stdin (hidden) and held only in memory.
# - We do NOT place the password on any command line; it is passed via stdin.
# - The root script is base64-encoded and decoded on the remote side to avoid
#   quoting and stdin conflicts with the sudo password delivery.

set -euo pipefail

CLIENTS_FILE=""
CA_DIR=""             # directory created by CA creation tool (out-dir)
CA_CERT=""            # resolved to CA_DIR/ca/ca.crt.pem
SSH_USER=""
SSH_PORT="22"
AUTH_MODE=""          # "key" or "password"
SSH_KEY_PATH=""       # used if AUTH_MODE=key (optional)
VERIFY=1
CONTAINER=""          # systemd-nspawn container name (e.g. "qcore")
VERIFY_TLS=""         # optional host:port for end-to-end TLS check
TRUST_NAME="company-lab-root-ca"   # trust file name on targets (.crt is appended)
CONNECT_TIMEOUT=8

# In-memory secrets
SSHPASS=""            # only if AUTH_MODE=password (sshpass)
SUDO_PASS=""          # always required (remote sudo password)

usage() {
  cat <<EOF
Usage: $0 --clients <file> --ca <ca-tool-out-dir> [options]

Required:
  --clients <file>        File with one client IP/hostname/FQDN per line
  --ca <dir>              Directory created by CA creation tool (e.g. /root/qumulo-tls)
                          CA cert is expected at: <dir>/ca/ca.crt.pem

Optional:
  --ssh-user <name>           SSH username (if omitted, will prompt)
  --port <n>              SSH port (default: $SSH_PORT)
  --auth key              Use SSH key auth
  --auth password         Use password SSH auth (requires sshpass)
  --key <path>            SSH private key path (for --auth key)
  --container <name>      Also install cert into a systemd-nspawn container
                          on each host (e.g. --container qcore), using the
                          container's own trust store tools. A host without
                          machinectl or without that running container gets a
                          WARNING and the container is skipped.
  --verify-tls <h:p>     End-to-end TLS check against host:port after install
                          (e.g. --verify-tls stratusdatacore.qumulotest.local:443)
  --no-verify             Skip the check that the refreshed trust store
                          contains the CA (host and container)
  --trust-name <name>     Trust file name on targets, without .crt
                          (default: $TRUST_NAME)
  --timeout <sec>         SSH connect timeout (default: $CONNECT_TIMEOUT)
  --help                  Show help

EOF
}

err()  { echo "ERROR: $*" >&2; }
info() { echo "INFO:  $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

cleanup() {
  SSHPASS=""
  SUDO_PASS=""
  unset SSHPASS SUDO_PASS
}
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --clients) CLIENTS_FILE="${2:-}"; shift 2 ;;
      --ca) CA_DIR="${2:-}"; shift 2 ;;
      --ssh-user) SSH_USER="${2:-}"; shift 2 ;;
      --port) SSH_PORT="${2:-}"; shift 2 ;;
      --auth) AUTH_MODE="${2:-}"; shift 2 ;;
      --key) SSH_KEY_PATH="${2:-}"; shift 2 ;;
      --container) CONTAINER="${2:-}"; shift 2 ;;
      --verify-tls) VERIFY_TLS="${2:-}"; shift 2 ;;
      --no-verify) VERIFY=0; shift 1 ;;
      --trust-name) TRUST_NAME="${2:-}"; shift 2 ;;
      --timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [[ -z "$CLIENTS_FILE" || ! -f "$CLIENTS_FILE" ]]; then
    err "--clients file is required and must exist"; exit 1
  fi

  if [[ -z "$CA_DIR" || ! -d "$CA_DIR" ]]; then
    err "--ca must point to the CA tool output directory and must exist"; exit 1
  fi

  CA_CERT="${CA_DIR%/}/ca/ca.crt.pem"
  if [[ ! -f "$CA_CERT" ]]; then
    err "CA cert not found at expected path: $CA_CERT"
    err "Ensure --ca points to the same --out-dir used by the CA creation tool."
    exit 1
  fi

  if ! openssl x509 -in "$CA_CERT" -noout >/dev/null 2>&1; then
    err "CA file does not look like a valid PEM X.509 cert: $CA_CERT"; exit 1
  fi

  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
    err "--port must be a valid TCP port"; exit 1
  fi
  if ! [[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$CONNECT_TIMEOUT" -lt 1 ]]; then
    err "--timeout must be a positive integer"; exit 1
  fi
  if [[ -n "$AUTH_MODE" && "$AUTH_MODE" != "key" && "$AUTH_MODE" != "password" ]]; then
    err "--auth must be 'key' or 'password'"; exit 1
  fi
  if [[ -n "$SSH_KEY_PATH" && ! -f "$SSH_KEY_PATH" ]]; then
    err "--key path not found: $SSH_KEY_PATH"; exit 1
  fi
  # The name is spliced into the root script, so only plain names are allowed.
  if [[ -n "$CONTAINER" && ! "$CONTAINER" =~ ^[A-Za-z0-9._-]+$ ]]; then
    err "--container must contain only letters, digits, '.', '_' and '-'"; exit 1
  fi
  if ! [[ "$TRUST_NAME" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*$ ]]; then
    err "--trust-name must start with a letter, digit, '_' or '-' and contain only those and '.'"; exit 1
  fi
}

# Read the clients file up front so an empty file fails before any prompt.
load_hosts() {
  local line
  HOSTS=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(echo "$line" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    HOSTS+=("$line")
  done < "$CLIENTS_FILE"
  if [[ ${#HOSTS[@]} -eq 0 ]]; then
    err "No hosts found in $CLIENTS_FILE"; exit 1
  fi
}

prompt_creds() {
  if [[ -z "$SSH_USER" ]]; then
    read -r -e -p "SSH username for Cluster B nodes: " SSH_USER
  fi
  if [[ -z "$SSH_USER" ]]; then
    err "SSH username cannot be empty"; exit 1
  fi

  if [[ -z "$AUTH_MODE" ]]; then
    echo "Choose SSH auth method:"
    echo "  1) key (recommended)"
    echo "  2) password (requires sshpass)"
    read -r -e -p "Selection [1/2]: " sel
    case "$sel" in
      2) AUTH_MODE="password" ;;
      *) AUTH_MODE="key" ;;
    esac
  fi

  case "$AUTH_MODE" in
    key)
      if [[ -z "$SSH_KEY_PATH" ]]; then
        read -r -e -p "SSH key path (leave blank to use ssh-agent/default config): " SSH_KEY_PATH || true
      fi
      ;;
    password)
      need_cmd sshpass
      read -r -e -s -p "SSH password for ${SSH_USER}: " SSHPASS
      echo
      if [[ -z "$SSHPASS" ]]; then
        err "Password auth selected but SSH password was empty"; exit 1
      fi
      export SSHPASS
      ;;
  esac

  # Always required because user is NOT passwordless sudoer
  read -r -e -s -p "Remote sudo password for ${SSH_USER}: " SUDO_PASS
  echo
  if [[ -z "$SUDO_PASS" ]]; then
    err "Remote sudo password cannot be empty"; exit 1
  fi
}

ssh_opts_base() {
  echo "-p ${SSH_PORT} -o ConnectTimeout=${CONNECT_TIMEOUT} -o StrictHostKeyChecking=accept-new"
}

# Run a remote command without TTY allocation (for non-interactive scripts).
# Stdin is forwarded to the remote command, so callers can pipe data in.
run_ssh_no_tty() {
  local host="$1"; shift
  local opts; opts="$(ssh_opts_base)"

  if [[ "$AUTH_MODE" == "password" ]]; then
    sshpass -e ssh -T $opts -o BatchMode=no "${SSH_USER}@${host}" "$@"
  else
    if [[ -n "$SSH_KEY_PATH" ]]; then
      ssh -T $opts -o BatchMode=yes -i "$SSH_KEY_PATH" "${SSH_USER}@${host}" "$@"
    else
      ssh -T $opts -o BatchMode=yes "${SSH_USER}@${host}" "$@"
    fi
  fi
}

# Copy a file to remote host
run_scp() {
  local src="$1"
  local host="$2"
  local dst="$3"

  if [[ "$AUTH_MODE" == "password" ]]; then
    sshpass -e scp -P "${SSH_PORT}" -o ConnectTimeout="${CONNECT_TIMEOUT}" -o StrictHostKeyChecking=accept-new -o BatchMode=no \
      "$src" "${SSH_USER}@${host}:$dst"
  else
    if [[ -n "$SSH_KEY_PATH" ]]; then
      scp -P "${SSH_PORT}" -o ConnectTimeout="${CONNECT_TIMEOUT}" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
        -i "$SSH_KEY_PATH" "$src" "${SSH_USER}@${host}:$dst"
    else
      scp -P "${SSH_PORT}" -o ConnectTimeout="${CONNECT_TIMEOUT}" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
        "$src" "${SSH_USER}@${host}:$dst"
    fi
  fi
}

# Run a root script on remote host via sudo -S.
# The script is base64-encoded and passed as a command argument to avoid
# stdin conflicts.  The sudo password is piped via stdin to the remote
# command, which reads it and feeds it to sudo -S.
run_remote_sudo_script() {
  local host="$1"
  local root_script="$2"

  # Base64-encode the script so it can be safely embedded in a command string
  local b64_script
  b64_script="$(printf '%s' "$root_script" | base64 | tr -d '\n')"

  # Remote command sequence:
  #   1. read the sudo password from stdin (first and only line)
  #   2. decode the base64 payload into a temp script
  #   3. run the temp script under sudo -S (password piped in)
  #   4. clean up and propagate the exit code
  local remote_cmd
  remote_cmd="read -r _PW \
&& _S=\$(mktemp) \
&& echo '${b64_script}' | base64 -d > \"\$_S\" \
&& printf '%s\\n' \"\$_PW\" | sudo -S bash \"\$_S\"; \
_rc=\$?; rm -f \"\$_S\"; exit \$_rc"

  # Pipe the sudo password as stdin; use no-TTY ssh to prevent interactive shell
  printf '%s\n' "$SUDO_PASS" | run_ssh_no_tty "$host" "$remote_cmd"
}

install_on_node() {
  local host="$1"

  info "[$host] installing CA into system trust store (sudo required)"

  # Embed the CA cert directly in the payload — avoids SCP and the
  # temp-file permission issue (previous runs leave root-owned files in /tmp).
  local b64_cert
  b64_cert="$(base64 < "$CA_CERT" | tr -d '\n')" || return 1

  local root_script
  root_script="$(cat <<'RSCRIPT'
exec </dev/null
set -euo pipefail
CONTAINER="__CONTAINER__"
VERIFY_TLS_EP="__VERIFY_TLS__"
VERIFY_TRUST="__VERIFY__"
TRUST_NAME="__TRUST_NAME__"

# Normalised SHA-256 of a PEM cert; empty when the file is not a readable cert.
fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d : | tr a-f A-F || true
}

# Install the lab root (PEM on stdin) into this machine's trust store and,
# when verify=1, prove the refreshed system bundle contains it. Runs on the
# host directly and inside the container through nsenter, so each side uses
# its own tools and paths. Callers run it in an `if`, where set -e does not
# apply, so every step returns on failure.
trust_install() {
  local label="$1" where="$2" name="$3" verify="$4"
  local dst refresh bundle tmp new_fp old_fp
  if command -v update-ca-certificates >/dev/null 2>&1; then
    echo "$label: Ubuntu-family (update-ca-certificates)"
    dst="/usr/local/share/ca-certificates/$name.crt"
    refresh="update-ca-certificates"
    bundle="/etc/ssl/certs/ca-certificates.crt"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    echo "$label: RHEL-family (update-ca-trust)"
    dst="/etc/pki/ca-trust/source/anchors/$name.crt"
    refresh="update-ca-trust extract"
    bundle="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
  else
    echo "ERROR: No supported trust store tool found (need update-ca-certificates or update-ca-trust)" >&2
    return 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found on $where; install it (apt/dnf install openssl)" >&2
    return 1
  fi
  tmp="$(mktemp)" || return 1
  cat > "$tmp" || { rm -f "$tmp"; return 1; }
  new_fp="$(fp_of "$tmp")"
  if [ -z "$new_fp" ]; then
    echo "ERROR: Bad CA cert" >&2; rm -f "$tmp"; return 1
  fi
  if [ -f "$dst" ]; then
    old_fp="$(fp_of "$dst")"
    if [ "$old_fp" != "$new_fp" ]; then
      echo "WARNING: replacing a different lab's root on $where ($dst)" >&2
    fi
  fi
  cat "$tmp" > "$dst" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  chmod 0644 "$dst" || return 1
  $refresh >/dev/null || { echo "ERROR: $refresh failed on $where" >&2; return 1; }
  echo "Installed: $dst"
  openssl x509 -in "$dst" -noout -subject -fingerprint -sha256 || return 1
  if [ "$verify" = 1 ]; then
    # -trusted, not -CAfile: -CAfile also consults the default CA path, so it
    # can pass for a cert that is not in the bundle.
    if ! openssl verify -trusted "$bundle" "$dst" >/dev/null 2>&1; then
      echo "ERROR: lab root not found in $bundle on $where after $refresh" >&2
      return 1
    fi
    echo "Verified: lab root is in $bundle"
  fi
}

CERT="$(mktemp)"
trap 'rm -f "$CERT"' EXIT
echo '__B64_CERT__' | base64 -d > "$CERT"

if ! trust_install "Trust store" "host" "$TRUST_NAME" "$VERIFY_TRUST" < "$CERT"; then
  exit 1
fi

# Clean up stale temp file from older script versions
rm -f /tmp/company-lab-root-ca.crt

# Install into systemd-nspawn container if requested
if [ -n "$CONTAINER" ]; then
  echo ""
  echo "Installing CA cert into nspawn container: $CONTAINER"
  if ! command -v machinectl >/dev/null 2>&1; then
    echo "WARNING: container '$CONTAINER' skipped: machinectl not found (install systemd-container)" >&2
  elif ! machinectl status "$CONTAINER" >/dev/null 2>&1; then
    echo "WARNING: container '$CONTAINER' is not running — skipped" >&2
  else
    LEADER=$(machinectl show "$CONTAINER" -p Leader --value)

    # Same function, run inside the container's namespaces with its own tools.
    if ! nsenter -t "$LEADER" -m -p -u -- bash -c "$(declare -f fp_of trust_install); trust_install \"\$@\"" _ \
        "Container $CONTAINER trust store" "container $CONTAINER" "$TRUST_NAME" "$VERIFY_TRUST" < "$CERT"; then
      echo "ERROR: CA cert could not be installed in container $CONTAINER" >&2
      exit 1
    fi

    # End-to-end TLS check inside the container
    if [ -n "$VERIFY_TLS_EP" ]; then
      echo ""
      echo "TLS verify (container $CONTAINER -> $VERIFY_TLS_EP):"
      if out=$(nsenter -t "$LEADER" -m -p -u -n -- bash -c \
        "echo | timeout 15 openssl s_client -connect '$VERIFY_TLS_EP' -verify_return_error -brief 2>&1"); then
        printf '%s\n' "$out" | sed -n '1,3p'
        echo "TLS OK (container)"
      else
        printf '%s\n' "$out" >&2
        echo "ERROR: TLS verification failed inside container $CONTAINER" >&2
        exit 1
      fi
    fi
  fi
fi

# End-to-end TLS check on the host
if [ -n "$VERIFY_TLS_EP" ]; then
  echo ""
  echo "TLS verify (host -> $VERIFY_TLS_EP):"
  if out=$(echo | timeout 15 openssl s_client -connect "$VERIFY_TLS_EP" -verify_return_error -brief 2>&1); then
    printf '%s\n' "$out" | sed -n '1,3p'
    echo "TLS OK (host)"
  else
    printf '%s\n' "$out" >&2
    echo "ERROR: TLS verification failed on host" >&2
    exit 1
  fi
fi
RSCRIPT
)" || return 1
  root_script="${root_script/__B64_CERT__/$b64_cert}"
  root_script="${root_script/__CONTAINER__/$CONTAINER}"
  root_script="${root_script/__VERIFY_TLS__/$VERIFY_TLS}"
  root_script="${root_script/__VERIFY__/$VERIFY}"
  root_script="${root_script/__TRUST_NAME__/$TRUST_NAME}"

  run_remote_sudo_script "$host" "$root_script" || return 1

  if [[ "$VERIFY" -eq 1 ]]; then
    info "[$host] done"
  else
    info "[$host] done (trust store NOT verified: --no-verify)"
  fi
}

main() {
  need_cmd ssh
  need_cmd scp
  need_cmd openssl

  parse_args "$@"
  load_hosts
  prompt_creds

  info "CA tool output dir: $CA_DIR"
  info "Resolved CA cert:   $CA_CERT"
  info "Clients file:       $CLIENTS_FILE"
  info "SSH user:           $SSH_USER"
  info "SSH port:           $SSH_PORT"
  info "Auth mode:          $AUTH_MODE"
  [[ "$AUTH_MODE" == "key" && -n "$SSH_KEY_PATH" ]] && info "SSH key:            $SSH_KEY_PATH"
  [[ -n "$CONTAINER" ]] && info "nspawn container:   $CONTAINER" || info "nspawn container:   (none)"
  [[ -n "$VERIFY_TLS" ]] && info "TLS endpoint:       $VERIFY_TLS" || info "TLS endpoint:       (none)"
  [[ "$VERIFY" -eq 1 ]] && info "Verification:       enabled" || info "Verification:       disabled"

  local total=0 ok=0 fail=0
  local failures=()

  local host
  for host in "${HOSTS[@]}"; do
    total=$((total+1))
    echo "=============================="
    echo "Target: $host"
    echo "=============================="

    if install_on_node "$host"; then
      ok=$((ok+1))
    else
      fail=$((fail+1))
      failures+=("$host")
      err "[$host] failed (continuing)"
    fi
    echo
  done

  echo "=============================="
  echo "Summary"
  echo "=============================="
  echo "Total: $total"
  echo "OK:    $ok"
  echo "Fail:  $fail"
  if [[ "$VERIFY" -eq 0 ]]; then
    echo "Note: --no-verify was set; trust stores were not verified."
  fi
  if [[ "$fail" -gt 0 ]]; then
    echo
    echo "Failed nodes:"
    printf '  %s\n' "${failures[@]}"
    exit 2
  fi
}

main "$@"