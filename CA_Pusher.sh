#!/usr/bin/env bash
# push_ca_trust_to_clusterB.sh
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
#   6) installs it into the system trust store, detected per host (and per container):
#        Ubuntu/Debian:      /usr/local/share/ca-certificates      + update-ca-certificates
#        Rocky/RHEL/Fedora:  /etc/pki/ca-trust/source/anchors      + update-ca-trust extract
#   7) verifies the CA is trusted by the system store (openssl verify)
#
# Requirements (on Cluster A):
#   - bash, ssh, scp, openssl
#   - OPTIONAL: sshpass (only if using password-based SSH)
#       Ubuntu/Debian:  sudo apt-get update && sudo apt-get install -y sshpass
#       Rocky/RHEL:     sudo dnf install -y epel-release && sudo dnf install -y sshpass
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
# - A host counts as OK only if the install (and, unless --no-verify, the trust
#   check and any --verify-tls check) succeeded; failures exit 2.

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
                          on each host (e.g. --container qcore)
  --verify-tls <h:p>     End-to-end TLS check against host:port after install, from
                          the host and the container; the cert must match host
                          (e.g. --verify-tls stratusdatacore.qumulotest.local:443)
  --no-verify             Skip the post-install system trust check
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
  # Without a port, openssl s_client silently uses 4433, so require host:port
  if [[ -n "$VERIFY_TLS" ]]; then
    if ! [[ "$VERIFY_TLS" =~ ^(.+):([0-9]+)$ ]] || [[ "${BASH_REMATCH[2]}" -lt 1 || "${BASH_REMATCH[2]}" -gt 65535 ]]; then
      err "--verify-tls must be host:port (e.g. jjdc.qumulotest.local:443), got '$VERIFY_TLS'"; exit 1
    fi
  fi
  if [[ -n "$AUTH_MODE" && "$AUTH_MODE" != "key" && "$AUTH_MODE" != "password" ]]; then
    err "--auth must be 'key' or 'password'"; exit 1
  fi
  if [[ -n "$SSH_KEY_PATH" && ! -f "$SSH_KEY_PATH" ]]; then
    err "--key path not found: $SSH_KEY_PATH"; exit 1
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
  #   2. decode the base64 payload into a private temp script (mktemp)
  #   3. run the temp script under sudo -S (password piped in, no prompt text)
  #   4. clean up and propagate the exit code
  local remote_cmd
  remote_cmd="read -r _PW \
&& _F=\$(mktemp) \
&& echo '${b64_script}' | base64 -d > \"\$_F\" \
&& printf '%s\\n' \"\$_PW\" | sudo -S -p '' bash \"\$_F\"; \
_rc=\$?; rm -f \"\$_F\"; exit \$_rc"

  # Pipe the sudo password as stdin; use no-TTY ssh to prevent interactive shell
  printf '%s\n' "$SUDO_PASS" | run_ssh_no_tty "$host" "$remote_cmd"
}

install_on_node() {
  local host="$1"

  info "[$host] installing CA into system trust store (sudo required)"

  # Embed the CA cert directly in the payload — avoids SCP and the
  # temp-file permission issue (previous runs leave root-owned files in /tmp).
  local b64_cert
  b64_cert="$(base64 < "$CA_CERT" | tr -d '\n')"

  local root_script
  root_script="$(cat <<'RSCRIPT'
set -euo pipefail
CA_PEM="$(echo '__B64_CERT__' | base64 -d)"
CONTAINER="__CONTAINER__"
VERIFY_TLS_EP="__VERIFY_TLS__"
DO_VERIFY="__VERIFY__"

# Installs the CA (PEM on stdin) into the system trust store of whatever root
# filesystem it runs in, choosing the layout by what that system provides.
# Runs on the host and, via nsenter, inside the container (which may be a
# different distro), so it is plain POSIX sh. $1 = 1 to verify trust afterwards.
INSTALL_SH='
set -eu
NAME=company-lab-root-ca
if command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
  # Ubuntu / Debian
  DST=/usr/local/share/ca-certificates/$NAME.crt
  cat > "$DST"; chmod 0644 "$DST"
  update-ca-certificates >/dev/null
elif command -v update-ca-trust >/dev/null 2>&1 && [ -d /etc/pki/ca-trust/source/anchors ]; then
  # Rocky / RHEL / Fedora
  DST=/etc/pki/ca-trust/source/anchors/$NAME.crt
  cat > "$DST"; chmod 0644 "$DST"
  if command -v restorecon >/dev/null 2>&1; then restorecon "$DST" || true; fi
  update-ca-trust extract
else
  echo "ERROR: no supported trust store (need update-ca-certificates or update-ca-trust)" >&2
  exit 1
fi
openssl x509 -in "$DST" -noout >/dev/null 2>&1 || { echo "Bad CA cert at $DST" >&2; exit 1; }
echo "Installed: $DST"
openssl x509 -in "$DST" -noout -subject -fingerprint -sha256
if [ "$1" = 1 ]; then
  # A self-signed root only verifies if the default system store trusts it
  if openssl verify "$DST" >/dev/null 2>&1; then
    echo "Trusted by system store: yes"
  else
    echo "ERROR: $DST is not trusted by the system store after update" >&2
    exit 1
  fi
fi
'

# Name the server cert must match: the endpoint host ([v6] brackets stripped),
# checked as an IP SAN for IP literals and as a DNS name otherwise
EP_HOST="${VERIFY_TLS_EP%:*}"; EP_HOST="${EP_HOST#[}"; EP_HOST="${EP_HOST%]}"
if [[ "$EP_HOST" =~ ^[0-9.]+$ || "$EP_HOST" == *:* ]]; then NAME_OPT=-verify_ip; else NAME_OPT=-verify_hostname; fi

# tls_check <label> [command prefix...]: handshake to VERIFY_TLS_EP must verify,
# including the certificate matching EP_HOST
tls_check() {
  local label="$1" out; shift
  echo ""
  echo "TLS verify ($label -> $VERIFY_TLS_EP):"
  if out="$("$@" sh -c 'echo | openssl s_client -connect "$1" -verify_return_error "$2" "$3" -brief 2>&1' \
              sh "$VERIFY_TLS_EP" "$NAME_OPT" "$EP_HOST")"; then
    printf '%s\n' "$out" | grep -E '^(Protocol version|Verification|Verified peername)' || true
    echo "TLS OK ($label)"
  else
    printf '%s\n' "$out" | tail -5 >&2
    echo "ERROR: TLS verification failed ($label)" >&2
    return 1
  fi
}

printf '%s\n' "$CA_PEM" | sh -c "$INSTALL_SH" sh "$DO_VERIFY"

# TLS checks don't stop at the first failure, so one run shows whether the
# host, the container, or both can't reach/verify the endpoint
TLS_FAILED=0

# Clean up stale temp file from older script versions
rm -f /tmp/company-lab-root-ca.crt

# Install into systemd-nspawn container if requested
if [ -n "$CONTAINER" ]; then
  echo ""
  echo "Installing CA cert into nspawn container: $CONTAINER"
  if machinectl status "$CONTAINER" >/dev/null 2>&1; then
    LEADER=$(machinectl show "$CONTAINER" -p Leader --value)
    printf '%s\n' "$CA_PEM" | nsenter -t "$LEADER" -m -p -u -- sh -c "$INSTALL_SH" sh "$DO_VERIFY"
    if [ -n "$VERIFY_TLS_EP" ]; then
      tls_check "container $CONTAINER" nsenter -t "$LEADER" -m -p -u -n -- || TLS_FAILED=1
    fi
  else
    echo "WARNING: container '$CONTAINER' is not running — skipped" >&2
  fi
fi

# End-to-end TLS check on the host
if [ -n "$VERIFY_TLS_EP" ]; then
  tls_check host || TLS_FAILED=1
fi
exit "$TLS_FAILED"
RSCRIPT
)"
  root_script="${root_script/__B64_CERT__/$b64_cert}"
  root_script="${root_script/__CONTAINER__/$CONTAINER}"
  root_script="${root_script/__VERIFY_TLS__/$VERIFY_TLS}"
  root_script="${root_script/__VERIFY__/$VERIFY}"

  # Explicit "|| return 1": callers use "if install_on_node", which disables
  # set -e inside this function, so a failed install would otherwise count as OK.
  run_remote_sudo_script "$host" "$root_script" || return 1

  info "[$host] done"
}

main() {
  need_cmd ssh
  need_cmd scp
  need_cmd openssl

  parse_args "$@"
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

  while IFS= read -r host <&3 || [[ -n "$host" ]]; do
    host="$(echo "$host" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$host" ]] && continue

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
  done 3< "$CLIENTS_FILE"

  echo "=============================="
  echo "Summary"
  echo "=============================="
  echo "Total: $total"
  echo "OK:    $ok"
  echo "Fail:  $fail"
  if [[ "$fail" -gt 0 ]]; then
    echo
    echo "Failed nodes:"
    printf '  %s\n' "${failures[@]}"
    exit 2
  fi
}

main "$@"