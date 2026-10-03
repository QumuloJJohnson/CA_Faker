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
#   1) pulls the CA cert from: <dir>/ca/ca.crt.pem (or <dir>/ca.crt.pem)
#   2) prompts for SSH username
#   3) prompts for SSH auth method (key or password)
#   4) prompts for the remote sudo password (or reads it from stdin with
#      --sudo-password-stdin; empty = passwordless sudo, checked per host)
#   5) copies the CA cert to each client
#   6) installs it into the system trust store: Ubuntu/Debian
#      (/usr/local/share/ca-certificates, update-ca-certificates) or
#      RHEL/Rocky/Alma (/etc/pki/ca-trust/source/anchors, update-ca-trust)
#   7) proves the refreshed system bundle contains it (skip with --no-verify)
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
#   Hosts may contain only letters, digits, '.', '_', ':' and '-'.
#
# Machine-readable results (stable interface; one line per fact on stdout):
#   RESULT <host> trust OK|FAILED|NOT-VERIFIED
#   RESULT <host> trust-replaced <old-sha256>          (informational)
#   RESULT <host> container <name> OK|SKIPPED|FAILED|NOT-VERIFIED
#   RESULT <host> tls host <host:port> OK|FAILED
#   RESULT <host> tls container <name> <host:port> OK|FAILED
# With --remove:
#   RESULT <host> trust REMOVED|FAILED
#   RESULT <host> container <name> trust REMOVED|FAILED
# <host> is the line from the clients file. A missing line means not proven.
#
# Exit codes: 0 every host done, 1 bad arguments or input, 2 a host failed.
#
# Security notes:
# - The sudo password is read from stdin (hidden) and held only in memory.
# - We do NOT place the password on any command line; it is passed via stdin.
# - The root script is base64-encoded and decoded on the remote side to avoid
#   quoting and stdin conflicts with the sudo password delivery.

set -euo pipefail

# Stock macOS bash 3.2 cannot parse the rest of this script, so this check
# runs before any function is defined.
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "ERROR: macOS needs Homebrew bash and OpenSSL: brew install bash openssl@3, then run with PATH=\"\$(brew --prefix openssl@3)/bin:\$PATH\" bash $0 ..." >&2
  else
    echo "ERROR: bash 4 or newer is required; found bash $BASH_VERSION" >&2
  fi
  exit 1
fi

VERSION="2.0.0"

CLIENTS_FILE=""
CA_DIR=""             # directory created by CA creation tool (out-dir)
CA_CERT=""            # resolved to CA_DIR/ca/ca.crt.pem
SSH_USER=""
SSH_PORT="22"
AUTH_MODE=""          # "key" or "password"
SSH_KEY_PATH=""       # used if AUTH_MODE=key (optional)
VERIFY=1
CONTAINER=""          # systemd-nspawn container name (e.g. "qcore")
VERIFY_TLS=""         # space-separated host:port list for end-to-end TLS checks
VERIFY_TLS_LIST=()
REMOVE=0
REMOVE_ROOTS=()       # normalised SHA-256 fingerprints for --remove
SUDO_STDIN=0
CONTAINER_SKIPPED=()
TRUST_NAME="company-lab-root-ca"   # trust file name on targets (.crt is appended)
CONNECT_TIMEOUT=8

# In-memory secrets
SSHPASS=""            # only if AUTH_MODE=password (sshpass)
SUDO_PASS=""          # remote sudo password; empty = passwordless sudo

usage() {
  cat <<EOF
Usage: $0 --clients <file> --ca <ca-tool-out-dir> [options]
       $0 --clients <file> --remove --remove-sha256 <hex> [--remove-sha256 <hex> ...] [options]

Required:
  --clients <file>        File with one client IP/hostname/FQDN per line
  --ca <dir>              Out-dir from CA_Faker.sh (e.g. /root/qumulo-tls)
                          CA cert is expected at: <dir>/ca/ca.crt.pem
                          (or <dir>/ca.crt.pem, e.g. a CA_Faker --ca-dir)

Optional:
  --ssh-user <name>       SSH username (if omitted, will prompt)
  --port <n>              SSH port (default: $SSH_PORT)
  --auth key              Use SSH key auth
  --auth password         Use password SSH auth (requires sshpass)
  --key <path>            SSH private key path (for --auth key)
  --container <name>      Also install cert into a systemd-nspawn container
                          on each host (e.g. --container qcore), using the
                          container's own trust store tools. A host without
                          machinectl or without that running container gets a
                          WARNING and the container is skipped.
  --verify-tls <h:p>      End-to-end TLS check against host:port after install,
                          from the host and the container. The chain AND the
                          name (or IP) are checked. The port is required; put
                          IPv6 in brackets. May be given more than once; every
                          endpoint is checked.
                          (e.g. --verify-tls stratusdatacore.qumulotest.local:443
                           or --verify-tls [2001:db8::10]:443)
  --no-verify             Skip the check that the refreshed trust store
                          contains the CA (host and container)
  --trust-name <name>     Trust file name on targets, without .crt
                          (default: $TRUST_NAME)
  --sudo-password-stdin   Read the sudo password from the first line of stdin
                          (no prompt). Empty means passwordless sudo.
  --remove                Remove lab roots instead of installing: every single-
                          cert file in the trust store holding a listed root is
                          deleted, then the refreshed bundle is proven free of
                          them (host and --container)
  --remove-sha256 <hex>   Root to remove (SHA-256, 64 uppercase hex, no colons);
                          repeatable; required with --remove
  --timeout <sec>         SSH connect timeout (default: $CONNECT_TIMEOUT)
  --version               Show version
  --help                  Show help

EOF
}

err()  { echo "ERROR: $*" >&2; }
info() { echo "INFO:  $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

# Stock macOS ships LibreSSL, which lacks -verify_hostname and -verify_ip;
# fail with the fix instead of a confusing error later.
preflight() {
  need_cmd openssl
  if [[ "$(openssl version)" != OpenSSL* ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      err "macOS needs Homebrew bash and OpenSSL: brew install bash openssl@3, then run with PATH=\"\$(brew --prefix openssl@3)/bin:\$PATH\" bash $0 ..."
    else
      err "OpenSSL (not LibreSSL) is required; found $(openssl version)"
    fi
    exit 1
  fi
}

# Same name rules as CA_Faker.sh; tests/run_tests.sh keeps the copies identical.
is_ipv4() {
  local o
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    [[ "$o" =~ ^(0|[1-9][0-9]*)$ ]] && (( 10#$o <= 255 )) || return 1
  done
}

# Prints how many 16-bit groups one side of an IPv6 address holds (a
# trailing dotted quad counts as 2); fails if a group is malformed.
ipv6_groups() {
  local s="$1" n=0 g last
  local -a gs
  [[ -z "$s" ]] && { echo 0; return 0; }
  last="${s##*:}"
  if [[ "$last" == *.* ]]; then
    is_ipv4 "$last" || return 1
    n=2
    [[ "$s" == "$last" ]] && { echo 2; return 0; }
    s="${s%:*}"
  fi
  [[ "$s" == *: || "$s" == :* ]] && return 1
  IFS=: read -r -a gs <<< "$s"
  for g in "${gs[@]}"; do
    [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    n=$((n+1))
  done
  echo "$n"
}

is_ipv6() {
  local a="$1" l r nl nr
  [[ "$a" == *::*::* ]] && return 1
  if [[ "$a" == *::* ]]; then
    l="${a%%::*}"; r="${a#*::}"
    [[ "$l" == *.* ]] && return 1
    nl="$(ipv6_groups "$l")" || return 1
    nr="$(ipv6_groups "$r")" || return 1
    (( nl + nr <= 7 ))
  else
    nl="$(ipv6_groups "$a")" || return 1
    (( nl == 8 ))
  fi
}

is_ip_literal() {
  is_ipv4 "$1" || is_ipv6 "$1"
}

# Browsers parse an all-digit or 0x-hex last label as a number (an IPv4
# address), and only accept '*' as the whole leftmost label.
is_dns_name() {
  local n="$1" label last i
  local -a labels
  [[ ${#n} -ge 1 && ${#n} -le 253 ]] || return 1
  [[ "$n" == .* || "$n" == *. || "$n" == *..* ]] && return 1
  IFS=. read -r -a labels <<< "$n"
  for i in "${!labels[@]}"; do
    label="${labels[$i]}"
    if [[ "$i" -eq 0 && "$label" == "*" ]]; then
      [[ ${#labels[@]} -ge 3 ]] || return 1
      continue
    fi
    [[ "$label" =~ ^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$ ]] || return 1
  done
  last="${labels[${#labels[@]}-1]}"
  [[ "$last" =~ ^[0-9]+$ ]] && return 1
  [[ "$last" =~ ^0[xX][0-9A-Fa-f]*$ ]] && return 1
  return 0
}

# --verify-tls is spliced into the root script and handed to s_client: an
# empty host disables the name check and a missing port silently means 4433.
check_verify_tls() {
  local ep="$1" host="" port=""
  local re_v6='^\[([^]]*)\]:([^:]*)$'
  local re_name='^([^:]*):([^:]*)$'
  if [[ "$ep" =~ $re_v6 ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    is_ipv6 "$host" || host=""
  elif [[ "$ep" =~ $re_name ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    if [[ "$host" == *'*'* ]] || ! { is_ipv4 "$host" || is_dns_name "$host"; }; then
      host=""
    fi
  fi
  if [[ -z "$host" ]] || ! [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || [[ "$port" -gt 65535 ]]; then
    err "--verify-tls must be host:port with a valid name or IP (IPv6 in brackets), e.g. stratusdatacore.qumulotest.local:443 or [2001:db8::10]:443; got '$ep'"
    exit 1
  fi
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
      --verify-tls) VERIFY_TLS_LIST+=("${2:-}"); shift 2 ;;
      --no-verify) VERIFY=0; shift 1 ;;
      --trust-name) TRUST_NAME="${2:-}"; shift 2 ;;
      --sudo-password-stdin) SUDO_STDIN=1; shift 1 ;;
      --remove) REMOVE=1; shift 1 ;;
      --remove-sha256) REMOVE_ROOTS+=("${2:-}"); shift 2 ;;
      --timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
      --version) echo "$(basename "$0") $VERSION"; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [[ -z "$CLIENTS_FILE" || ! -f "$CLIENTS_FILE" ]]; then
    err "--clients file is required and must exist"; exit 1
  fi

  local root
  if [[ "$REMOVE" -eq 1 ]]; then
    if [[ ${#REMOVE_ROOTS[@]} -eq 0 ]]; then
      err "--remove needs at least one --remove-sha256 <hex>"; exit 1
    fi
    for root in "${REMOVE_ROOTS[@]}"; do
      if ! [[ "$root" =~ ^[0-9A-F]{64}$ ]]; then
        err "--remove-sha256 must be 64 uppercase hex characters without colons; got '$root'"; exit 1
      fi
    done
    if [[ ${#VERIFY_TLS_LIST[@]} -gt 0 ]]; then
      err "--verify-tls cannot be used with --remove"; exit 1
    fi
  elif [[ ${#REMOVE_ROOTS[@]} -gt 0 ]]; then
    err "--remove-sha256 needs --remove"; exit 1
  fi

  if [[ "$REMOVE" -eq 0 ]]; then
    if [[ -z "$CA_DIR" || ! -d "$CA_DIR" ]]; then
      err "--ca must point to the CA tool output directory and must exist"; exit 1
    fi

    # Today's out-dir layout first, then a directory holding ca.crt.pem itself.
    CA_CERT="${CA_DIR%/}/ca/ca.crt.pem"
    [[ -f "$CA_CERT" ]] || CA_CERT="${CA_DIR%/}/ca.crt.pem"
    if [[ ! -f "$CA_CERT" ]]; then
      err "CA cert not found at expected path: ${CA_DIR%/}/ca/ca.crt.pem (or ${CA_DIR%/}/ca.crt.pem)"
      err "Ensure --ca points to the same --out-dir used by the CA creation tool."
      exit 1
    fi

    if ! openssl x509 -in "$CA_CERT" -noout >/dev/null 2>&1; then
      err "CA file does not look like a valid PEM X.509 cert: $CA_CERT"; exit 1
    fi
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
  local ep
  for ep in ${VERIFY_TLS_LIST[@]+"${VERIFY_TLS_LIST[@]}"}; do
    check_verify_tls "$ep"
  done
  # Safe to join with spaces: every endpoint is a validated host:port.
  VERIFY_TLS="${VERIFY_TLS_LIST[*]+${VERIFY_TLS_LIST[*]}}"
}

# Read the clients file up front so an empty file fails before any prompt.
# Hosts are spliced into the root script, so only plain names are allowed.
load_hosts() {
  local line n=0 bad=0
  HOSTS=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n+1))
    line="$(echo "$line" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    if ! [[ "$line" =~ ^[A-Za-z0-9._:-]+$ ]]; then
      err "$CLIENTS_FILE line $n: '$line' is not a valid host (letters, digits, '.', '_', ':' and '-' only)"
      bad=1
      continue
    fi
    HOSTS+=("$line")
  done < "$CLIENTS_FILE"
  [[ "$bad" -eq 0 ]] || exit 1
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

  # Empty is allowed: each host is then checked for passwordless sudo.
  if [[ "$SUDO_STDIN" -eq 1 ]]; then
    IFS= read -r SUDO_PASS || true
  else
    read -r -e -s -p "Remote sudo password for ${SSH_USER} (empty for passwordless sudo): " SUDO_PASS
    echo
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
  local sudo_cmd="sudo -S -p ''"
  if [[ -z "$SUDO_PASS" ]]; then
    if ! run_ssh_no_tty "$host" "sudo -n true" </dev/null; then
      err "[$host] no sudo password was given and ${SSH_USER} cannot sudo without one"
      return 1
    fi
    sudo_cmd="sudo -n"
  fi

  local remote_cmd
  remote_cmd="read -r _PW \
&& _S=\$(mktemp) \
&& echo '${b64_script}' | base64 -d > \"\$_S\" \
&& printf '%s\\n' \"\$_PW\" | ${sudo_cmd} bash \"\$_S\"; \
_rc=\$?; rm -f \"\$_S\"; exit \$_rc"

  # Pipe the sudo password as stdin; use no-TTY ssh to prevent interactive shell
  printf '%s\n' "$SUDO_PASS" | run_ssh_no_tty "$host" "$remote_cmd"
}

install_on_node() {
  local host="$1"

  if [[ "$REMOVE" -eq 1 ]]; then
    info "[$host] removing lab roots from the system trust store (sudo required)"
  else
    info "[$host] installing CA into system trust store (sudo required)"
  fi

  # Embed the CA cert directly in the payload — avoids SCP and the
  # temp-file permission issue (previous runs leave root-owned files in /tmp).
  local b64_cert=""
  if [[ "$REMOVE" -eq 0 ]]; then
    b64_cert="$(base64 < "$CA_CERT" | tr -d '\n')" || return 1
  fi

  local root_script
  root_script="$(cat <<'RSCRIPT'
exec </dev/null
set -euo pipefail
MODE="__MODE__"
HOST="__HOST__"
CONTAINER="__CONTAINER__"
VERIFY_TLS_EPS="__VERIFY_TLS__"
VERIFY_TRUST="__VERIFY__"
TRUST_NAME="__TRUST_NAME__"
REMOVE_ROOTS="__ROOTS__"
ANY_FAIL=0

# Normalised SHA-256 of a PEM cert; empty when the file is not a readable cert.
fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d : | tr a-f A-F || true
}

# Detect this machine's trust store tools; sets TS_DIR, TS_REFRESH, TS_BUNDLE.
# update-ca-certificates is checked first so Ubuntu hosts behave as before.
trust_family() {
  local label="$1"
  # The tool alone is not enough: a host can carry the binary without the
  # anchor directory of that family.
  if command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
    echo "$label: Ubuntu-family (update-ca-certificates)"
    TS_DIR="/usr/local/share/ca-certificates"
    TS_REFRESH="update-ca-certificates"
    TS_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
  elif command -v update-ca-trust >/dev/null 2>&1 && [ -d /etc/pki/ca-trust/source/anchors ]; then
    echo "$label: RHEL-family (update-ca-trust)"
    TS_DIR="/etc/pki/ca-trust/source/anchors"
    TS_REFRESH="update-ca-trust extract"
    TS_BUNDLE="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
  else
    echo "ERROR: No supported trust store tool found (need update-ca-certificates or update-ca-trust)" >&2
    return 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found on $2; install it (apt/dnf install openssl)" >&2
    return 1
  fi
}

# Install the lab root (PEM on stdin) into this machine's trust store and,
# when verify=1, prove the refreshed system bundle contains it. Runs on the
# host directly and inside the container through nsenter, so each side uses
# its own tools and paths. Callers run it in an `if`, where set -e does not
# apply, so every step returns on failure.
trust_install() {
  local label="$1" where="$2" name="$3" verify="$4" replaced_line="$5"
  local dst tmp new_fp old_fp
  trust_family "$label" "$where" || return 1
  dst="$TS_DIR/$name.crt"
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
      if [ -n "$replaced_line" ]; then
        echo "$replaced_line ${old_fp:-unreadable}"
      fi
    fi
  fi
  cat "$tmp" > "$dst" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  chmod 0644 "$dst" || return 1
  # SELinux hosts (RHEL family) need the anchors context on the new file.
  if command -v restorecon >/dev/null 2>&1; then restorecon "$dst" || true; fi
  $TS_REFRESH >/dev/null || { echo "ERROR: $TS_REFRESH failed on $where" >&2; return 1; }
  echo "Installed: $dst"
  openssl x509 -in "$dst" -noout -subject -fingerprint -sha256 || return 1
  if [ "$verify" = 1 ]; then
    # -trusted, not -CAfile: -CAfile also consults the default CA path, so it
    # can pass for a cert that is not in the bundle.
    if ! openssl verify -trusted "$TS_BUNDLE" "$dst" >/dev/null 2>&1; then
      echo "ERROR: lab root not found in $TS_BUNDLE on $where after $TS_REFRESH" >&2
      return 1
    fi
    echo "Verified: lab root is in $TS_BUNDLE"
  fi
}

# Delete every single-cert anchor file holding one of the listed roots, then
# prove the refreshed system bundle parses and holds none of them. A failing
# `openssl verify` is not proof (an empty bundle or an expired root fail it
# too), so every cert in the bundle is fingerprinted instead.
trust_remove() {
  local label="$1" where="$2" roots="$3"
  local refresh f n fp c chunks hit total=0 bad=0
  trust_family "$label" "$where" || return 1
  refresh="$TS_REFRESH"
  [ "$refresh" = "update-ca-certificates" ] && refresh="update-ca-certificates --fresh"
  # dotglob: hidden anchor files must be scanned too, like find -type f.
  shopt -s globstar nullglob dotglob
  for f in "$TS_DIR"/**; do
    [ -f "$f" ] || continue
    n="$(grep -c 'BEGIN CERTIFICATE' "$f" 2>/dev/null || true)"
    [ "${n:-0}" -ge 1 ] || continue
    if [ "$n" -eq 1 ]; then
      fp="$(fp_of "$f")"
      [ -n "$fp" ] || continue
      case " $roots " in
        *" $fp "*) rm -f "$f" || return 1; echo "Removed: $f" ;;
      esac
    else
      # Never edit a multi-cert file: name it and fail.
      chunks="$(mktemp -d)" || return 1
      awk -v d="$chunks" '/-----BEGIN CERTIFICATE-----/{n++; f=d"/c"n".pem"} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$f"
      hit=0
      for c in "$chunks"/c*.pem; do
        fp="$(fp_of "$c")"
        case " $roots " in *" $fp "*) [ -n "$fp" ] && hit=1 ;; esac
      done
      rm -rf "$chunks"
      if [ "$hit" -eq 1 ]; then
        echo "ERROR: $f holds several certificates, one of them a lab root; not edited — remove that cert by hand" >&2
        bad=1
      fi
    fi
  done
  $refresh >/dev/null || { echo "ERROR: $refresh failed on $where" >&2; return 1; }
  if [ ! -s "$TS_BUNDLE" ]; then
    echo "ERROR: $TS_BUNDLE is missing or empty on $where" >&2
    return 1
  fi
  chunks="$(mktemp -d)" || return 1
  if ! awk -v d="$chunks" '/-----BEGIN CERTIFICATE-----/{n++; f=d"/c"n".pem"} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$TS_BUNDLE"; then
    rm -rf "$chunks"; return 1
  fi
  for c in "$chunks"/c*.pem; do
    total=$((total+1))
    if ! fp="$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null)"; then
      echo "ERROR: a certificate in $TS_BUNDLE on $where cannot be read" >&2
      bad=1; continue
    fi
    fp="$(printf '%s\n' "$fp" | cut -d= -f2 | tr -d : | tr a-f A-F)"
    if [ -z "$fp" ]; then
      bad=1; continue
    fi
    case " $roots " in
      *" $fp "*) echo "ERROR: lab root $fp is still in $TS_BUNDLE on $where" >&2; bad=1 ;;
    esac
  done
  rm -rf "$chunks"
  if [ "$total" -lt 1 ]; then
    echo "ERROR: no certificates found in $TS_BUNDLE on $where" >&2
    bad=1
  fi
  [ "$bad" -eq 0 ]
}

# Validate a TLS endpoint with this machine's default trust store, checking
# the chain AND the name: IP literals with -verify_ip (and no SNI), names
# with -servername and -verify_hostname.
tls_check() {
  local ep="$1" h out
  local -a name_opts
  h="${ep%:*}"; h="${h#[}"; h="${h%]}"
  if [[ "$h" == *:* || "$h" =~ ^[0-9.]+$ ]]; then
    name_opts=(-verify_ip "$h")
  else
    name_opts=(-servername "$h" -verify_hostname "$h")
  fi
  if out=$(echo | timeout 15 openssl s_client -connect "$ep" "${name_opts[@]}" -verify_return_error -brief 2>&1); then
    printf '%s\n' "$out" | sed -n '1,3p'
    return 0
  fi
  printf '%s\n' "$out" >&2
  return 1
}

# Prints the container leader PID, or nothing (with a WARNING naming the
# cause) when the container cannot be used.
container_leader() {
  if ! command -v machinectl >/dev/null 2>&1; then
    echo "WARNING: container '$CONTAINER' skipped: machinectl not found (install systemd-container)" >&2
    return 1
  fi
  if ! machinectl status "$CONTAINER" >/dev/null 2>&1; then
    echo "WARNING: container '$CONTAINER' is not running — skipped" >&2
    return 1
  fi
  machinectl show "$CONTAINER" -p Leader --value
}

if [ "$MODE" = "remove" ]; then
  if trust_remove "Trust store" "$HOST" "$REMOVE_ROOTS"; then
    echo "RESULT $HOST trust REMOVED"
  else
    echo "RESULT $HOST trust FAILED"; ANY_FAIL=1
  fi
  if [ -n "$CONTAINER" ]; then
    echo ""
    echo "Removing lab roots from nspawn container: $CONTAINER"
    if LEADER="$(container_leader)" && [ -n "$LEADER" ] \
        && nsenter -t "$LEADER" -m -p -u -- bash -c "$(declare -f fp_of trust_family trust_remove); trust_remove \"\$@\"" _ \
          "Container $CONTAINER trust store" "container $CONTAINER" "$REMOVE_ROOTS"; then
      echo "RESULT $HOST container $CONTAINER trust REMOVED"
    else
      echo "ERROR: lab roots could not be removed from container $CONTAINER (if it is not running: start it and rerun)" >&2
      echo "RESULT $HOST container $CONTAINER trust FAILED"; ANY_FAIL=1
    fi
  fi
  [ "$ANY_FAIL" -eq 0 ] || exit 1
  exit 0
fi

CERT="$(mktemp)"
trap 'rm -f "$CERT"' EXIT
echo '__B64_CERT__' | base64 -d > "$CERT"

if trust_install "Trust store" "$HOST" "$TRUST_NAME" "$VERIFY_TRUST" "RESULT $HOST trust-replaced" < "$CERT"; then
  if [ "$VERIFY_TRUST" = 1 ]; then
    echo "RESULT $HOST trust OK"
  else
    echo "RESULT $HOST trust NOT-VERIFIED"
  fi
else
  echo "RESULT $HOST trust FAILED"
  exit 1
fi

# Clean up stale temp file from older script versions
rm -f /tmp/company-lab-root-ca.crt

# Install into systemd-nspawn container if requested
CSTATE=""
LEADER=""
if [ -n "$CONTAINER" ]; then
  echo ""
  echo "Installing CA cert into nspawn container: $CONTAINER"
  if ! LEADER="$(container_leader)" || [ -z "$LEADER" ]; then
    CSTATE="SKIPPED"
  elif nsenter -t "$LEADER" -m -p -u -- bash -c "$(declare -f fp_of trust_family trust_install); trust_install \"\$@\"" _ \
      "Container $CONTAINER trust store" "container $CONTAINER" "$TRUST_NAME" "$VERIFY_TRUST" "" < "$CERT"; then
    if [ "$VERIFY_TRUST" = 1 ]; then CSTATE="OK"; else CSTATE="NOT-VERIFIED"; fi
  else
    echo "ERROR: CA cert could not be installed in container $CONTAINER" >&2
    CSTATE="FAILED"; ANY_FAIL=1
  fi
  echo "RESULT $HOST container $CONTAINER $CSTATE"
fi

# Endpoints are validated host:port values; -f stops '[v6]' being globbed.
set -f
for EP in $VERIFY_TLS_EPS; do
  [ "$CSTATE" = "OK" ] || [ "$CSTATE" = "NOT-VERIFIED" ] || continue
  echo ""
  echo "TLS verify (container $CONTAINER -> $EP):"
  if nsenter -t "$LEADER" -m -p -u -n -- bash -c "$(declare -f tls_check); tls_check \"\$1\"" _ "$EP"; then
    echo "TLS OK (container $CONTAINER): chain and name validated for $EP"
    echo "RESULT $HOST tls container $CONTAINER $EP OK"
  else
    echo "ERROR: trust store installed OK, but TLS endpoint $EP did not validate in container $CONTAINER (expected if the cert has not been applied to the cluster yet — README step 3)" >&2
    echo "RESULT $HOST tls container $CONTAINER $EP FAILED"
    ANY_FAIL=1
  fi
done

for EP in $VERIFY_TLS_EPS; do
  echo ""
  echo "TLS verify (host -> $EP):"
  if tls_check "$EP"; then
    echo "TLS OK (host): chain and name validated for $EP"
    echo "RESULT $HOST tls host $EP OK"
  else
    echo "ERROR: trust store installed OK, but TLS endpoint $EP did not validate (expected if the cert has not been applied to the cluster yet — README step 3)" >&2
    echo "RESULT $HOST tls host $EP FAILED"
    ANY_FAIL=1
  fi
done
set +f

[ "$ANY_FAIL" -eq 0 ] || exit 1
RSCRIPT
)" || return 1
  root_script="${root_script/__B64_CERT__/$b64_cert}"
  root_script="${root_script/__CONTAINER__/$CONTAINER}"
  root_script="${root_script/__VERIFY_TLS__/$VERIFY_TLS}"
  root_script="${root_script/__VERIFY__/$VERIFY}"
  root_script="${root_script/__TRUST_NAME__/$TRUST_NAME}"
  root_script="${root_script/__HOST__/$host}"
  if [[ "$REMOVE" -eq 1 ]]; then
    root_script="${root_script/__MODE__/remove}"
  else
    root_script="${root_script/__MODE__/install}"
  fi
  root_script="${root_script/__ROOTS__/${REMOVE_ROOTS[*]+${REMOVE_ROOTS[*]}}}"

  # Keep a copy of the remote output to read this host's RESULT lines.
  local out_file
  out_file="$(mktemp)" || return 1
  if ! run_remote_sudo_script "$host" "$root_script" | tee "$out_file"; then
    rm -f "$out_file"
    return 1
  fi

  local notes=""
  if [[ "$REMOVE" -eq 0 && "$VERIFY" -eq 0 ]]; then
    notes+=" (trust store NOT verified: --no-verify)"
  fi
  if [[ -n "$CONTAINER" ]] && grep -qFx "RESULT $host container $CONTAINER SKIPPED" "$out_file"; then
    notes+=" (container $CONTAINER SKIPPED)"
    CONTAINER_SKIPPED+=("$host")
  fi
  rm -f "$out_file"
  info "[$host] done$notes"
}

main() {
  preflight
  need_cmd ssh
  need_cmd scp

  parse_args "$@"
  load_hosts
  prompt_creds

  info "CA tool output dir: $CA_DIR"
  [[ "$REMOVE" -eq 1 ]] && info "Mode:               remove ${#REMOVE_ROOTS[@]} lab root(s)"
  [[ "$REMOVE" -eq 0 ]] && info "Resolved CA cert:   $CA_CERT"
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
  if [[ "$REMOVE" -eq 0 && "$VERIFY" -eq 0 ]]; then
    echo "Note: --no-verify was set; trust stores were not verified."
  fi
  if [[ ${#CONTAINER_SKIPPED[@]} -gt 0 ]]; then
    echo "Container skipped on: ${CONTAINER_SKIPPED[*]}"
  fi
  if [[ "$fail" -gt 0 ]]; then
    echo
    echo "Failed nodes:"
    printf '  %s\n' "${failures[@]}"
    exit 2
  fi
}

main "$@"