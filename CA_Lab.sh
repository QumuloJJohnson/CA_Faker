#!/usr/bin/env bash
# CA_Lab.sh
#
# The easy button: one lab = one CA. Fill in clusters.txt and clients.txt
# and run one command:
#   - every cluster gets a cert from the lab CA (CA_Faker.sh), applied with qq
#   - every machine listed anywhere trusts the lab root (CA_Pusher.sh)
#   - every machine is proven to validate every cluster
# It never does PKI or trust-store work itself.
#
# Runs on Linux or WSL (needs setsid). Needs: openssl, ssh, ssh-keygen,
# ssh-copy-id and sshpass (one-time key push), qq (with --clusters).
#
# clusters.txt, one cluster per line (# comments and blank lines ignored):
#   <cluster FQDN>  [dns:/ip: names for the cert]  [ssh:<node> ...]
#   stratusdatacore.qumulotest.local  ip:10.1.1.10 dns:node1.qumulotest.local ssh:10.1.1.11
# clients.txt: CA_Pusher.sh's format (one host per line).
#
# Exit codes: 0 everything listed was done and proven; 1 bad input or setup
# error (no cluster or trust store changed); 2 something not done or not proven.

set -euo pipefail

# Stock macOS bash 3.2 cannot parse the rest of this script, so this check
# runs before any function is defined.
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "ERROR: bash 4 or newer is required; found bash $BASH_VERSION" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: CA_Lab.sh needs Linux or WSL (it uses setsid and GNU tools); CA_Faker.sh and CA_Pusher.sh also run on macOS" >&2
  exit 1
fi

# A trace would print passwords.
case "$-" in
  *x*) echo "ERROR: do not trace CA_Lab — it handles passwords" >&2; exit 1 ;;
esac

VERSION="2.0.0"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
FAKER="$SCRIPT_DIR/CA_Faker.sh"
PUSHER="$SCRIPT_DIR/CA_Pusher.sh"

CLUSTERS_FILE=""
CLIENTS_FILE=""
SSH_USER=""
NODE_USER=""
NODE_CONTAINER="qcore"
CLIENT_CONTAINER=""
LAB_DIR="./lab-tls"
QQ_USER="admin"
SSH_PORT="22"
CONNECT_TIMEOUT=8
SSH_KEY=""
NEW_LAB=0
DRY_RUN=0
REMOVE=0
FORGET_HOSTS=()

LAB_ABS=""
LOCK_HELD=0
LOG_FILE=""
STAMP="$(date +%Y%m%d-%H%M%S)"
KEY=""
KEY_MODE=""
NO_KEY_YET=0
KNOWN_HOSTS_OPTS=(-o StrictHostKeyChecking=accept-new)
LAB_HAS_CA=0

CLUSTERS=()
declare -A CL_SAN=() CL_SSH=() CL_LINE=() CL_IPS=() CL_ISSUE=() CL_APPLY=() CL_SERVED=() CL_NAMES_BAD=()
CLIENT_HOSTS=()
TARGETS=()
declare -A T_HOST=() T_ROLE=() KEY_OK=() SUDO_NOPW=() T_FAIL=() T_TRUST=() T_CONT=() T_OK=() T_BAD=()
declare -A SSH_PW=() SUDO_PW=()
QQ_PW=""
NOT_DONE=()

# Secrets from the environment are read once and removed from it at once.
ENV_SSH_PW_SET="${CA_LAB_SSH_PASSWORD+1}"
ENV_SSH_PW="${CA_LAB_SSH_PASSWORD-}"
ENV_SUDO_PW_SET="${CA_LAB_SUDO_PASSWORD+1}"
ENV_SUDO_PW="${CA_LAB_SUDO_PASSWORD-}"
ENV_QQ_PW_SET="${CA_LAB_QQ_PASSWORD+1}"
ENV_QQ_PW="${CA_LAB_QQ_PASSWORD-}"
unset CA_LAB_SSH_PASSWORD CA_LAB_SUDO_PASSWORD CA_LAB_QQ_PASSWORD

usage() {
  cat <<EOF
Usage: $0 --clusters <file> --clients <file> --ssh-user <name> [options]
       $0 --remove [--lab-dir <path>] [--ssh-key <path>]
       $0 --forget <host> [--lab-dir <path>]

Files (at least one):
  --clusters <file>         Clusters to get a lab cert: <fqdn> [dns:/ip: ...] [ssh:<node> ...]
  --clients <file>          Machines that connect to lab systems (CA_Pusher format)

Optional:
  --ssh-user <name>         SSH + sudo user on every machine (prompted if omitted)
  --node-user <name>        Different SSH + sudo user for ssh: nodes (default: --ssh-user)
  --node-container <name>   Container on ssh: nodes (default: $NODE_CONTAINER; "none" to skip)
  --container <name>        Container on clients.txt hosts (default: none)
  --lab-dir <path>          Lab folder (default: $LAB_DIR)
  --qq-user <name>          Qumulo admin user (default: $QQ_USER)
  --port <n>                SSH port (default: $SSH_PORT)
  --timeout <sec>           SSH connect timeout (default: $CONNECT_TIMEOUT)
  --ssh-key <path>          Use this existing key instead of the lab key (no key push)
  --new-lab                 Allow creating a new lab CA without a TTY
  --dry-run                 Show what would be done; change nothing
  --remove                  Remove this lab from every machine in the inventory
  --forget <host>           Drop a host from the inventory without contacting it
  --version                 Show version
  --help                    Show help

Passwords are asked once each, hidden. Without a TTY they are read from
CA_LAB_SSH_PASSWORD, CA_LAB_SUDO_PASSWORD and CA_LAB_QQ_PASSWORD.

EOF
}

err()  { echo "ERROR: $*" >&2; }
info() { echo "INFO: $*" >&2; }
warn() { echo "WARNING: $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

# Stock macOS ships LibreSSL, which lacks -verify_hostname and -verify_ip.
preflight() {
  need_cmd openssl
  if [[ "$(openssl version)" != OpenSSL* ]]; then
    err "OpenSSL (not LibreSSL) is required; found $(openssl version)"
    exit 1
  fi
}

cleanup() {
  QQ_PW=""
  SSH_PW=()
  SUDO_PW=()
  # Only the lock holder owns tmp/: another run's tmp/ holds its qq
  # credential stores and per-host files.
  if [[ -n "$LAB_ABS" && "$DRY_RUN" -eq 0 && "$LOCK_HELD" -eq 1 ]]; then
    rm -rf "$LAB_ABS/tmp" "$LAB_ABS/.lock"
  fi
  return 0
}
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --clusters) CLUSTERS_FILE="${2:-}"; shift 2 ;;
      --clients) CLIENTS_FILE="${2:-}"; shift 2 ;;
      --ssh-user) SSH_USER="${2:-}"; shift 2 ;;
      --node-user) NODE_USER="${2:-}"; shift 2 ;;
      --node-container) NODE_CONTAINER="${2:-}"; shift 2 ;;
      --container) CLIENT_CONTAINER="${2:-}"; shift 2 ;;
      --lab-dir) LAB_DIR="${2:-}"; shift 2 ;;
      --qq-user) QQ_USER="${2:-}"; shift 2 ;;
      --port) SSH_PORT="${2:-}"; shift 2 ;;
      --timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
      --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
      --new-lab) NEW_LAB=1; shift 1 ;;
      --dry-run) DRY_RUN=1; shift 1 ;;
      --remove) REMOVE=1; shift 1 ;;
      --forget) FORGET_HOSTS+=("${2:-}"); shift 2 ;;
      --version) echo "$(basename "$0") $VERSION"; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [[ "$REMOVE" -eq 0 && ${#FORGET_HOSTS[@]} -eq 0 && -z "$CLUSTERS_FILE" && -z "$CLIENTS_FILE" ]]; then
    err "give --clusters and/or --clients"; usage; exit 1
  fi
  local f
  for f in "$CLUSTERS_FILE" "$CLIENTS_FILE"; do
    if [[ -n "$f" && ! -f "$f" ]]; then
      err "file not found: $f"; exit 1
    fi
  done
  if [[ -z "$LAB_DIR" ]]; then
    err "--lab-dir cannot be empty"; exit 1
  fi
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
    err "--port must be a valid TCP port"; exit 1
  fi
  if ! [[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$CONNECT_TIMEOUT" -lt 1 ]]; then
    err "--timeout must be a positive integer"; exit 1
  fi
  [[ "$NODE_CONTAINER" == "none" ]] && NODE_CONTAINER=""
  local c
  for c in "$NODE_CONTAINER" "$CLIENT_CONTAINER"; do
    if [[ -n "$c" && ! "$c" =~ ^[A-Za-z0-9._-]+$ ]]; then
      err "container names may contain only letters, digits, '.', '_' and '-'; got '$c'"; exit 1
    fi
  done
  LAB_ABS="$(readlink -m "$LAB_DIR")"
}

# Prints the normalised SHA-256 of a cert file.
fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr a-f A-F
}

lab_root() {
  echo "$LAB_ABS/ca/ca.crt.pem"
}

lab_root_fp() {
  [[ -f "$(lab_root)" ]] || return 0
  fp_of "$(lab_root)"
}

# True when $2 is one whole line of $1.
has_line() {
  [[ $'\n'"$1"$'\n' == *$'\n'"$2"$'\n'* ]]
}

check_siblings() {
  local s v
  for s in "$FAKER" "$PUSHER"; do
    if [[ ! -x "$s" ]]; then
      err "$(basename "$s") not found next to CA_Lab.sh (in $SCRIPT_DIR)"; exit 1
    fi
    v="$("$s" --version 2>/dev/null || true)"
    v="${v##* }"
    if ! [[ "${v%%.*}" =~ ^[0-9]+$ ]] || [[ "${v%%.*}" -lt "${VERSION%%.*}" ]]; then
      err "$(basename "$s") is older than CA_Lab.sh — update both"; exit 1
    fi
  done
}

# Step 1: read clusters.txt; names are checked by CA_Faker.sh --check-names.
parse_clusters() {
  local file="$1" line n=0 bad=0 fqdn tok typ val out errf sorted
  local -a toks sans nodes ips
  errf="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n+1))
    # Files edited on Windows end lines with CR.
    line="${line//$'\r'/}"
    line="${line%%#*}"
    read -r -a toks <<< "$line"
    [[ ${#toks[@]} -eq 0 ]] && continue
    fqdn="${toks[0],,}"
    if [[ "$fqdn" != *.* || "$fqdn" == *'*'* || "$fqdn" == *:* ]]; then
      err "$file line $n: '${toks[0]}' must be the cluster's FQDN (a DNS name with a dot, no wildcard)"
      bad=1; continue
    fi
    if [[ -n "${CL_LINE[$fqdn]+x}" ]]; then
      err "$file line $n: $fqdn is listed twice"
      bad=1; continue
    fi
    sans=(); nodes=(); ips=()
    for tok in "${toks[@]:1}"; do
      typ="${tok%%:*}"; val="${tok#*:}"
      if [[ "$tok" != *:* || -z "$val" ]]; then
        err "$file line $n: '$tok' is not dns:<name>, ip:<addr> or ssh:<host>"
        bad=1; continue
      fi
      case "${typ,,}" in
        dns) sans+=("dns:$val") ;;
        ip) sans+=("ip:$val"); ips+=("$val") ;;
        ssh)
          if ! [[ "$val" =~ ^[A-Za-z0-9._:-]+$ ]]; then
            err "$file line $n: ssh host '$val' may contain only letters, digits, '.', '_', ':' and '-'"
            bad=1; continue
          fi
          nodes+=("$val") ;;
        *)
          err "$file line $n: '$tok' is not dns:<name>, ip:<addr> or ssh:<host>"
          bad=1; continue ;;
      esac
    done
    local -a check=(--check-names --cn "$fqdn")
    if [[ ${#sans[@]} -gt 0 ]]; then
      check+=(--san "$(IFS=,; echo "${sans[*]}")")
    fi
    if ! out="$("$FAKER" "${check[@]}" 2>"$errf")"; then
      err "$file line $n: $(grep '^ERROR:' "$errf" | sed 's/^ERROR: //' | head -1)"
      bad=1; continue
    fi
    CLUSTERS+=("$fqdn")
    CL_SAN[$fqdn]="$(IFS=,; echo "${sans[*]+${sans[*]}}")"
    CL_SSH[$fqdn]="${nodes[*]+${nodes[*]}}"
    CL_IPS[$fqdn]="${ips[*]+${ips[*]}}"
    sorted="$(printf '%s\n' ${sans[@]+"${sans[@]}"} | LC_ALL=C sort | paste -sd' ' -)"
    CL_LINE[$fqdn]="$fqdn${sorted:+ $sorted}"
    if [[ ${#nodes[@]} -eq 0 ]]; then
      warn "$fqdn has no ssh: nodes — it gets a cert, but its own processes won't trust the lab; this run will end with exit 2"
    fi
  done < "$file"
  rm -f "$errf"
  [[ "$bad" -eq 0 ]] || exit 1
  if [[ ${#CLUSTERS[@]} -eq 0 ]]; then
    err "No clusters found in $file"; exit 1
  fi
}

parse_clients() {
  local file="$1" line n=0 bad=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n+1))
    line="$(echo "$line" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    if ! [[ "$line" =~ ^[A-Za-z0-9._:-]+$ ]]; then
      err "$file line $n: '$line' is not a valid host (letters, digits, '.', '_', ':' and '-' only)"
      bad=1; continue
    fi
    CLIENT_HOSTS+=("$line")
  done < "$file"
  [[ "$bad" -eq 0 ]] || exit 1
  if [[ ${#CLIENT_HOSTS[@]} -eq 0 ]]; then
    err "No hosts found in $file"; exit 1
  fi
}

# Clients-only mode: the clusters this lab already issued certs for.
load_lab_clusters() {
  local crt dir fqdn tok
  local -a toks
  for crt in "$LAB_ABS"/*/issued/server.crt.pem; do
    [[ -f "$crt" ]] || continue
    dir="$(dirname "$(dirname "$crt")")"
    fqdn="$(basename "$dir")"
    CLUSTERS+=("$fqdn")
    CL_IPS[$fqdn]=""
    CL_SSH[$fqdn]=""
    if [[ -f "$dir/clusters-line.txt" ]]; then
      read -r -a toks < <(sed -n 1p "$dir/clusters-line.txt")
      for tok in ${toks[@]+"${toks[@]}"}; do
        [[ "$tok" == ip:* ]] && CL_IPS[$fqdn]+="${CL_IPS[$fqdn]:+ }${tok#ip:}"
      done
    fi
  done
}

check_ssh_key() {
  local msg
  if [[ ! -f "$SSH_KEY" ]]; then
    err "--ssh-key $SSH_KEY not found"; exit 1
  fi
  if ! msg="$(ssh-keygen -y -P '' -f "$SSH_KEY" 2>&1 >/dev/null)"; then
    err "--ssh-key $SSH_KEY can't be used without a prompt: $msg"
    err "omit --ssh-key to use the lab key, or use an unencrypted key with mode 600"
    exit 1
  fi
}

root_days_left() {
  local end
  end="$(openssl x509 -in "$(lab_root)" -noout -enddate | cut -d= -f2)"
  echo $(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
}

# Step 1: check everything; nothing is changed yet.
check_inputs() {
  info "Lab folder: $LAB_ABS"
  check_siblings
  [[ -n "$CLUSTERS_FILE" ]] && parse_clusters "$CLUSTERS_FILE"
  [[ -n "$CLIENTS_FILE" ]] && parse_clients "$CLIENTS_FILE"
  [[ -n "$SSH_KEY" ]] && check_ssh_key

  [[ -f "$(lab_root)" ]] && LAB_HAS_CA=1
  if [[ -z "$CLUSTERS_FILE" ]]; then
    if [[ "$LAB_HAS_CA" -eq 0 ]]; then
      err "no lab CA yet — run with --clusters first"; exit 1
    fi
    load_lab_clusters
  fi
  if [[ "$LAB_HAS_CA" -eq 1 ]] && ! openssl x509 -in "$(lab_root)" -noout -checkend 86400 >/dev/null; then
    err "lab CA expired on $(openssl x509 -in "$(lab_root)" -noout -enddate | cut -d= -f2); delete $LAB_ABS/ca to start a new lab"
    exit 1
  fi

  if [[ -n "$CLUSTERS_FILE" && ! -d "$LAB_ABS/ca" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "Would create a NEW lab CA in $LAB_ABS"
    elif [[ "$NEW_LAB" -eq 0 ]]; then
      echo "Creating a NEW lab CA in $LAB_ABS" >&2
      if [[ ! -t 0 ]]; then
        err "no TTY to confirm a new lab CA; rerun with --new-lab (or fix --lab-dir)"; exit 1
      fi
      local ans
      read -r -p "Create it? [y/N] " ans
      [[ "$ans" == "y" || "$ans" == "Y" ]] || { err "not creating a new lab CA"; exit 1; }
    fi
  fi

  need_cmd ssh
  need_cmd ssh-keygen
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if [[ -z "$SSH_KEY" ]]; then
      need_cmd ssh-copy-id
      need_cmd sshpass
    fi
    if [[ -n "$CLUSTERS_FILE" ]]; then
      need_cmd qq
      need_cmd setsid
    fi
  fi

  if [[ -z "$SSH_USER" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "SSH + sudo user for all machines: " SSH_USER
    fi
    [[ -n "$SSH_USER" ]] || { err "--ssh-user is required"; exit 1; }
  fi
  [[ -n "$NODE_USER" ]] || NODE_USER="$SSH_USER"
}

take_lock() {
  mkdir -p "$LAB_ABS"
  chmod 700 "$LAB_ABS"
  if ! mkdir "$LAB_ABS/.lock" 2>/dev/null; then
    err "another CA_Lab run is using $LAB_ABS ($(cat "$LAB_ABS/.lock/owner" 2>/dev/null || echo unknown)); if no run is active: rm -r $LAB_ABS/.lock"
    exit 1
  fi
  LOCK_HELD=1
  echo "$$ $(uname -n)" > "$LAB_ABS/.lock/owner"
}

# Both streams go to the log; the terminal keeps them separate.
start_log() {
  mkdir -p "$LAB_ABS/logs" "$LAB_ABS/tmp"
  LOG_FILE="$LAB_ABS/logs/$STAMP.log"
  exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
}

# Step 2: SSH targets = clients.txt hosts + every ssh: node, de-duplicated
# case-insensitively; a host in both is treated as a node.
add_target() {
  local k="${1,,}"
  if [[ -z "${T_ROLE[$k]+x}" ]]; then
    TARGETS+=("$k")
    T_HOST[$k]="$1"
    T_ROLE[$k]="$2"
  elif [[ "$2" == "node" ]]; then
    T_ROLE[$k]="node"
  fi
}

build_targets() {
  local h fqdn
  for h in ${CLIENT_HOSTS[@]+"${CLIENT_HOSTS[@]}"}; do
    add_target "$h" client
  done
  for fqdn in ${CLUSTERS[@]+"${CLUSTERS[@]}"}; do
    for h in ${CL_SSH[$fqdn]:-}; do
      add_target "$h" node
    done
  done
  local k
  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    info "Target ${T_HOST[$k]}: ${T_ROLE[$k]}, user $(user_of "$k"), container $(container_of "$k" | sed 's/^$/(none)/')"
  done
}

user_of() {
  if [[ "${T_ROLE[$1]}" == "node" ]]; then echo "$NODE_USER"; else echo "$SSH_USER"; fi
}

container_of() {
  if [[ "${T_ROLE[$1]}" == "node" ]]; then echo "$NODE_CONTAINER"; else echo "$CLIENT_CONTAINER"; fi
}

# Key-only SSH with the agent off: a loaded agent can exhaust MaxAuthTries,
# and without IdentitiesOnly an agent or default key could pass the test.
lab_ssh() {
  local user="$1" host="$2"; shift 2
  env -u SSH_AUTH_SOCK ssh -p "$SSH_PORT" -o ConnectTimeout="$CONNECT_TIMEOUT" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i "$KEY" \
    "${KNOWN_HOSTS_OPTS[@]}" "$user@$host" "$@" </dev/null
}

# Step 3: the lab key, then a read-only key + passwordless-sudo test.
setup_key() {
  if [[ -n "$SSH_KEY" ]]; then
    KEY="$(readlink -f "$SSH_KEY")"
    KEY_MODE="own:$KEY"
  else
    KEY="$LAB_ABS/ssh/id_ed25519"
    KEY_MODE="lab"
    if [[ ! -f "$KEY" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        info "Would create the lab SSH key $KEY"
        NO_KEY_YET=1
      else
        mkdir -p "$LAB_ABS/ssh"
        chmod 700 "$LAB_ABS/ssh"
        ssh-keygen -q -t ed25519 -N "" -C "ca-lab-$(uname -n)-$STAMP" -f "$KEY"
        chmod 600 "$KEY"
        info "Created the lab SSH key $KEY"
      fi
    fi
  fi
}

probe_target() {
  local k="$1" user host
  user="$(user_of "$k")"
  host="${T_HOST[$k]}"
  KEY_OK[$k]=0
  SUDO_NOPW[$k]=0
  [[ "$NO_KEY_YET" -eq 1 ]] && return 0
  if lab_ssh "$user" "$host" true >/dev/null 2>&1; then
    KEY_OK[$k]=1
    if lab_ssh "$user" "$host" "sudo -n true" >/dev/null 2>&1; then
      SUDO_NOPW[$k]=1
    fi
  fi
}

probe_targets() {
  local k
  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    probe_target "$k"
    if [[ "${KEY_OK[$k]}" -eq 1 ]]; then
      info "${T_HOST[$k]}: key login OK$([[ "${SUDO_NOPW[$k]}" -eq 1 ]] && echo ", passwordless sudo")"
    elif [[ "$NO_KEY_YET" -eq 1 ]]; then
      info "${T_HOST[$k]}: key push needed (untested)"
    elif [[ -n "$SSH_KEY" ]]; then
      info "${T_HOST[$k]}: --ssh-key does not log in"
    else
      info "${T_HOST[$k]}: key push needed"
    fi
  done
}

# Prompts once (hidden) or takes the CA_LAB_* value; never reads stdin
# without a TTY.
ask_secret() {
  local env_set="$1" env_val="$2" prompt="$3"
  if [[ -n "$env_set" ]]; then
    REPLY_SECRET="$env_val"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    err "no TTY — set CA_LAB_*_PASSWORD or run interactively"; exit 1
  fi
  read -r -s -p "$prompt: " REPLY_SECRET
  echo >&2
}

# Inventory: one tab-separated line per (host, user):
#   host user role container key-mode root-sha256-list date
# Written before every key push and every CA_Pusher call, whatever the outcome.
# Empty fields are written as "-": read splits on tabs and would merge them.
inv_file() {
  echo "$LAB_ABS/inventory.txt"
}

inv_update() {
  local host="$1" user="$2" role="$3" cont="$4" keymode="$5" root="$6"
  local f tmp line found=0 h u r c k roots d
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  f="$(inv_file)"
  tmp="$f.tmp"
  : > "$tmp"
  if [[ -f "$f" ]]; then
    while IFS=$'\t' read -r h u r c k roots d; do
      [[ -z "$h" ]] && continue
      if [[ "${h,,}" == "${host,,}" && "$u" == "$user" ]]; then
        found=1
        # Once installed, a container stays recorded as installed.
        if [[ "$c" == *":installed" && "$cont" == "${c%%:*}:"* ]]; then
          cont="$c"
        fi
        # Once the lab key was pushed, --remove must still remove it.
        [[ "$k" == "lab" ]] && keymode="lab"
        if [[ -n "$root" && "$roots" == "-" ]]; then
          roots="$root"
        elif [[ -n "$root" && ",$roots," != *",$root,"* ]]; then
          roots="$roots,$root"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$u" "$role" "$cont" "$keymode" "$roots" "$(date +%Y-%m-%d)" >> "$tmp"
      else
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$u" "$r" "$c" "$k" "$roots" "$d" >> "$tmp"
      fi
    done < "$f"
  fi
  if [[ "$found" -eq 0 ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "$user" "$role" "$cont" "$keymode" "${root:--}" "$(date +%Y-%m-%d)" >> "$tmp"
  fi
  mv "$tmp" "$f"
}

container_field() {
  local c="$1" state="$2"
  if [[ -z "$c" ]]; then echo "-"; else echo "$c:$state"; fi
}

# Steps 4-5: SSH password, key push, sudo password, Qumulo password - in that
# order, each asked once and only when needed.
push_keys() {
  local k user host out rc
  local -a need=()
  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    [[ "${KEY_OK[$k]}" -eq 1 ]] || need+=("$k")
  done
  [[ ${#need[@]} -eq 0 ]] && return 0

  if [[ -n "$SSH_KEY" ]]; then
    for k in "${need[@]}"; do
      T_FAIL[$k]="--ssh-key $SSH_KEY does not log in as $(user_of "$k") (check the user and authorized_keys)"
    done
    return 0
  fi

  for k in "${need[@]}"; do
    user="$(user_of "$k")"
    if [[ -z "${SSH_PW[$user]+x}" ]]; then
      ask_secret "$ENV_SSH_PW_SET" "$ENV_SSH_PW" "SSH password for $user"
      SSH_PW[$user]="$REPLY_SECRET"
    fi
  done

  for k in "${need[@]}"; do
    user="$(user_of "$k")"
    host="${T_HOST[$k]}"
    inv_update "$host" "$user" "${T_ROLE[$k]}" "$(container_field "$(container_of "$k")" pending)" "$KEY_MODE" "$(lab_root_fp)"
    info "Pushing the lab key to $user@$host"
    rc=0
    # PubkeyAuthentication=no forces password auth: otherwise ssh-copy-id
    # tries the user's own keys and hangs on a passphrase prompt.
    out="$(SSHPASS="${SSH_PW[$user]}" env -u SSH_AUTH_SOCK timeout -k 5 60 sshpass -e \
      ssh-copy-id -i "$KEY.pub" -p "$SSH_PORT" -o ConnectTimeout="$CONNECT_TIMEOUT" \
      -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new "$user@$host" 2>&1 </dev/null)" || rc=$?
    probe_target "$k"
    if [[ "${KEY_OK[$k]}" -eq 1 ]]; then
      info "$host: lab key installed"
      continue
    fi
    printf '%s\n' "$out" >&2
    # ssh-copy-id may not pass sshpass's exit code through; use its output.
    if [[ "$out" == *"IDENTIFICATION HAS CHANGED"* ]]; then
      T_FAIL[$k]="host key changed — run ssh-keygen -R $host"
    elif [[ "$out" == *"Permission denied"* ]]; then
      T_FAIL[$k]="wrong SSH password for $user"
    else
      T_FAIL[$k]="key login still fails (rc $rc) — check the user's home dir and AuthorizedKeysFile"
    fi
    err "$host: ${T_FAIL[$k]}"
  done
}

ask_sudo_passwords() {
  local k user ans
  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    [[ -n "${T_FAIL[$k]:-}" || "${SUDO_NOPW[$k]}" -eq 1 ]] && continue
    user="$(user_of "$k")"
    [[ -n "${SUDO_PW[$user]+x}" ]] && continue
    if [[ -n "${SSH_PW[$user]+x}" && -z "$ENV_SUDO_PW_SET" && -t 0 ]]; then
      read -r -p "Is the sudo password for $user the same as the SSH password? [Y/n] " ans
      if [[ "$ans" != "n" && "$ans" != "N" ]]; then
        SUDO_PW[$user]="${SSH_PW[$user]}"
        continue
      fi
    fi
    ask_secret "$ENV_SUDO_PW_SET" "$ENV_SUDO_PW" "sudo password for $user"
    SUDO_PW[$user]="$REPLY_SECRET"
  done
}

# Where to reach a cluster from here: its FQDN, or the first listed IP when
# the FQDN does not resolve on this machine.
cluster_addr() {
  local fqdn="$1" ip
  if getent hosts "$fqdn" >/dev/null 2>&1; then
    echo "$fqdn:443"
    return 0
  fi
  ip="${CL_IPS[$fqdn]%% *}"
  [[ -n "$ip" ]] || return 1
  if [[ "$ip" == *:* ]]; then echo "[$ip]:443"; else echo "$ip:443"; fi
}

served_fp() {
  local fqdn="$1" addr out
  addr="$(cluster_addr "$fqdn")" || return 0
  out="$(echo | timeout 15 openssl s_client -connect "$addr" -servername "$fqdn" 2>/dev/null)" || true
  printf '%s\n' "$out" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d : | tr a-f A-F || true
}

issued_fp() {
  fp_of "$LAB_ABS/$1/issued/server.crt.pem"
}

server_days() {
  local left
  left="$(root_days_left)"
  if [[ "$left" -lt 730 ]]; then echo "$left"; else echo 730; fi
}

# Step 6a: certs for every cluster first, so a CA_Faker failure changes no
# cluster. A cluster is reissued when its clusters.txt line or the lab root
# differs from the record of its last successful issue.
issue_certs() {
  local fqdn od line_file root_before reason out
  local -a args
  for fqdn in "${CLUSTERS[@]}"; do
    od="$LAB_ABS/$fqdn"
    line_file="$od/clusters-line.txt"
    root_before="$(lab_root_fp)"
    reason=""
    if [[ ! -f "$line_file" ]]; then
      reason="new cluster"
    elif [[ "$(sed -n 1p "$line_file")" != "${CL_LINE[$fqdn]}" ]]; then
      reason="its clusters.txt line changed"
    elif [[ "$(sed -n 2p "$line_file")" != "$root_before" ]]; then
      reason="the lab CA changed"
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
      if [[ -n "$reason" ]]; then
        info "$fqdn: would issue a cert ($reason) and apply it"
      else
        info "$fqdn: cert unchanged; would apply it only if the cluster does not already serve it"
      fi
      continue
    fi
    args=(--cn "$fqdn" --out-dir "$od" --ca-dir "$LAB_ABS/ca")
    [[ -n "${CL_SAN[$fqdn]}" ]] && args+=(--san "${CL_SAN[$fqdn]}")
    if [[ -z "$root_before" ]]; then
      args+=(--ca-days 730 --server-days 730)
    else
      args+=(--server-days "$(server_days)")
    fi
    if [[ -n "$reason" ]]; then
      args+=(--force-reissue)
      info "$fqdn: issuing a cert ($reason)"
      CL_ISSUE[$fqdn]="issued ($reason)"
    else
      CL_ISSUE[$fqdn]="reused"
    fi
    if ! out="$("$FAKER" "${args[@]}" 2>&1)"; then
      printf '%s\n' "$out" >&2
      err "CA_Faker.sh failed for $fqdn; stopping (no cluster was changed)"
      exit 1
    fi
    rm -f "$line_file"
    printf '%s\n%s\n' "${CL_LINE[$fqdn]}" "$(lab_root_fp)" > "$line_file"
  done
}

qq_apply() {
  local fqdn="$1" od="$LAB_ABS/$1" cred="$LAB_ABS/tmp/$1.cred" errout rc=0
  rm -f "$cred"
  # setsid: without a controlling terminal qq reads the password from stdin.
  if ! errout="$(set +o pipefail; printf '%s\n' "$QQ_PW" \
      | setsid -w qq --host "$fqdn" --credentials-store "$cred" login -u "$QQ_USER" 2>&1 >/dev/null)"; then
    rc=1
  fi
  errout="$(printf '%s\n' "$errout" | sed -e '/may be echoed/d' -e 's/^[A-Za-z ]*[Pp]assword: //' | sed '/^$/d')"
  [[ -n "$errout" ]] && printf '%s\n' "$errout" >&2
  if [[ "$rc" -ne 0 ]]; then
    err "qq login to $fqdn as $QQ_USER failed"
    rm -f "$cred"
    return 1
  fi
  rc=0
  qq --host "$fqdn" --credentials-store "$cred" ssl_modify_certificate \
    -c "$od/certbundle.pem" -k "$od/private.key.insecure" </dev/null >&2 || rc=1
  qq --host "$fqdn" --credentials-store "$cred" logout </dev/null >/dev/null 2>&1 || true
  rm -f "$cred"
  if [[ "$rc" -ne 0 ]]; then
    err "qq ssl_modify_certificate on $fqdn failed"
    return 1
  fi
}

# Steps 6b-6c: apply (unless already served), then wait up to 60 s until the
# served leaf is the issued one.
apply_certs() {
  local fqdn want got deadline
  for fqdn in "${CLUSTERS[@]}"; do
    want="$(issued_fp "$fqdn")"
    CL_SERVED[$fqdn]=0
    if [[ "$(served_fp "$fqdn")" == "$want" ]]; then
      CL_APPLY[$fqdn]="OK (already served)"
      CL_SERVED[$fqdn]=1
      info "$fqdn already serves its lab cert; not re-applying"
      continue
    fi
    info "$fqdn: applying the cert with qq"
    if ! qq_apply "$fqdn"; then
      CL_APPLY[$fqdn]="FAILED"
      continue
    fi
    CL_APPLY[$fqdn]="OK"
    deadline=$((SECONDS + 60))
    while :; do
      got="$(served_fp "$fqdn")"
      if [[ "$got" == "$want" ]]; then
        CL_SERVED[$fqdn]=1
        break
      fi
      [[ "$SECONDS" -ge "$deadline" ]] && break
      sleep 3
    done
    [[ "${CL_SERVED[$fqdn]}" -eq 1 ]] || err "$fqdn: still not serving its new cert after 60 s"
  done
}

# Clients-only mode: one check per cluster, no wait.
check_served() {
  local fqdn
  for fqdn in "${CLUSTERS[@]}"; do
    CL_SERVED[$fqdn]=0
    [[ "$(served_fp "$fqdn")" == "$(issued_fp "$fqdn")" ]] && CL_SERVED[$fqdn]=1
  done
}

served_clusters() {
  local fqdn
  for fqdn in "${CLUSTERS[@]}"; do
    [[ "${CL_SERVED[$fqdn]:-0}" -eq 1 ]] && echo "$fqdn"
  done
  return 0
}

# Step 7: one CA_Pusher run per target, so results are per host. A fact
# counts only from its exact RESULT ... OK line; a missing line is FAILED.
trust_and_prove() {
  local k host user c out clients root root12 fqdn ep s pw
  local -a args k_list
  mapfile -t k_list < <(served_clusters)
  root="$(lab_root_fp)"
  root12="$(printf '%s' "${root:0:12}" | tr A-F a-f)"
  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    host="${T_HOST[$k]}"
    user="$(user_of "$k")"
    c="$(container_of "$k")"
    [[ -n "${T_FAIL[$k]:-}" ]] && continue
    clients="$LAB_ABS/tmp/clients.$k.txt"
    printf '%s\n' "$host" > "$clients"
    args=(--clients "$clients" --ca "$LAB_ABS" --ssh-user "$user" --auth key --key "$KEY"
      --port "$SSH_PORT" --timeout "$CONNECT_TIMEOUT" --trust-name "company-lab-root-ca-$root12"
      --sudo-password-stdin)
    [[ -n "$c" ]] && args+=(--container "$c")
    for fqdn in ${k_list[@]+"${k_list[@]}"}; do
      args+=(--verify-tls "$fqdn:443")
    done
    inv_update "$host" "$user" "${T_ROLE[$k]}" "$(container_field "$c" pending)" "$KEY_MODE" "$root"
    pw=""
    [[ "${SUDO_NOPW[$k]}" -eq 1 ]] || pw="${SUDO_PW[$user]:-}"
    info "Trusting the lab on $host (CA_Pusher.sh)"
    out="$(printf '%s\n' "$pw" | env -u SSH_AUTH_SOCK "$PUSHER" "${args[@]}")" || true
    printf '%s\n' "$out" >&2

    T_TRUST[$k]="FAILED"
    has_line "$out" "RESULT $host trust OK" && T_TRUST[$k]="OK"
    T_CONT[$k]=""
    if [[ -n "$c" ]]; then
      T_CONT[$k]="FAILED"
      for s in OK SKIPPED FAILED; do
        has_line "$out" "RESULT $host container $c $s" && T_CONT[$k]="$s"
      done
      if [[ "${T_CONT[$k]}" == "OK" ]]; then
        inv_update "$host" "$user" "${T_ROLE[$k]}" "$c:installed" "$KEY_MODE" "$root"
      elif [[ "${T_CONT[$k]}" == "SKIPPED" ]]; then
        inv_update "$host" "$user" "${T_ROLE[$k]}" "$c:skipped" "$KEY_MODE" "$root"
      fi
    fi
    while IFS= read -r s; do
      [[ "$s" == "RESULT $host trust-replaced "* ]] && warn "$host: replaced a different lab's root (${s##* })"
    done <<< "$out"

    T_OK[$k]=0
    T_BAD[$k]=""
    for fqdn in ${k_list[@]+"${k_list[@]}"}; do
      ep="$fqdn:443"
      s=1
      if ! has_line "$out" "RESULT $host tls host $ep OK"; then
        s=0; T_BAD[$k]+="${T_BAD[$k]:+, }$ep (host)"
      fi
      if [[ "${T_CONT[$k]}" == "OK" ]] && ! has_line "$out" "RESULT $host tls container $c $ep OK"; then
        s=0; T_BAD[$k]+="${T_BAD[$k]:+, }$ep (container $c)"
      fi
      [[ "$s" -eq 1 ]] && T_OK[$k]=$(( ${T_OK[$k]} + 1 ))
    done
  done
}

# Prints the dns:/ip: names in a cert, one per line.
cert_names() {
  local line part
  line="$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | sed -n '2p' | sed 's/^[[:space:]]*//')"
  IFS=',' read -r -a parts <<< "$line"
  for part in ${parts[@]+"${parts[@]}"}; do
    part="${part# }"
    case "$part" in
      DNS:*) echo "dns:${part#DNS:}" ;;
      "IP Address:"*) echo "ip:${part#IP Address:}" ;;
    esac
  done
}

# Step 8: every name in the issued cert, checked from this machine against
# the served cert, trusting only the lab root.
prove_names() {
  local fqdn entry n addr bad
  local -a opts
  for fqdn in $(served_clusters); do
    bad=""
    while IFS= read -r entry; do
      case "$entry" in
        dns:*)
          n="${entry#dns:}"
          [[ "$n" == '*.'* ]] && n="check.${n#\*.}"
          addr="$(cluster_addr "$fqdn")" || { bad+="${bad:+, }$entry (unreachable)"; continue; }
          opts=(-servername "$n" -verify_hostname "$n") ;;
        ip:*)
          n="${entry#ip:}"
          if [[ "$n" == *:* ]]; then addr="[$n]:443"; else addr="$n:443"; fi
          opts=(-verify_ip "$n") ;;
      esac
      if ! echo | timeout 15 openssl s_client -connect "$addr" "${opts[@]:0:2}" >/dev/null 2>&1; then
        bad+="${bad:+, }$entry (does not resolve or unreachable)"
      elif ! echo | timeout 15 openssl s_client -connect "$addr" "${opts[@]}" \
          -CAfile "$(lab_root)" -verify_return_error >/dev/null 2>&1; then
        bad+="${bad:+, }$entry (certificate rejected)"
      fi
    done < <(cert_names "$LAB_ABS/$fqdn/issued/server.crt.pem")
    CL_NAMES_BAD[$fqdn]="$bad"
  done
}

not_done() {
  NOT_DONE+=("$*")
}

# Step 9: summary on stdout.
print_summary() {
  local fqdn k h total node_bad line
  local -a k_list
  mapfile -t k_list < <(served_clusters)
  total="${#k_list[@]}"

  echo
  echo "=============================="
  echo "CA_Lab summary"
  echo "=============================="
  for fqdn in "${CLUSTERS[@]}"; do
    echo "Cluster $fqdn:"
    if [[ -n "$CLUSTERS_FILE" ]]; then
      echo "  cert: ${CL_ISSUE[$fqdn]}"
      echo "  cert applied: ${CL_APPLY[$fqdn]}"
      [[ "${CL_APPLY[$fqdn]}" == FAILED ]] && not_done "$fqdn: cert not applied"
    fi
    if [[ "${CL_SERVED[$fqdn]}" -eq 1 ]]; then
      echo "  served cert matches: OK"
    else
      echo "  served cert matches: FAILED"
      not_done "$fqdn: served cert is not the lab cert"
    fi
    [[ -n "$CLUSTERS_FILE" ]] || continue
    if [[ "${CL_SERVED[$fqdn]}" -eq 1 ]]; then
      if [[ -z "${CL_NAMES_BAD[$fqdn]}" ]]; then
        echo "  all names covered by served cert: OK"
      else
        echo "  all names covered by served cert: FAILED (${CL_NAMES_BAD[$fqdn]})"
        not_done "$fqdn: names not proven: ${CL_NAMES_BAD[$fqdn]}"
      fi
    else
      echo "  all names covered by served cert: FAILED (not served)"
    fi
    if [[ -z "${CL_SSH[$fqdn]}" ]]; then
      echo "  trusted on nodes: SKIPPED (no ssh: nodes)"
      not_done "$fqdn: trusted on nodes SKIPPED (no ssh: nodes)"
      continue
    fi
    node_bad=""
    for h in ${CL_SSH[$fqdn]}; do
      k="${h,,}"
      if [[ -n "${T_FAIL[$k]:-}" || "${T_TRUST[$k]:-}" != OK || "${T_OK[$k]:-0}" -ne "$total" ]] \
          || [[ -n "$NODE_CONTAINER" && "${T_CONT[$k]:-}" != OK ]]; then
        node_bad+="${node_bad:+, }$h"
      fi
    done
    if [[ -z "$node_bad" ]]; then
      echo "  trusted on nodes: OK"
    else
      echo "  trusted on nodes: FAILED ($node_bad)"
      not_done "$fqdn: nodes not proven: $node_bad"
    fi
  done

  for k in ${TARGETS[@]+"${TARGETS[@]}"}; do
    h="${T_HOST[$k]}"
    echo "Host $h (${T_ROLE[$k]}, $(user_of "$k")):"
    if [[ -n "${T_FAIL[$k]:-}" ]]; then
      echo "  FAILED: ${T_FAIL[$k]}"
      not_done "$h: ${T_FAIL[$k]}"
      continue
    fi
    echo "  trusts lab CA: ${T_TRUST[$k]}"
    [[ "${T_TRUST[$k]}" == OK ]] || not_done "$h: does not trust the lab CA"
    line="  validates ${T_OK[$k]}/$total clusters"
    [[ -n "${T_BAD[$k]}" ]] && line+=" (failing: ${T_BAD[$k]})"
    echo "$line"
    [[ "${T_OK[$k]}" -eq "$total" ]] || not_done "$h: validates ${T_OK[$k]}/$total clusters (${T_BAD[$k]})"
    if [[ -n "$(container_of "$k")" ]]; then
      case "${T_CONT[$k]}" in
        OK) echo "  container $(container_of "$k"): OK" ;;
        SKIPPED)
          if [[ "${T_ROLE[$k]}" == node ]]; then
            echo "  container $(container_of "$k"): FAILED (skipped: not running or no machinectl)"
            not_done "$h: container $(container_of "$k") skipped on a cluster node"
          else
            echo "  container skipped"
          fi ;;
        *)
          echo "  container $(container_of "$k"): FAILED"
          not_done "$h: container $(container_of "$k") not proven" ;;
      esac
    fi
  done

  echo
  if [[ ${#NOT_DONE[@]} -gt 0 ]]; then
    echo "Not done:"
    printf '  - %s\n' "${NOT_DONE[@]}"
    echo
  fi
  print_lab_footer
}

print_lab_footer() {
  local root comment=""
  root="$(lab_root)"
  if [[ -f "$root" ]]; then
    echo "Desktops/browsers: see README step 5. Root CN: $(openssl x509 -in "$root" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')"
    echo "  SHA-1: $(openssl x509 -in "$root" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
    echo "  Chain valid until $(openssl x509 -in "$root" -noout -enddate | cut -d= -f2) (root expiry)."
  fi
  [[ -f "$LAB_ABS/ssh/id_ed25519.pub" ]] && comment="$(awk '{print $3}' "$LAB_ABS/ssh/id_ed25519.pub")"
  echo "Cleanup: ./CA_Lab.sh --remove --lab-dir $LAB_ABS (README \"Cleaning up after the lab\")${comment:+; lab key comment in authorized_keys: $comment}"
  echo "Lab folder: $LAB_ABS"
  [[ -n "$LOG_FILE" ]] && echo "Log: $LOG_FILE"
  echo "WARNING: this root can sign certs for ANY site — keep $LAB_ABS secret and remove the root when the lab ends."
}

# --remove, step for one host: drop the lab key from authorized_keys, then
# prove with a fresh connection that the key is refused.
remove_lab_key() {
  local user="$1" host="$2" kt kb script out rc=0
  read -r kt kb _ < "$LAB_ABS/ssh/id_ed25519.pub"
  # Rewrites in place (owner and mode kept) only if the filter succeeded and
  # kept exactly the lines it did not match.
  script='f="$HOME/.ssh/authorized_keys"
[ -f "$f" ] || exit 0
t="$(mktemp)" || exit 1
if ! awk -v kt="KT" -v kb="KB" -v cnt="$t.cnt" '\''{ l = $0; sub(/\r$/, "", l); n = split(l, a, /[ \t]+/); hit = 0; for (i = 1; i < n; i++) if (a[i] == kt && a[i+1] == kb) hit = 1; if (hit) m++; else { print; k++ } } END { print m+0, k+0 > cnt }'\'' "$f" > "$t"; then
  rm -f "$t" "$t.cnt"; exit 1
fi
read m k < "$t.cnt"
orig="$(awk '\''END { print NR }'\'' "$f")"
if [ "$k" -ne $((orig - m)) ]; then rm -f "$t" "$t.cnt"; exit 1; fi
if [ "$m" -gt 0 ]; then cat "$t" > "$f" || { rm -f "$t" "$t.cnt"; exit 1; }; fi
rm -f "$t" "$t.cnt"'
  script="${script/KT/$kt}"
  script="${script/KB/$kb}"
  if ! lab_ssh "$user" "$host" "$script" >&2; then
    err "$host: could not edit ~/.ssh/authorized_keys for $user"
    echo "FAILED"
    return 0
  fi
  out="$(env -u SSH_AUTH_SOCK ssh -p "$SSH_PORT" -o ConnectTimeout="$CONNECT_TIMEOUT" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PreferredAuthentications=publickey -o ControlPath=none -o StrictHostKeyChecking=yes \
    -i "$LAB_ABS/ssh/id_ed25519" "$user@$host" true 2>&1 </dev/null)" || rc=$?
  # Only a refused key proves removal: refused connections, timeouts, DNS and
  # host-key errors also exit 255.
  if [[ "$rc" -eq 255 && "$out" == *"Permission denied ("* ]]; then
    echo "REMOVED"
  else
    printf '%s\n' "$out" >&2
    echo "FAILED"
  fi
}

remove_lab() {
  local f h u r c k roots d own_missing="" out root key_state cont_ok pw idx
  local -a lines=() keep=() args
  f="$(inv_file)"
  if [[ ! -f "$f" ]]; then
    err "no inventory at $f — nothing to remove (check --lab-dir)"; exit 1
  fi
  check_siblings
  need_cmd ssh
  [[ -n "$SSH_KEY" ]] && check_ssh_key
  mapfile -t lines < "$f"
  for idx in "${!lines[@]}"; do
    IFS=$'\t' read -r h u r c k roots d <<< "${lines[$idx]}"
    if [[ "$k" == own:* && -z "$SSH_KEY" ]]; then
      own_missing+="${own_missing:+, }$h (was ${k#own:})"
    fi
  done
  if [[ -n "$own_missing" ]]; then
    err "--remove needs --ssh-key for $own_missing"; exit 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    for idx in "${!lines[@]}"; do
      IFS=$'\t' read -r h u r c k roots d <<< "${lines[$idx]}"
      info "Would remove from $u@$h: roots ${roots//,/ }$([[ "$c" == *:installed || "$c" == *:pending ]] && echo " (and container ${c%%:*})")$([[ "$k" == lab ]] && echo "; then the lab key")"
    done
    return 0
  fi
  take_lock
  start_log

  for idx in "${!lines[@]}"; do
    IFS=$'\t' read -r h u r c k roots d <<< "${lines[$idx]}"
    if [[ "$k" == lab ]]; then KEY="$LAB_ABS/ssh/id_ed25519"; else KEY="$(readlink -f "$SSH_KEY")"; fi
    pw=""
    if ! lab_ssh "$u" "$h" "sudo -n true" >/dev/null 2>&1; then
      if [[ -z "${SUDO_PW[$u]+x}" ]]; then
        ask_secret "$ENV_SUDO_PW_SET" "$ENV_SUDO_PW" "sudo password for $u"
        SUDO_PW[$u]="$REPLY_SECRET"
      fi
      pw="${SUDO_PW[$u]}"
    fi
    if [[ "$roots" == "-" ]]; then
      # Roots are recorded before every push, so none recorded = none pushed.
      info "$h: no lab root was ever pushed there"
      echo "RESULT $h trust REMOVED"
      cont_ok=1
      if [[ "$k" == lab ]]; then
        key_state="$(remove_lab_key "$u" "$h")"
        echo "RESULT $h key $key_state"
        [[ "$key_state" == REMOVED ]] || cont_ok=0
      fi
      [[ "$cont_ok" -eq 1 ]] || keep+=("${lines[$idx]}")
      continue
    fi
    printf '%s\n' "$h" > "$LAB_ABS/tmp/clients.remove.txt"
    args=(--clients "$LAB_ABS/tmp/clients.remove.txt" --remove --ssh-user "$u" --auth key --key "$KEY"
      --port "$SSH_PORT" --timeout "$CONNECT_TIMEOUT" --sudo-password-stdin)
    for root in ${roots//,/ }; do
      args+=(--remove-sha256 "$root")
    done
    cont_ok=1
    if [[ "$c" == *:installed || "$c" == *:pending ]]; then
      args+=(--container "${c%%:*}")
    fi
    info "Removing this lab from $u@$h"
    out="$(printf '%s\n' "$pw" | env -u SSH_AUTH_SOCK "$PUSHER" "${args[@]}")" || true
    printf '%s\n' "$out" >&2
    if [[ "$c" == *:installed || "$c" == *:pending ]]; then
      if has_line "$out" "RESULT $h container ${c%%:*} trust REMOVED"; then
        echo "RESULT $h container ${c%%:*} trust REMOVED"
      else
        echo "RESULT $h container ${c%%:*} trust FAILED"
        cont_ok=0
      fi
    fi
    if has_line "$out" "RESULT $h trust REMOVED"; then
      echo "RESULT $h trust REMOVED"
    else
      echo "RESULT $h trust FAILED"
      cont_ok=0
    fi
    if [[ "$k" == lab ]]; then
      if [[ "$cont_ok" -eq 1 ]]; then
        key_state="$(remove_lab_key "$u" "$h")"
      else
        key_state="KEPT"
      fi
      echo "RESULT $h key $key_state"
      [[ "$key_state" == REMOVED ]] || cont_ok=0
    fi
    [[ "$cont_ok" -eq 1 ]] || keep+=("${lines[$idx]}")
  done

  rm -f "$f"
  if [[ ${#keep[@]} -gt 0 ]]; then
    printf '%s\n' "${keep[@]}" > "$f"
    echo
    echo "Not removed (rerun --remove, or --forget hosts that no longer exist):"
    printf '%s\n' "${keep[@]}" | cut -f1,2 | sed 's/^/  /'
  fi
  echo
  print_desktop_removal
  # The rerun needs the lab key and inventory, so only a clean lab may go.
  if [[ ${#keep[@]} -eq 0 ]]; then
    echo "Now delete $LAB_ABS"
  else
    echo "Keep $LAB_ABS until --remove has cleaned every host (the rerun needs its key and inventory)."
    exit 2
  fi
}

print_desktop_removal() {
  local root
  root="$(lab_root)"
  [[ -f "$root" ]] || return 0
  echo "Desktops: remove the lab root per README step 5:"
  echo "  root CN: $(openssl x509 -in "$root" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')"
  echo "  SHA-1:   $(openssl x509 -in "$root" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
}

forget_hosts() {
  local f h line
  local -a keep=()
  f="$(inv_file)"
  [[ -f "$f" ]] || { err "no inventory at $f"; exit 1; }
  take_lock
  while IFS= read -r line; do
    h="${line%%$'\t'*}"
    local drop=0 x
    for x in "${FORGET_HOSTS[@]}"; do
      [[ "${h,,}" == "${x,,}" ]] && drop=1
    done
    if [[ "$drop" -eq 1 ]]; then
      warn "$h was not cleaned; if it still exists it may still trust this lab"
    else
      keep+=("$line")
    fi
  done < "$f"
  rm -f "$f"
  [[ ${#keep[@]} -eq 0 ]] || printf '%s\n' "${keep[@]}" > "$f"
}

main() {
  preflight
  parse_args "$@"
  umask 077

  if [[ ${#FORGET_HOSTS[@]} -gt 0 ]]; then
    forget_hosts
    exit 0
  fi
  if [[ "$REMOVE" -eq 1 ]]; then
    [[ "$DRY_RUN" -eq 1 ]] || KNOWN_HOSTS_OPTS=(-o StrictHostKeyChecking=yes)
    remove_lab
    exit 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    # Read-only probes must not touch known_hosts either.
    KNOWN_HOSTS_OPTS=(-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
  fi

  check_inputs
  if [[ "$DRY_RUN" -eq 0 ]]; then
    take_lock
    start_log
    info "Lab folder: $LAB_ABS"
  fi
  build_targets
  setup_key
  probe_targets
  if [[ "$DRY_RUN" -eq 1 ]]; then
    [[ -n "$CLUSTERS_FILE" ]] && issue_certs
    info "Dry run: nothing was changed"
    exit 0
  fi

  push_keys
  ask_sudo_passwords
  if [[ -n "$CLUSTERS_FILE" ]]; then
    ask_secret "$ENV_QQ_PW_SET" "$ENV_QQ_PW" "Qumulo password for $QQ_USER"
    QQ_PW="$REPLY_SECRET"
    issue_certs
    apply_certs
  else
    check_served
  fi
  trust_and_prove
  [[ -n "$CLUSTERS_FILE" ]] && prove_names
  print_summary
  [[ ${#NOT_DONE[@]} -eq 0 ]] || exit 2
}

main "$@"
