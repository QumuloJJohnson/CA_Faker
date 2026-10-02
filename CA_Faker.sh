#!/usr/bin/env bash
# configure_clusterA_qumulo_tls_ubuntu.sh
#
# Script to prepare TLS materials for Qumulo Cluster A
# up to (but NOT including) running `qq ssl_modify_certificate`.
# Runs on Linux, WSL, or macOS with Homebrew bash 4+ and OpenSSL 3.
#
# REQUIRED: --cn <fqdn>
#
# Produces in --out-dir:
#   private.key.insecure   (unencrypted PEM private key)
#   certbundle.pem         (leaf + intermediate CA + root CA, Qumulo-required order)
#   ca/ca.crt.pem          (root CA cert to distribute to Cluster B nodes)
#   ca/ca.key.pem          (root CA private key - protect!)
#   ca/intermediate.crt.pem, ca/intermediate.key.pem
#                          (intermediate CA that signs the server cert - protect the key!)
#   ca/ca.cer              (DER copy of the root CA cert, for double-click import)
# With --ca-dir, the CA (keys included) lives in that directory instead and
# only the public ca.crt.pem / intermediate.crt.pem / ca.cer are copied to ca/.
#
# Example:
#   ./CA_Faker.sh \
#     --cn datacore.company.com \
#     --san "dns:datacore.company.com,dns:*.datacore.company.com" \
#     --out-dir ./qumulo-tls
#
# Notes:
# - Qumulo expects certbundle ordering: leaf -> intermediate(s) -> root.
#   This lab script builds root -> intermediate -> leaf, so the bundle is:
#   leaf -> intermediate -> root.

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

# ---- defaults ----
CN=""  # REQUIRED runtime flag
SAN_LIST=""  # defaults per prepare_names if not provided
SAN_GIVEN=0
SAN_OPENSSL=""
NAME_NOTES=()
CHECK_NAMES=0
OUT_DIR="./qumulo-tls"
CA_DIR=""  # defaults to <out-dir>/ca
LOCK_DIR=""
CA_NAME="Company Lab Root CA"
INT_NAME="Company Lab Intermediate CA"
CA_OU="Lab CA"
CA_ORG="Company Lab"
CA_COUNTRY="US"
CA_KEY_BITS=4096
SERVER_KEY_BITS=2048
CA_DAYS=3650
SERVER_DAYS=825
FORCE_REISSUE=0

usage() {
  cat <<EOF
Usage: $0 --cn <fqdn> [options]

Required:
  --cn <fqdn>                 Server certificate Common Name (e.g. datacore.company.com)

Optional:
  --san <list>                SAN list. If omitted, defaults to "ip:<cn>" for an IP,
                              "dns:<cn>,dns:<first label>" for a dotted name
                              (e.g. dns:node1.lab.test,dns:node1), else "dns:<cn>".
                              The CN is always added if missing.
                              Format: dns:name,ip:addr (IPs must use ip:)
                              Example: --san "dns:datacore.company.com,dns:*.datacore.company.com,ip:10.10.10.10"
  --out-dir <path>            Output directory (default: $OUT_DIR)
  --ca-dir <path>             Where the root + intermediate CA live
                              (default: <out-dir>/ca). Give every server of one
                              lab the same --ca-dir to share one lab CA.
  --server-days <days>        Server cert validity days (default: $SERVER_DAYS;
                              Apple devices reject more than 825)
  --ca-days <days>            CA cert validity days (default: $CA_DAYS)
  --force-reissue             Regenerate server key/cert even if present
  --check-names               Validate --cn/--san, print the final SAN list
                              (one entry per line) and exit; writes nothing
  --version                   Show version
  --help                      Show help

Outputs (in --out-dir):
  private.key.insecure
  certbundle.pem
  ca/ca.crt.pem
  ca/ca.key.pem
  ca/intermediate.crt.pem
  ca/intermediate.key.pem
  ca/ca.cer
  issued/server.crt.pem
  csr/server.csr.pem

EOF
}

err() { echo "ERROR: $*" >&2; }
info() { echo "INFO: $*" >&2; }

warn() { echo "WARNING: $*" >&2; }

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

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cn)
        CN="${2:-}"; shift 2 ;;
      --san)
        SAN_LIST="${2:-}"
        [[ -n "$SAN_LIST" ]] && SAN_GIVEN=1
        shift 2 ;;
      --out-dir)
        OUT_DIR="${2:-}"; shift 2 ;;
      --ca-dir)
        CA_DIR="${2:-}"; shift 2 ;;
      --server-days)
        SERVER_DAYS="${2:-}"; shift 2 ;;
      --ca-days)
        CA_DAYS="${2:-}"; shift 2 ;;
      --force-reissue)
        FORCE_REISSUE=1; shift 1 ;;
      --check-names)
        CHECK_NAMES=1; shift 1 ;;
      --version)
        echo "$(basename "$0") $VERSION"; exit 0 ;;
      --help|-h)
        usage; exit 0 ;;
      *)
        err "Unknown option: $1"
        usage
        exit 1 ;;
    esac
  done

  if [[ -z "$CN" ]]; then
    err "--cn is required"
    usage
    exit 1
  fi

  if ! [[ "$SERVER_DAYS" =~ ^[0-9]+$ ]] || [[ "$SERVER_DAYS" -lt 1 ]]; then
    err "--server-days must be a positive integer"; exit 1
  fi
  if ! [[ "$CA_DAYS" =~ ^[0-9]+$ ]] || [[ "$CA_DAYS" -lt 1 ]]; then
    err "--ca-days must be a positive integer"; exit 1
  fi
  if [[ "$SERVER_DAYS" -gt 825 ]]; then
    warn "Apple devices reject TLS certs valid for more than 825 days"
  fi
}

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

check_dns_name() {
  is_dns_name "$1" && return 0
  err "$1 is not a valid DNS name (letters, digits and '-' only, dot-separated; use xn-- punycode for international names; all-number names are read as IP addresses by browsers)"
  exit 1
}

# Convert SAN_LIST like "dns:a,ip:1.2.3.4,dns:*.x" into:
# "DNS:a,IP:1.2.3.4,DNS:*.x"
build_san_openssl() {
  local in="$1"
  local out=""
  IFS=',' read -r -a parts <<< "$in"
  for p in "${parts[@]}"; do
    p="$(echo "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$p" ]] && continue
    local typ="${p%%:*}"
    local val="${p#*:}"
    if [[ "$typ" == "$val" ]]; then
      err "Bad SAN entry '$p' (expected type:value like dns:example.com)"; exit 1
    fi
    case "${typ,,}" in
      dns)
        # Browsers match IPs only against IP SANs.
        if is_ip_literal "$val"; then
          err "dns:$val is an IP address; use ip:$val"; exit 1
        fi
        check_dns_name "$val"
        out+="${out:+,}DNS:${val}" ;;
      ip)
        is_ip_literal "$val" || { err "ip:$val is not a valid IP address"; exit 1; }
        out+="${out:+,}IP:${val}" ;;
      *) err "Unsupported SAN type '$typ' in '$p' (use dns: or ip:)"; exit 1 ;;
    esac
  done

  if [[ -z "$out" ]]; then
    err "SAN list resolved to empty; check --san"; exit 1
  fi
  echo "$out"
}

# Prints SAN_OPENSSL as dns:/ip: entries, one per line.
san_entries() {
  local part
  IFS=',' read -r -a parts <<< "$SAN_OPENSSL"
  for part in "${parts[@]}"; do
    case "$part" in
      DNS:*) echo "dns:${part#DNS:}" ;;
      IP:*) echo "ip:${part#IP:}" ;;
    esac
  done
}

# Builds the final SAN list before anything is generated, so a bad name
# never leaves a half-built CA behind.
prepare_names() {
  local cn_entry short
  if [[ ${#CN} -gt 64 ]]; then
    err "--cn must be 64 characters or fewer (put long names in --san)"; exit 1
  fi
  if is_ip_literal "$CN"; then
    cn_entry="ip:$CN"
  else
    check_dns_name "$CN"
    cn_entry="dns:$CN"
  fi

  if [[ "$SAN_GIVEN" -eq 0 ]]; then
    if [[ "$cn_entry" == ip:* || "$CN" == '*.'* || "$CN" != *.* ]]; then
      SAN_LIST="$cn_entry"
    else
      short="${CN%%.*}"
      if is_dns_name "$short"; then
        SAN_LIST="dns:$CN,dns:$short"
      else
        SAN_LIST="dns:$CN"
        NAME_NOTES+=("Not adding short name $short — browsers would treat it as an IP address.")
      fi
    fi
  fi

  SAN_OPENSSL="$(build_san_openssl "$SAN_LIST")"

  # Browsers ignore the CN, so it must also be a SAN entry.
  local entry found=0
  while IFS= read -r entry; do
    [[ "${entry,,}" == "${cn_entry,,}" ]] && found=1
  done < <(san_entries)
  if [[ "$found" -eq 0 ]]; then
    if [[ "$cn_entry" == ip:* ]]; then
      SAN_OPENSSL="IP:${CN},${SAN_OPENSSL}"
    else
      SAN_OPENSSL="DNS:${CN},${SAN_OPENSSL}"
    fi
    NAME_NOTES+=("Added $cn_entry to the SAN list — browsers ignore the CN and only check SANs.")
  fi
}

write_ca_extfile() {
  local extfile="$1"
  rm -f "$extfile"
  cat > "$extfile" <<EOF
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
}

write_intermediate_extfile() {
  local extfile="$1"
  rm -f "$extfile"
  cat > "$extfile" <<EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
}

# SKI/AKI are explicit because OpenSSL 1.1.1 does not add them on its own.
write_server_extfile() {
  local extfile="$1"
  local san_line="$2"
  rm -f "$extfile"
  cat > "$extfile" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${san_line}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
}

# Normalised fingerprints: OpenSSL 1.1.1 prints "SHA256 Fingerprint=",
# 3.x "sha256 Fingerprint=", so only the value after '=' is used.
cert_sha256() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr a-f A-F
}

cert_sha1() {
  openssl x509 -in "$1" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d : | tr a-f A-F
}

cert_cn() {
  openssl x509 -in "$1" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p'
}

cert_enddate() {
  openssl x509 -in "$1" -noout -enddate | cut -d= -f2
}

# Print the SAN entries found in a cert's -text output as dns:<name> or
# ip:<addr>, one per line.
sans_from_text() {
  local line part
  line="$(printf '%s\n' "$1" | sed -n '/X509v3 Subject Alternative Name:/{n;s/^[[:space:]]*//;p;}')"
  IFS=',' read -r -a parts <<< "$line"
  for part in "${parts[@]}"; do
    part="${part# }"
    case "$part" in
      DNS:*) echo "dns:${part#DNS:}" ;;
      "IP Address:"*) echo "ip:${part#IP Address:}" ;;
    esac
  done
}

# Prints the value line under an extension header (SKI/AKI), without the
# "keyid:" prefix that OpenSSL 1.1.1 adds to AKI.
ext_value() {
  printf '%s\n' "$1" | sed -n "/$2:/{n;s/^[[:space:]]*//;s/^keyid://;p;}"
}

self_check_fail() {
  err "Self-check failed: $*"
  exit 1
}

# Checks the files that will ship (staged bundle + shipped root), not the CA
# dir, so what is published is exactly what was proven.
self_check() {
  local bundle="$1" ship_ca="$2" int_crt="$3" server_crt="$4" server_key="$5" chk="$6" ship_cer="$7"
  local n entry val out root_text int_text leaf_text sans
  local -a opt

  rm -rf "$chk"
  mkdir -p "$chk"
  n="$(awk -v d="$chk" '/-----BEGIN CERTIFICATE-----/{n++; f=d"/bundle."n".pem"} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""} END{print n+0}' "$bundle")"
  [[ "$n" -eq 3 ]] || self_check_fail "certbundle.pem holds $n certificates, expected 3 (leaf, intermediate, root)"
  [[ "$(cert_sha256 "$chk/bundle.1.pem")" == "$(cert_sha256 "$server_crt")" ]] \
    || self_check_fail "certbundle.pem cert 1 is not $server_crt"
  [[ "$(cert_sha256 "$chk/bundle.2.pem")" == "$(cert_sha256 "$int_crt")" ]] \
    || self_check_fail "certbundle.pem cert 2 is not $int_crt"
  [[ "$(cert_sha256 "$chk/bundle.3.pem")" == "$(cert_sha256 "$ship_ca")" ]] \
    || self_check_fail "certbundle.pem cert 3 is not $ship_ca"
  [[ "$(openssl x509 -inform DER -in "$ship_cer" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr a-f A-F)" == "$(cert_sha256 "$ship_ca")" ]] \
    || self_check_fail "ca.cer is not the DER form of $ship_ca"

  root_text="$(openssl x509 -in "$ship_ca" -noout -text)"
  int_text="$(openssl x509 -in "$chk/bundle.2.pem" -noout -text)"
  leaf_text="$(openssl x509 -in "$chk/bundle.1.pem" -noout -text)"

  # OpenSSL 1.1.1's -x509_strict does not catch a CA without keyUsage.
  [[ "$root_text" == *"X509v3 Key Usage"*"Certificate Sign"* ]] \
    || self_check_fail "root CA has no keyUsage with Certificate Sign"
  [[ "$int_text" == *"X509v3 Key Usage"*"Certificate Sign"* ]] \
    || self_check_fail "intermediate CA has no keyUsage with Certificate Sign"
  [[ "$int_text" == *"X509v3 Authority Key Identifier"* ]] \
    || self_check_fail "intermediate CA has no Authority Key Identifier"
  [[ "$leaf_text" == *"X509v3 Authority Key Identifier"* ]] \
    || self_check_fail "server cert has no Authority Key Identifier"
  [[ "$leaf_text" == *"X509v3 Subject Alternative Name"* ]] \
    || self_check_fail "server cert has no Subject Alternative Name"
  [[ "$leaf_text" == *"TLS Web Server Authentication"* ]] \
    || self_check_fail "server cert is not marked for TLS Web Server Authentication"

  if [[ "$(openssl x509 -in "$server_crt" -pubkey -noout)" != "$(openssl pkey -in "$server_key" -pubout)" ]]; then
    self_check_fail "the server key does not match the certificate — delete issued/server.crt.pem and rerun"
  fi

  # -trusted, not -CAfile: -CAfile also consults the default CA path.
  sans="$(sans_from_text "$leaf_text")"
  [[ -n "$sans" ]] || self_check_fail "server cert lists no DNS or IP names"
  while IFS= read -r entry; do
    case "$entry" in
      dns:*)
        val="${entry#dns:}"
        [[ "$val" == '*.'* ]] && val="check.${val#\*.}"
        opt=(-verify_hostname "$val") ;;
      ip:*)
        opt=(-verify_ip "${entry#ip:}") ;;
    esac
    if ! out="$(openssl verify -x509_strict -purpose sslserver -trusted "$ship_ca" \
        -untrusted "$chk/bundle.2.pem" "${opt[@]}" "$chk/bundle.1.pem" 2>&1)"; then
      printf '%s\n' "$out" >&2
      if [[ "$(ext_value "$leaf_text" "X509v3 Authority Key Identifier")" != "$(ext_value "$int_text" "X509v3 Subject Key Identifier")" ]]; then
        self_check_fail "this server's cert was issued by a different lab CA (was --ca-dir rebuilt?) — rerun with --force-reissue, then re-apply with qq and re-push"
      fi
      self_check_fail "the chain does not validate for $entry"
    fi
  done <<< "$sans"
  rm -rf "$chk"
}

print_ready() {
  local ca_crt="$1" ca_state="$2" int_crt="$3" int_state="$4" server_crt="$5" leaf_state="$6"
  local certbundle="$7" server_key="$8" leaf_text sans suggest
  leaf_text="$(openssl x509 -in "$server_crt" -noout -text)"
  sans="$(sans_from_text "$leaf_text")"
  suggest="$(cert_cn "$server_crt")"
  [[ "$suggest" == '*'* ]] && suggest="<your-cluster>"

  cat <<EOF

READY.

Built this run (created) or kept from an earlier run (reused):
  Root CA:          $ca_state  $ca_crt
                    CN: $(cert_cn "$ca_crt")
                    expires: $(cert_enddate "$ca_crt")
                    SHA-256: $(cert_sha256 "$ca_crt")
                    SHA-1:   $(cert_sha1 "$ca_crt")
  Intermediate CA:  $int_state  $int_crt
                    CN: $(cert_cn "$int_crt")
                    expires: $(cert_enddate "$int_crt")
  Server cert:      $leaf_state  $server_crt
                    CN: $(cert_cn "$server_crt")
                    expires: $(cert_enddate "$server_crt")
  Chain valid until $(cert_enddate "$ca_crt") (root expiry).

Names covered by the server cert:
$(printf '%s\n' "$sans" | sed 's/^/  /')
Clients and browsers can ONLY connect using these names/IPs. Clients that
connect to the cluster by IP need that IP here. Add every node name, node IP
and floating IP with --san.

Files for Qumulo:
  $server_key
  $certbundle

Next steps:
  1. Linux nodes and clients - trust the root CA:
       ./CA_Pusher.sh --clients <file> --ca $OUT_DIR
     (add --container qcore for Qumulo nodes so their own processes trust the lab)
  2. Qumulo - apply the certificate (use your cluster's name, e.g. $suggest):
       qq --host <your-cluster> login -u admin
       qq --host <your-cluster> ssl_modify_certificate -c $certbundle -k $server_key
  3. Confirm end to end after applying:
       ./CA_Pusher.sh --clients <file> --ca $OUT_DIR --verify-tls <cluster-fqdn>:443

WARNING: this root can sign certs for ANY site — keep $OUT_DIR secret and remove the root when the lab ends.
When the lab is gone, delete $OUT_DIR — anyone with ca/*.key.pem can issue certs your machines will trust.

EOF
}

main() {
  preflight
  need_cmd sed

  parse_args "$@"
  prepare_names

  if [[ "$CHECK_NAMES" -eq 1 ]]; then
    local note
    for note in ${NAME_NOTES[@]+"${NAME_NOTES[@]}"}; do
      info "$note"
    done
    san_entries
    exit 0
  fi

  umask 077

  local ca_dir="${CA_DIR:-$OUT_DIR/ca}"
  local ship_dir="$OUT_DIR/ca"
  local issued_dir="$OUT_DIR/issued"
  local csr_dir="$OUT_DIR/csr"
  local tmp_dir="$OUT_DIR/tmp"

  local ca_key="$ca_dir/ca.key.pem"
  local ca_crt="$ca_dir/ca.crt.pem"
  local int_key="$ca_dir/intermediate.key.pem"
  local int_crt="$ca_dir/intermediate.crt.pem"
  local ship_ca_crt="$ship_dir/ca.crt.pem"
  local ship_int_crt="$ship_dir/intermediate.crt.pem"
  local ship_cer="$ship_dir/ca.cer"

  local server_key="$OUT_DIR/private.key.insecure"
  local server_csr="$csr_dir/server.csr.pem"
  local server_crt="$issued_dir/server.crt.pem"
  local certbundle="$OUT_DIR/certbundle.pem"

  # A root without keyUsage is rejected by strict clients; refuse to build on it.
  if [[ -f "$ca_key" && -f "$ca_crt" ]]; then
    local old_root_text
    old_root_text="$(openssl x509 -in "$ca_crt" -noout -text)"
    if [[ "$old_root_text" != *"X509v3 Key Usage"* ]]; then
      err "Existing Root CA at $ca_crt was made by an older CA_Faker and is missing keyUsage; strict clients (e.g. Python 3.13+) will reject it. Use a new --out-dir (or new --ca-dir) to build a fresh CA."
      exit 1
    fi
  fi

  mkdir -p "$ca_dir" "$ship_dir" "$issued_dir" "$csr_dir" "$tmp_dir"
  chmod 700 "$OUT_DIR" "$ca_dir" "$ship_dir" "$issued_dir" "$csr_dir" "$tmp_dir" || true

  # Own vs shared CA is decided by file identity, never by comparing strings
  # (./x/ca and ./x/ca/ are the same directory).
  local shared=0
  [[ "$ca_dir" -ef "$ship_dir" ]] || shared=1
  if [[ "$shared" -eq 1 && -f "$ship_dir/ca.key.pem" ]]; then
    err "$OUT_DIR has its own CA; use a new --out-dir for a server in a shared lab CA"
    exit 1
  fi
  if [[ "$shared" -eq 0 && -f "$ship_dir/ca.crt.pem" && ! -f "$ship_dir/ca.key.pem" ]]; then
    err "$OUT_DIR uses a shared lab CA; pass the same --ca-dir as before"
    exit 1
  fi

  # Two runs on one CA dir could build two roots or corrupt a serial file.
  LOCK_DIR="$(cd "$ca_dir" && pwd)/.lock"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCK_DIR=""
    err "another CA_Faker run is using $ca_dir; try again (if no run is active: rmdir $(cd "$ca_dir" && pwd)/.lock)"
    exit 1
  fi
  trap '[[ -n "$LOCK_DIR" ]] && rmdir "$LOCK_DIR"' EXIT

  info "Output directory: $OUT_DIR"
  info "Server CN (requested): $CN"
  info "SAN list (requested): $(san_entries | paste -sd, -)"

  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  local ca_state="reused" int_state="reused" key_state="reused" leaf_state="reused"

  # 1) Create Root CA if missing
  if [[ ! -f "$ca_key" || ! -f "$ca_crt" ]]; then
    info "Creating new Root CA"
    rm -f "$ca_key" "$ca_crt" "$tmp_dir/ca.csr.pem"
    openssl genrsa -out "$ca_key" "$CA_KEY_BITS"
    chmod 400 "$ca_key"

    # x509 -req -signkey takes extensions only from our extfile, unlike
    # req -x509, which also applies the system openssl.cnf defaults.
    write_ca_extfile "$tmp_dir/ca_ext.cnf"
    openssl req -new \
      -key "$ca_key" \
      -out "$tmp_dir/ca.csr.pem" \
      -subj "/C=${CA_COUNTRY}/O=${CA_ORG}/OU=${CA_OU}/CN=${CA_NAME} ${stamp}"
    openssl x509 -req \
      -in "$tmp_dir/ca.csr.pem" \
      -signkey "$ca_key" \
      -sha256 -days "$CA_DAYS" \
      -extfile "$tmp_dir/ca_ext.cnf" \
      -out "$ca_crt"

    chmod 444 "$ca_crt"
    ca_state="created"
  else
    info "Root CA already exists; reusing $ca_crt"
  fi

  info "CA details:"
  openssl x509 -in "$ca_crt" -noout -subject -issuer -fingerprint -sha256 >&2

  # 2) Create Intermediate CA if missing, or if the root was just rebuilt
  if [[ "$ca_state" == "created" || ! -f "$int_key" || ! -f "$int_crt" ]]; then
    info "Creating new Intermediate CA"
    rm -f "$int_key" "$int_crt" "$tmp_dir/intermediate.csr.pem"
    openssl genrsa -out "$int_key" "$CA_KEY_BITS"
    chmod 400 "$int_key"

    write_intermediate_extfile "$tmp_dir/intermediate_ext.cnf"
    openssl req -new \
      -key "$int_key" \
      -out "$tmp_dir/intermediate.csr.pem" \
      -subj "/C=${CA_COUNTRY}/O=${CA_ORG}/OU=${CA_OU}/CN=${INT_NAME} ${stamp}"
    openssl x509 -req \
      -in "$tmp_dir/intermediate.csr.pem" \
      -CA "$ca_crt" \
      -CAkey "$ca_key" \
      -CAserial "$ca_dir/ca.crt.srl" \
      -CAcreateserial \
      -sha256 -days "$CA_DAYS" \
      -extfile "$tmp_dir/intermediate_ext.cnf" \
      -out "$int_crt"

    chmod 444 "$int_crt"
    int_state="created"
  else
    info "Intermediate CA already exists; reusing $int_crt"
  fi

  # 3) Create or reuse server key
  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_key" ]]; then
    info "Generating server private key -> $server_key"
    rm -f "$server_key"
    openssl genrsa -out "$server_key" "$SERVER_KEY_BITS"
    chmod 600 "$server_key"
    key_state="created"
  else
    info "Reusing existing server private key -> $server_key"
  fi

  # Verify server key is readable (unencrypted)
  if ! openssl pkey -in "$server_key" -noout >/dev/null 2>&1; then
    err "Server key at $server_key is not readable as an unencrypted PEM key."
    err "If it's encrypted, convert it with: openssl rsa -in encrypted.key -out $server_key"
    exit 1
  fi

  # 4) Sign the server certificate. The CSR is always regenerated with the
  #    leaf, so a new key or a new --cn can never be paired with an old CSR.
  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_crt" || "$key_state" == "created" || "$int_state" == "created" ]]; then
    local note
    for note in ${NAME_NOTES[@]+"${NAME_NOTES[@]}"}; do
      info "$note"
    done
    info "Generating CSR -> $server_csr"
    rm -f "$server_csr"
    openssl req -new \
      -key "$server_key" \
      -out "$server_csr" \
      -subj "/C=US/O=Company Lab/CN=${CN}"
    chmod 644 "$server_csr"

    local extfile="$tmp_dir/server_ext.cnf"
    write_server_extfile "$extfile" "$SAN_OPENSSL"

    info "Signing server certificate -> $server_crt"
    rm -f "$server_crt"
    openssl x509 -req \
      -in "$server_csr" \
      -CA "$int_crt" \
      -CAkey "$int_key" \
      -CAserial "$ca_dir/intermediate.crt.srl" \
      -CAcreateserial \
      -out "$server_crt" \
      -days "$SERVER_DAYS" \
      -sha256 \
      -extfile "$extfile"
    chmod 444 "$server_crt"
    leaf_state="created"
  else
    info "Reusing existing server certificate (names below are read from it). Your --cn/--san were not applied; to change them rerun with --force-reissue, then re-apply certbundle.pem AND private.key.insecure with qq."
  fi

  # 5) Build certbundle.pem in Qumulo order (leaf -> intermediate -> root),
  #    the public CA copies and ca.cer in tmp/; publish them only after every
  #    self-check passes.
  local staged_bundle="$tmp_dir/certbundle.pem"
  local staged_ca="$ca_crt"
  local staged_int="$tmp_dir/ship.intermediate.crt.pem"
  local staged_cer="$tmp_dir/ca.cer"
  info "Building certbundle.pem (leaf -> intermediate -> root) -> $certbundle"
  rm -f "$staged_bundle" "$staged_int" "$staged_cer" "$tmp_dir/ship.ca.crt.pem"
  if [[ "$shared" -eq 1 ]]; then
    staged_ca="$tmp_dir/ship.ca.crt.pem"
    cp "$ca_crt" "$staged_ca"
    cp "$int_crt" "$staged_int"
  fi
  cat "$server_crt" "$int_crt" "$staged_ca" > "$staged_bundle"
  openssl x509 -in "$staged_ca" -outform DER -out "$staged_cer"

  # 6) Verification checks
  info "Self-check: chain, extensions, key match and every name in the cert..."
  self_check "$staged_bundle" "$staged_ca" "$int_crt" "$server_crt" "$server_key" "$tmp_dir/check" "$staged_cer"

  chmod 444 "$staged_bundle" "$staged_cer"
  rm -f "$certbundle" "$ship_cer"
  mv "$staged_bundle" "$certbundle"
  mv "$staged_cer" "$ship_cer"
  if [[ "$shared" -eq 1 ]]; then
    chmod 444 "$staged_ca" "$staged_int"
    rm -f "$ship_ca_crt" "$ship_int_crt"
    mv "$staged_ca" "$ship_ca_crt"
    mv "$staged_int" "$ship_int_crt"
  fi

  info "Showing server certificate subject + SANs..."
  openssl x509 -in "$server_crt" -noout -subject -issuer -dates >&2
  openssl x509 -in "$server_crt" -noout -ext subjectAltName >&2 || true

  print_ready "$ca_crt" "$ca_state" "$int_crt" "$int_state" "$server_crt" "$leaf_state" "$certbundle" "$server_key"
  if [[ "$shared" -eq 1 ]]; then
    info "Shared lab CA in $ca_dir; public copies for CA_Pusher --ca $OUT_DIR are in $ship_dir"
  fi
}

main "$@"