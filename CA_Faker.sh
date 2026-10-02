#!/usr/bin/env bash
# configure_clusterA_qumulo_tls.sh
#
# Prepares TLS materials for Qumulo Cluster A (needs bash 4+; runs on Ubuntu
# and Rocky 9.3 / OpenSSL 3.0.7)
# up to (but NOT including) running `qq ssl_modify_certificate`.
#
# REQUIRED: --cn <fqdn>
#
# Produces in --out-dir:
#   private.key.insecure   (unencrypted PEM private key)
#   certbundle.pem         (leaf cert + root CA, Qumulo-required order)
#   ca/ca.crt.pem          (root CA cert to distribute to Cluster B nodes)
#   ca/ca.key.pem          (root CA private key - protect!)
#   ca/ca.srl              (CA serial number file)
#
# Example:
#   ./CA_Faker.sh \
#     --cn datacore.company.com \
#     --san "dns:datacore.company.com,dns:*.datacore.company.com" \
#     --out-dir ./qumulo-tls
#
# Notes:
# - Qumulo expects certbundle ordering: leaf -> intermediate(s) -> root.
#   This lab script uses only a root CA, so bundle is: leaf -> root.

set -euo pipefail

# ---- defaults ----
CN=""  # REQUIRED runtime flag
SAN_LIST=""  # defaults to dns:$CN if not provided
OUT_DIR="./qumulo-tls"
CA_NAME="Company Lab Root CA"
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
  --san <list>                SAN list. If omitted, defaults to "dns:<cn>"
                              Format: dns:name,ip:addr
                              Example: --san "dns:datacore.company.com,dns:*.datacore.company.com,ip:10.10.10.10"
  --out-dir <path>            Output directory (default: $OUT_DIR)
  --server-days <days>        Server cert validity days (default: $SERVER_DAYS)
  --ca-days <days>            CA cert validity days (default: $CA_DAYS)
  --force-reissue             Regenerate server key/cert even if present
  --help                      Show help

Outputs (in --out-dir):
  private.key.insecure
  certbundle.pem
  ca/ca.crt.pem
  ca/ca.key.pem
  ca/ca.srl
  issued/server.crt.pem
  csr/server.csr.pem

EOF
}

err() { echo "ERROR: $*" >&2; }
info() { echo "INFO: $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cn)
        CN="${2:-}"; shift 2 ;;
      --san)
        SAN_LIST="${2:-}"; shift 2 ;;
      --out-dir)
        OUT_DIR="${2:-}"; shift 2 ;;
      --server-days)
        SERVER_DAYS="${2:-}"; shift 2 ;;
      --ca-days)
        CA_DAYS="${2:-}"; shift 2 ;;
      --force-reissue)
        FORCE_REISSUE=1; shift 1 ;;
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

  # If SAN not provided, default to dns:<CN>
  if [[ -z "$SAN_LIST" ]]; then
    SAN_LIST="dns:${CN}"
  fi

  if ! [[ "$SERVER_DAYS" =~ ^[0-9]+$ ]] || [[ "$SERVER_DAYS" -lt 1 ]]; then
    err "--server-days must be a positive integer"; exit 1
  fi
  if ! [[ "$CA_DAYS" =~ ^[0-9]+$ ]] || [[ "$CA_DAYS" -lt 1 ]]; then
    err "--ca-days must be a positive integer"; exit 1
  fi
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
      dns) out+="${out:+,}DNS:${val}" ;;
      ip)  out+="${out:+,}IP:${val}" ;;
      *) err "Unsupported SAN type '$typ' in '$p' (use dns: or ip:)"; exit 1 ;;
    esac
  done

  if [[ -z "$out" ]]; then
    err "SAN list resolved to empty; check --san"; exit 1
  fi
  echo "$out"
}

write_server_extfile() {
  local extfile="$1"
  local san_line="$2"
  cat > "$extfile" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${san_line}
EOF
}

main() {
  need_cmd openssl
  need_cmd sed

  parse_args "$@"

  umask 077

  local ca_dir="$OUT_DIR/ca"
  local issued_dir="$OUT_DIR/issued"
  local csr_dir="$OUT_DIR/csr"
  local tmp_dir="$OUT_DIR/tmp"

  mkdir -p "$ca_dir" "$issued_dir" "$csr_dir" "$tmp_dir"
  chmod 700 "$OUT_DIR" "$ca_dir" "$issued_dir" "$csr_dir" "$tmp_dir" || true

  local ca_key="$ca_dir/ca.key.pem"
  local ca_crt="$ca_dir/ca.crt.pem"
  # Explicit serial path: the default is derived from the CA file name and
  # differs between OpenSSL/LibreSSL versions (some write ./.srl in the CWD)
  local ca_srl="$ca_dir/ca.srl"

  local server_key="$OUT_DIR/private.key.insecure"
  local server_csr="$csr_dir/server.csr.pem"
  local server_crt="$issued_dir/server.crt.pem"
  local certbundle="$OUT_DIR/certbundle.pem"

  info "Output directory: $OUT_DIR"
  info "Server CN: $CN"
  info "SAN list: $SAN_LIST"

  # 1) Create Root CA if missing
  if [[ ! -f "$ca_key" || ! -f "$ca_crt" ]]; then
    info "Creating new Root CA"
    openssl genrsa -out "$ca_key" "$CA_KEY_BITS"
    chmod 400 "$ca_key"

    openssl req -x509 -new -nodes \
      -key "$ca_key" \
      -sha256 -days "$CA_DAYS" \
      -out "$ca_crt" \
      -subj "/C=${CA_COUNTRY}/O=${CA_ORG}/CN=${CA_NAME}"

    chmod 444 "$ca_crt"
  else
    info "Root CA already exists; reusing $ca_crt"
  fi

  info "CA details:"
  openssl x509 -in "$ca_crt" -noout -subject -issuer -fingerprint -sha256 >&2

  # 2) Create or reuse server key
  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_key" ]]; then
    info "Generating server private key -> $server_key"
    openssl genrsa -out "$server_key" "$SERVER_KEY_BITS"
    chmod 600 "$server_key"
  else
    info "Reusing existing server private key -> $server_key"
  fi

  # Verify server key is readable (unencrypted)
  if ! openssl pkey -in "$server_key" -noout >/dev/null 2>&1; then
    err "Server key at $server_key is not readable as an unencrypted PEM key."
    err "If it's encrypted, convert it with: openssl rsa -in encrypted.key -out $server_key"
    exit 1
  fi

  # 3) Create CSR (or reuse if not forcing and exists)
  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_csr" ]]; then
    info "Generating CSR -> $server_csr"
    openssl req -new \
      -key "$server_key" \
      -out "$server_csr" \
      -subj "/C=US/O=Company Lab/CN=${CN}"
    chmod 644 "$server_csr"
  else
    info "Reusing existing CSR -> $server_csr"
  fi

  # 4) Sign server certificate with SANs
  local san_openssl
  san_openssl="$(build_san_openssl "$SAN_LIST")"

  local extfile="$tmp_dir/server_ext.cnf"
  write_server_extfile "$extfile" "$san_openssl"

  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_crt" ]]; then
    info "Signing server certificate -> $server_crt"
    openssl x509 -req \
      -in "$server_csr" \
      -CA "$ca_crt" \
      -CAkey "$ca_key" \
      -CAserial "$ca_srl" -CAcreateserial \
      -out "$server_crt" \
      -days "$SERVER_DAYS" \
      -sha256 \
      -extfile "$extfile"
    chmod 444 "$server_crt"
  else
    info "Reusing existing server certificate -> $server_crt"
  fi

  # 5) Build certbundle.pem in Qumulo order: leaf -> root (no intermediate in this lab)
  info "Building certbundle.pem (leaf -> root) -> $certbundle"
  cat "$server_crt" "$ca_crt" > "$certbundle"
  chmod 444 "$certbundle"

  # 6) Verification checks
  info "Verifying certificate chain (leaf signed by our CA)..."
  openssl verify -CAfile "$ca_crt" "$server_crt" >&2

  info "Showing server certificate subject + SANs..."
  openssl x509 -in "$server_crt" -noout -subject -issuer -dates >&2
  openssl x509 -in "$server_crt" -noout -ext subjectAltName >&2 || true

  cat <<EOF

READY.

Files created for Qumulo Step 4 (do NOT run here):
  $server_key
  $certbundle

Distribute this CA cert to Cluster B nodes and install it into their system
trust store (CA_Pusher.sh does this for Ubuntu/Debian and Rocky/RHEL):
  $ca_crt

Next step (manual): run the Qumulo doc Step 4 command:
  qq ssl_modify_certificate ... -c $certbundle -k $server_key

EOF
}

main "$@"