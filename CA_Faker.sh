#!/usr/bin/env bash
# configure_clusterA_qumulo_tls_ubuntu.sh
#
# Script to prepare TLS materials for Qumulo Cluster A
# up to (but NOT including) running `qq ssl_modify_certificate`.
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

# ---- defaults ----
CN=""  # REQUIRED runtime flag
SAN_LIST=""  # defaults to dns:$CN if not provided
OUT_DIR="./qumulo-tls"
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
  ca/intermediate.crt.pem
  ca/intermediate.key.pem
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

self_check_fail() {
  err "Self-check failed: $*"
  exit 1
}

# Checks the files that will ship (staged bundle + shipped root), not the CA
# dir, so what is published is exactly what was proven.
self_check() {
  local bundle="$1" ship_ca="$2" int_crt="$3" server_crt="$4" server_key="$5" chk="$6"
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
  need_cmd openssl
  need_cmd sed

  parse_args "$@"

  umask 077

  local ca_dir="$OUT_DIR/ca"
  local issued_dir="$OUT_DIR/issued"
  local csr_dir="$OUT_DIR/csr"
  local tmp_dir="$OUT_DIR/tmp"

  local ca_key="$ca_dir/ca.key.pem"
  local ca_crt="$ca_dir/ca.crt.pem"
  local int_key="$ca_dir/intermediate.key.pem"
  local int_crt="$ca_dir/intermediate.crt.pem"

  local server_key="$OUT_DIR/private.key.insecure"
  local server_csr="$csr_dir/server.csr.pem"
  local server_crt="$issued_dir/server.crt.pem"
  local certbundle="$OUT_DIR/certbundle.pem"

  # A root without keyUsage is rejected by strict clients; refuse to build on it.
  if [[ -f "$ca_key" && -f "$ca_crt" ]]; then
    local old_root_text
    old_root_text="$(openssl x509 -in "$ca_crt" -noout -text)"
    if [[ "$old_root_text" != *"X509v3 Key Usage"* ]]; then
      err "Existing Root CA at $ca_crt was made by an older CA_Faker and is missing keyUsage; strict clients (e.g. Python 3.13+) will reject it. Use a new --out-dir to build a fresh CA."
      exit 1
    fi
  fi

  mkdir -p "$ca_dir" "$issued_dir" "$csr_dir" "$tmp_dir"
  chmod 700 "$OUT_DIR" "$ca_dir" "$issued_dir" "$csr_dir" "$tmp_dir" || true

  info "Output directory: $OUT_DIR"
  info "Server CN (requested): $CN"
  info "SAN list (requested): $SAN_LIST"

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

  local san_openssl
  san_openssl="$(build_san_openssl "$SAN_LIST")"

  # 4) Sign the server certificate. The CSR is always regenerated with the
  #    leaf, so a new key or a new --cn can never be paired with an old CSR.
  if [[ "$FORCE_REISSUE" -eq 1 || ! -f "$server_crt" || "$key_state" == "created" || "$int_state" == "created" ]]; then
    info "Generating CSR -> $server_csr"
    rm -f "$server_csr"
    openssl req -new \
      -key "$server_key" \
      -out "$server_csr" \
      -subj "/C=US/O=Company Lab/CN=${CN}"
    chmod 644 "$server_csr"

    local extfile="$tmp_dir/server_ext.cnf"
    write_server_extfile "$extfile" "$san_openssl"

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

  # 5) Build certbundle.pem in Qumulo order (leaf -> intermediate -> root) in
  #    tmp/ and publish it only after every self-check passes.
  local staged_bundle="$tmp_dir/certbundle.pem"
  info "Building certbundle.pem (leaf -> intermediate -> root) -> $certbundle"
  rm -f "$staged_bundle"
  cat "$server_crt" "$int_crt" "$ca_crt" > "$staged_bundle"

  # 6) Verification checks
  info "Self-check: chain, extensions, key match and every name in the cert..."
  self_check "$staged_bundle" "$ca_crt" "$int_crt" "$server_crt" "$server_key" "$tmp_dir/check"

  chmod 444 "$staged_bundle"
  rm -f "$certbundle"
  mv "$staged_bundle" "$certbundle"

  info "Showing server certificate subject + SANs..."
  openssl x509 -in "$server_crt" -noout -subject -issuer -dates >&2
  openssl x509 -in "$server_crt" -noout -ext subjectAltName >&2 || true

  print_ready "$ca_crt" "$ca_state" "$int_crt" "$int_state" "$server_crt" "$leaf_state" "$certbundle" "$server_key"
}

main "$@"