#!/usr/bin/env bash
# tests/run_tests.sh
#
# Local checks for CA_Faker.sh, CA_Pusher.sh and CA_Lab.sh.
# Needs only bash and openssl: no containers, no network, no root.
#
# Usage:
#   bash tests/run_tests.sh              # run every test
#   bash tests/run_tests.sh test_a ...   # run only the named tests
#
# Each test_* function runs in its own empty temp directory. A test fails if
# any assert in it fails; the run exits 1 if any test failed.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKER="$REPO/CA_Faker.sh"
PUSHER="$REPO/CA_Pusher.sh"
LAB="$REPO/CA_Lab.sh"

CACHE="$(mktemp -d)"
WORK=""
SERVER_PID=""
SERVER_PORT=""
OUT=""
STDOUT=""
RC=0
T_FAILED=0
T_SKIPPED=0
PASSED=0
SKIPPED=0
FAILED=()

cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  [[ -n "$WORK" ]] && rm -rf "$WORK"
  rm -rf "$CACHE"
}
trap cleanup EXIT

fail() {
  T_FAILED=1
  echo "    not ok: $*"
}

skip() {
  T_SKIPPED=1
  echo "    skipped: $*"
}

# Run a command with stdin from $1; OUT = stdout+stderr, STDOUT = stdout only.
run_in() {
  local input="$1"; shift
  set +e
  STDOUT="$(set +o pipefail; printf '%s' "$input" | "$@" 2>"$WORK/.stderr")"
  RC=$?
  set -e
  OUT="$STDOUT"$'\n'"$(cat "$WORK/.stderr")"
}

run_cmd() { run_in "" "$@"; }

assert_rc() {
  [[ "$RC" -eq "$1" ]] || { fail "expected exit $1, got $RC"; show_out; }
}

assert_contains() {
  [[ "$OUT" == *"$1"* ]] || { fail "output does not contain: $1"; show_out; }
}

assert_not_contains() {
  [[ "$OUT" != *"$1"* ]] || { fail "output unexpectedly contains: $1"; show_out; }
}

assert_eq() {
  [[ "$1" == "$2" ]] || fail "${3:-value}: expected '$2', got '$1'"
}

assert_ne() {
  [[ "$1" != "$2" ]] || fail "${3:-value}: expected something other than '$2'"
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_no_file() {
  [[ ! -e "$1" ]] || fail "file should not exist: $1"
}

show_out() {
  printf '%s\n' "$OUT" | sed -n '1,40p' | sed 's/^/      | /'
}

# Normalised SHA-256 of the first certificate in a PEM file.
fp() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr a-f A-F
}

key_fp() {
  openssl pkey -in "$1" -pubout | openssl dgst -sha256 | awk '{print $NF}'
}

cert_count() {
  grep -c 'BEGIN CERTIFICATE' "$1"
}

leaf_cn() {
  openssl x509 -in "$1" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p'
}

leaf_sans() {
  openssl x509 -in "$1" -noout -ext subjectAltName | sed -n '2p' | sed 's/^ *//'
}

# One CA_Faker out-dir, built once per run and copied into each test that
# needs it (key generation is the slow part).
faker_outdir() {
  if [[ ! -d "$CACHE/base" ]]; then
    (cd "$CACHE" && "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./base >/dev/null 2>&1) \
      || { fail "could not build the CA_Faker fixture"; return 1; }
  fi
  cp -a "$CACHE/base" "$1"
}

# Serve a CA_Faker out-dir's cert on a loopback port (sets SERVER_PORT).
start_tls_server() {
  local od="$1"
  SERVER_PORT=$((20000 + RANDOM % 30000))
  openssl s_server -accept "$SERVER_PORT" -cert "$od/issued/server.crt.pem" \
    -key "$od/private.key.insecure" -cert_chain "$od/ca/intermediate.crt.pem" \
    -quiet </dev/null >/dev/null 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 50); do
    openssl s_client -connect "127.0.0.1:$SERVER_PORT" </dev/null >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "s_server did not start on port $SERVER_PORT"
  return 1
}

stop_tls_server() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

# Run the root script's tls_check locally, trusting only the given CA file.
run_tls_check() {
  local ca="$1" ep="$2"
  sed -n '/^tls_check() {/,/^}/p' "$PUSHER" > tls_check.sh
  mkdir -p empty_ca_dir
  run_cmd env SSL_CERT_FILE="$ca" SSL_CERT_DIR="$PWD/empty_ca_dir" \
    bash -c 'source ./tls_check.sh; tls_check "$1"' _ "$ep"
}

# A throwaway self-signed CA dir laid out like a CA_Faker out-dir.
make_plain_ca() {
  mkdir -p "$1/ca"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1/ca/ca.key.pem" \
    -subj "/CN=Test Root" -days 2 -out "$1/ca/ca.crt.pem" >/dev/null 2>&1
}

test_all_scripts_parse() {
  local f
  for f in "$REPO"/*.sh "$REPO"/tests/*.sh; do
    bash -n "$f" 2>/dev/null || fail "bash -n failed: $f"
  done
}

test_shellcheck_errors_if_installed() {
  if ! command -v shellcheck >/dev/null 2>&1; then
    skip "shellcheck not installed"
    return 0
  fi
  run_cmd shellcheck -S error "$REPO"/*.sh "$REPO"/tests/*.sh
  assert_rc 0
}

test_pusher_root_script_parses() {
  sed -n "/<<'RSCRIPT'/,/^RSCRIPT$/p" "$PUSHER" | sed '1d;$d' > root_script.sh
  [[ -s root_script.sh ]] || fail "root script not found in CA_Pusher.sh"
  bash -n root_script.sh 2>/dev/null || fail "root script does not parse"
}

test_pusher_empty_clients_file_fails() {
  make_plain_ca od
  : > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key
  assert_rc 1
  assert_contains "ERROR: No hosts found in clients.txt"
}

test_pusher_comment_only_clients_file_fails() {
  make_plain_ca od
  printf '# only a comment\n\n   \n' > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key
  assert_rc 1
  assert_contains "ERROR: No hosts found in clients.txt"
}

test_pusher_rejects_unsafe_container_name() {
  make_plain_ca od
  echo "node1.qumulotest.local" > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key --container 'qcore;id'
  assert_rc 1
  assert_contains "ERROR: --container must contain only"
}

# Port 1 on loopback refuses the connection, so the remote step fails;
# the host must be counted as failed, not OK.
test_pusher_unreachable_host_counts_failed() {
  if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    skip "ssh client not installed"
    return 0
  fi
  make_plain_ca od
  echo "127.0.0.1" > clients.txt
  ssh-keygen -q -t ed25519 -N "" -f key >/dev/null
  run_in $'pw\n' "$PUSHER" --clients clients.txt --ca od --ssh-user u \
    --auth key --key key --port 1 --timeout 2
  assert_rc 2
  assert_contains "Fail:  1"
  assert_contains "OK:    0"
  assert_not_contains "[127.0.0.1] done"
}

test_pusher_rejects_bad_trust_name() {
  make_plain_ca od
  echo "node1.qumulotest.local" > clients.txt
  local bad
  for bad in "" ".hidden" "a/b" "lab ca" 'x&y'; do
    run_cmd "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key --trust-name "$bad"
    assert_rc 1
    assert_contains "ERROR: --trust-name must"
  done
}

# Placeholders are replaced with ${var/pattern/value}, which only replaces
# the first match: each must appear exactly once in the root script.
test_pusher_placeholders_appear_once() {
  sed -n "/<<'RSCRIPT'/,/^RSCRIPT$/p" "$PUSHER" > root_script.sh
  local ph n
  for ph in __B64_CERT__ __CONTAINER__ __VERIFY_TLS__ __VERIFY__ __TRUST_NAME__ \
      __HOST__ __MODE__ __ROOTS__; do
    n="$(grep -o "$ph" root_script.sh | wc -l | tr -d ' ')"
    assert_eq "$n" 1 "count of $ph"
  done
}

test_faker_builds_root_intermediate_leaf_chain() {
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_contains "READY."
  assert_file od/private.key.insecure
  assert_file od/certbundle.pem
  assert_file od/ca/ca.crt.pem
  assert_file od/ca/ca.key.pem
  assert_file od/ca/intermediate.crt.pem
  assert_file od/ca/intermediate.key.pem
  assert_file od/issued/server.crt.pem
  assert_file od/csr/server.csr.pem
  assert_eq "$(cert_count od/certbundle.pem)" 3 "certs in bundle"

  local root int leaf
  root="$(openssl x509 -in od/ca/ca.crt.pem -noout -text)"
  int="$(openssl x509 -in od/ca/intermediate.crt.pem -noout -text)"
  leaf="$(openssl x509 -in od/issued/server.crt.pem -noout -text)"
  [[ "$root" == *"Certificate Sign, CRL Sign"* ]] || fail "root keyUsage"
  [[ "$int" == *"CA:TRUE, pathlen:0"* ]] || fail "intermediate pathlen:0"
  [[ "$int" == *"Certificate Sign, CRL Sign"* ]] || fail "intermediate keyUsage"
  [[ "$leaf" == *"X509v3 Subject Key Identifier"* ]] || fail "leaf SKI"
  [[ "$leaf" == *"X509v3 Authority Key Identifier"* ]] || fail "leaf AKI"
  [[ "$(leaf_cn od/ca/ca.crt.pem)" =~ ^Company\ Lab\ Root\ CA\ [0-9]{8}-[0-9]{6}$ ]] || fail "root CN not timestamped"
  [[ "$(leaf_cn od/ca/intermediate.crt.pem)" =~ ^Company\ Lab\ Intermediate\ CA\ [0-9]{8}-[0-9]{6}$ ]] || fail "intermediate CN not timestamped"

  run_cmd openssl verify -x509_strict -purpose sslserver -trusted od/ca/ca.crt.pem \
    -untrusted od/ca/intermediate.crt.pem -verify_hostname stratusdatacore.qumulotest.local \
    od/issued/server.crt.pem
  assert_rc 0
}

# Serial files have explicit names next to their CA (upstream: ca/ca.srl);
# OpenSSL/LibreSSL versions otherwise derive different defaults.
test_faker_serial_files_have_explicit_names() {
  faker_outdir od || return 1
  assert_file od/ca/ca.srl
  assert_file od/ca/intermediate.srl
  assert_no_file od/ca/ca.crt.srl
  assert_no_file od/ca/intermediate.crt.srl
  assert_no_file od/.srl
}

test_faker_rerun_reuses_everything() {
  faker_outdir od || return 1
  local before after
  before="$(fp od/ca/ca.crt.pem) $(fp od/ca/intermediate.crt.pem) $(fp od/issued/server.crt.pem) $(key_fp od/private.key.insecure)"
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  after="$(fp od/ca/ca.crt.pem) $(fp od/ca/intermediate.crt.pem) $(fp od/issued/server.crt.pem) $(key_fp od/private.key.insecure)"
  assert_eq "$after" "$before" "fingerprints after rerun"
  assert_contains "INFO: Reusing existing server certificate (names below are read from it). Your --cn/--san were not applied"
}

test_faker_rerun_with_new_san_keeps_cert_and_says_so() {
  faker_outdir od || return 1
  local before
  before="$(fp od/issued/server.crt.pem)"
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --san "dns:other.qumulotest.local" --out-dir ./od
  assert_rc 0
  assert_eq "$(fp od/issued/server.crt.pem)" "$before" "leaf fingerprint"
  assert_contains "Your --cn/--san were not applied"
  [[ "$(leaf_sans od/issued/server.crt.pem)" != *other* ]] || fail "new SAN was applied without --force-reissue"
}

# A wildcard CN is checked as check.<domain> and is never suggested as a
# qq --host value.
test_faker_issues_wildcard_cn_cert() {
  run_cmd "$FAKER" --cn '*.qumulotest.local' --out-dir ./od
  assert_rc 0
  assert_eq "$(leaf_sans od/issued/server.crt.pem)" 'DNS:*.qumulotest.local' "leaf SANs"
  assert_contains "(use your cluster's name, e.g. <your-cluster>)"
}

test_faker_ready_reports_values_read_from_certs() {
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --san "dns:other.qumulotest.local" --out-dir ./od
  assert_rc 0
  assert_contains "Root CA:          reused"
  assert_contains "Server cert:      reused"
  assert_contains "CN: $(leaf_cn od/ca/ca.crt.pem)"
  assert_contains "SHA-256: $(fp od/ca/ca.crt.pem)"
  [[ "$STDOUT" =~ SHA-1:\ +[0-9A-F]{40} ]] || fail "READY does not print a 40-hex SHA-1"
  assert_contains $'Names covered by the server cert:\n  dns:stratusdatacore.qumulotest.local'
  [[ "$STDOUT" != *other.qumulotest.local* ]] || fail "READY shows the requested SAN, not the cert's"
  assert_contains "WARNING: anyone with ./od can issue certs your machines will trust."
  assert_eq "$(grep -c '^WARNING:' <<< "$STDOUT")" 1 "warnings in READY"
}

test_faker_force_reissue_rebuilds_leaf_side_only() {
  faker_outdir od || return 1
  local ca_before leaf_before key_before
  ca_before="$(fp od/ca/ca.crt.pem) $(fp od/ca/intermediate.crt.pem)"
  leaf_before="$(fp od/issued/server.crt.pem)"
  key_before="$(key_fp od/private.key.insecure)"
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od --force-reissue
  assert_rc 0
  assert_eq "$(fp od/ca/ca.crt.pem) $(fp od/ca/intermediate.crt.pem)" "$ca_before" "CA fingerprints"
  assert_ne "$(fp od/issued/server.crt.pem)" "$leaf_before" "leaf fingerprint"
  assert_ne "$(key_fp od/private.key.insecure)" "$key_before" "server key"
}

test_faker_force_reissue_applies_new_san() {
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local \
    --san "dns:stratusdatacore.qumulotest.local,dns:node1.qumulotest.local,ip:10.1.1.11" \
    --out-dir ./od --force-reissue
  assert_rc 0
  assert_eq "$(leaf_sans od/issued/server.crt.pem)" \
    "DNS:stratusdatacore.qumulotest.local, DNS:node1.qumulotest.local, IP Address:10.1.1.11" "leaf SANs"
}

# Files are 444/400 after a run, so a rerun that rewrites them only works
# because every write removes the old file first.
test_faker_rewrites_readonly_files_as_non_root() {
  if [[ "$EUID" -eq 0 ]]; then
    skip "running as root, file modes are not enforced"
    return 0
  fi
  faker_outdir od || return 1
  rm -f od/ca/intermediate.key.pem
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od --force-reissue
  assert_rc 0
  assert_not_contains "Permission denied"
}

test_faker_deleted_root_rebuilds_everything() {
  faker_outdir od || return 1
  local int_before leaf_before
  int_before="$(fp od/ca/intermediate.crt.pem)"
  leaf_before="$(fp od/issued/server.crt.pem)"
  rm -f od/ca/ca.key.pem od/ca/ca.crt.pem
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_ne "$(fp od/ca/intermediate.crt.pem)" "$int_before" "intermediate fingerprint"
  assert_ne "$(fp od/issued/server.crt.pem)" "$leaf_before" "leaf fingerprint"
}

test_faker_deleted_intermediate_key_rebuilds_intermediate_and_leaf() {
  faker_outdir od || return 1
  local root_before int_before leaf_before key_before
  root_before="$(fp od/ca/ca.crt.pem)"
  int_before="$(fp od/ca/intermediate.crt.pem)"
  leaf_before="$(fp od/issued/server.crt.pem)"
  key_before="$(key_fp od/private.key.insecure)"
  rm -f od/ca/intermediate.key.pem
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_eq "$(fp od/ca/ca.crt.pem)" "$root_before" "root fingerprint"
  assert_ne "$(fp od/ca/intermediate.crt.pem)" "$int_before" "intermediate fingerprint"
  assert_ne "$(fp od/issued/server.crt.pem)" "$leaf_before" "leaf fingerprint"
  assert_eq "$(key_fp od/private.key.insecure)" "$key_before" "server key"
}

test_faker_deleted_server_key_rebuilds_key_csr_and_leaf() {
  faker_outdir od || return 1
  local leaf_before csr_before
  leaf_before="$(fp od/issued/server.crt.pem)"
  csr_before="$(openssl req -in od/csr/server.csr.pem -noout -pubkey | openssl dgst -sha256)"
  rm -f od/private.key.insecure
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_ne "$(fp od/issued/server.crt.pem)" "$leaf_before" "leaf fingerprint"
  assert_ne "$(openssl req -in od/csr/server.csr.pem -noout -pubkey | openssl dgst -sha256)" "$csr_before" "CSR key"
  assert_eq "$(openssl x509 -in od/issued/server.crt.pem -noout -pubkey)" \
    "$(openssl pkey -in od/private.key.insecure -pubout)" "leaf public key vs server key"
}

test_faker_deleted_leaf_with_new_cn_uses_new_cn() {
  faker_outdir od || return 1
  rm -f od/issued/server.crt.pem
  run_cmd "$FAKER" --cn clusterb.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_eq "$(leaf_cn od/issued/server.crt.pem)" "clusterb.qumulotest.local" "leaf CN"
  assert_eq "$(openssl req -in od/csr/server.csr.pem -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')" \
    "clusterb.qumulotest.local" "CSR CN"
}

test_faker_foreign_server_key_fails_and_keeps_bundle() {
  faker_outdir od || return 1
  local bundle_before
  bundle_before="$(openssl dgst -sha256 < od/certbundle.pem)"
  rm -f od/private.key.insecure
  openssl genrsa -out od/private.key.insecure 2048 >/dev/null 2>&1
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 1
  assert_contains "the server key does not match the certificate — delete issued/server.crt.pem and rerun"
  assert_not_contains "READY."
  assert_eq "$(openssl dgst -sha256 < od/certbundle.pem)" "$bundle_before" "certbundle.pem"
}

# A root made by the old script (req -x509 with the system defaults) has no
# keyUsage; the script must refuse it before generating anything.
test_faker_refuses_old_root_without_keyusage() {
  mkdir -p od/ca
  openssl genrsa -out od/ca/ca.key.pem 2048 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key od/ca/ca.key.pem -sha256 -days 30 \
    -out od/ca/ca.crt.pem -subj "/C=US/O=Company Lab/CN=Company Lab Root CA" >/dev/null 2>&1
  if [[ "$(openssl x509 -in od/ca/ca.crt.pem -noout -text)" == *"X509v3 Key Usage"* ]]; then
    skip "this openssl.cnf adds keyUsage to req -x509, so no old-style root can be made here"
    return 0
  fi
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 1
  assert_contains "was made by an older CA_Faker and is missing keyUsage"
  assert_no_file od/ca/intermediate.crt.pem
  assert_no_file od/certbundle.pem
}

mutate_faker() {
  sed "$1" "$FAKER" > ./CA_Faker.sh
  chmod +x ./CA_Faker.sh
  if [[ "$(cat ./CA_Faker.sh)" == "$(cat "$FAKER")" ]]; then
    fail "mutation did not change the script: $1"
    return 1
  fi
}

test_faker_self_check_catches_root_without_keyusage() {
  mutate_faker '/^write_ca_extfile() {/,/^}/{/^keyUsage/d;}' || return 1
  run_cmd ./CA_Faker.sh --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 1
  assert_contains "Self-check failed: root CA has no keyUsage with Certificate Sign"
  assert_no_file od/certbundle.pem
}

# A bundle with an extra cert must fail the count check, not be published.
test_faker_self_check_catches_wrong_bundle_count() {
  mutate_faker '/^  cat "\$server_crt"/s/ > "\$staged_bundle"/ "$int_crt" > "$staged_bundle"/' || return 1
  run_cmd ./CA_Faker.sh --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 1
  assert_contains "Self-check failed: certbundle.pem holds 4 certificates, expected 3 (leaf, intermediate, root)"
  assert_no_file od/certbundle.pem
}

# OpenSSL 3.x adds an AKI by itself unless told "none"; 1.1.1 rejects "none"
# and adds nothing when the line is absent.
test_faker_self_check_catches_leaf_without_aki() {
  if [[ "$(openssl version)" == "OpenSSL 1."* ]]; then
    mutate_faker '/^write_server_extfile() {/,/^}/{/^authorityKeyIdentifier/d;}' || return 1
  else
    mutate_faker '/^write_server_extfile() {/,/^}/{s/^authorityKeyIdentifier = keyid:always$/authorityKeyIdentifier = none/;}' || return 1
  fi
  run_cmd ./CA_Faker.sh --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 1
  assert_contains "Self-check failed: server cert has no Authority Key Identifier"
  assert_no_file od/certbundle.pem
}

check_names() {
  run_cmd "$FAKER" --check-names "$@"
}

test_names_accepts_good_names_and_prints_final_san_list() {
  check_names --cn qumulo
  assert_rc 0
  assert_eq "$STDOUT" "dns:qumulo" "--cn qumulo"

  check_names --cn stratusdatacore.qumulotest.local
  assert_rc 0
  assert_eq "$STDOUT" $'dns:stratusdatacore.qumulotest.local\ndns:stratusdatacore' "default SAN adds short name"

  check_names --cn 10.1.1.10
  assert_rc 0
  assert_eq "$STDOUT" "ip:10.1.1.10" "IPv4 CN"

  check_names --cn 2001:db8::10
  assert_rc 0
  assert_eq "$STDOUT" "ip:2001:db8::10" "IPv6 CN"

  check_names --cn '*.qumulotest.local'
  assert_rc 0
  assert_eq "$STDOUT" 'dns:*.qumulotest.local' "wildcard CN"

  check_names --cn 10.lab.test
  assert_rc 0
  assert_eq "$STDOUT" "dns:10.lab.test" "numeric short name dropped"
  assert_contains "INFO: Not adding short name 10 — browsers would treat it as an IP address."

  check_names --cn node1.lab.test --san ip:10.0.0.1
  assert_rc 0
  assert_eq "$STDOUT" $'dns:node1.lab.test\nip:10.0.0.1' "CN prepended"
  assert_contains "INFO: Added dns:node1.lab.test to the SAN list — browsers ignore the CN and only check SANs."

  check_names --cn node1.lab.test --san DNS:Node1.Lab.Test
  assert_rc 0
  assert_eq "$STDOUT" "dns:Node1.Lab.Test" "CN match is case-insensitive"

  check_names --cn my_host.lab.test
  assert_rc 0

  check_names --cn x.lab.test --san "ip:::1,ip:::ffff:10.0.0.1,dns:x.lab.test"
  assert_rc 0
  assert_eq "$STDOUT" $'ip:::1\nip:::ffff:10.0.0.1\ndns:x.lab.test' "IPv6 forms"

  check_names --cn "$(printf 'a%.0s' $(seq 60)).lab"
  assert_rc 0
}

test_names_rejects_bad_names_before_writing_anything() {
  local -a bad=(
    "--cn x.lab.test --san ip:999.1.1.1"
    "--cn x.lab.test --san ip:010.0.0.1"
    "--cn x.lab.test --san dns:10.0.0.1"
    "--cn x.lab.test --san dns:1.2.3"
    "--cn x.lab.test --san dns:foo*.lab.test"
    "--cn x.lab.test --san dns:*.test"
    "--cn x.lab.test --san dns:a.*.test"
    "--cn 010.0.0.1"
    "--cn host:443"
    "--cn x.lab.test --san dns:lab.test."
    "--cn x.lab.test --san dns:a..test"
    "--cn x.lab.test --san dns:-x.lab.test"
    "--cn x.lab.test --san dns:"
    "--cn x.lab.test --san ip:1:2"
    "--cn cafe:443"
    "--cn x.lab.test --san ip:[::1]"
    "--cn x.lab.test --san dns:foo.0x1f"
    "--cn [::1]"
  )
  local args
  for args in "${bad[@]}"; do
    rm -rf od
    mkdir od
    # shellcheck disable=SC2086
    run_cmd "$FAKER" $args --out-dir ./od
    [[ "$RC" -eq 1 ]] || fail "expected exit 1 for: $args (got $RC)"
    [[ "$OUT" == *"ERROR:"* ]] || fail "expected ERROR for: $args"
    [[ -z "$(ls -A od)" ]] || fail "files were written for: $args"
  done
}

test_names_trims_spaces_around_san_entries() {
  check_names --cn x.lab.test --san "dns:x.lab.test, ip:10.0.0.1 , dns:y.lab.test"
  assert_rc 0
  assert_eq "$STDOUT" $'dns:x.lab.test\nip:10.0.0.1\ndns:y.lab.test' "SAN list with spaces"
}

test_names_rejects_cn_longer_than_64() {
  check_names --cn "$(printf 'a%.0s' $(seq 62)).lab"
  assert_rc 1
  assert_contains "ERROR: --cn must be 64 characters or fewer (put long names in --san)"
}

test_names_specific_messages() {
  check_names --cn x.lab.test --san dns:10.0.0.1
  assert_contains "ERROR: dns:10.0.0.1 is an IP address; use ip:10.0.0.1"
  check_names --cn x.lab.test --san dns:1.2.3
  assert_contains "ERROR: 1.2.3 is not a valid DNS name (letters, digits, '-' and '_' only, dot-separated; use xn-- punycode for international names; all-number names are read as IP addresses by browsers)"
}

test_faker_server_days_over_825_warns() {
  check_names --cn x.lab.test --server-days 900
  assert_rc 0
  assert_contains "WARNING: Apple devices reject TLS certs valid for more than 825 days"
}

test_faker_issues_and_self_checks_ip_wildcard_and_ipv6_names() {
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local \
    --san "dns:*.qumulotest.local,ip:10.1.1.10,ip:2001:db8::10" --out-dir ./od
  assert_rc 0
  assert_contains "INFO: Added dns:stratusdatacore.qumulotest.local to the SAN list"
  local sans
  sans="$(leaf_sans od/issued/server.crt.pem)"
  assert_eq "$sans" "DNS:stratusdatacore.qumulotest.local, DNS:*.qumulotest.local, IP Address:10.1.1.10, IP Address:2001:DB8:0:0:0:0:0:10" "leaf SANs"
}

# Everything CA_Pusher runs inside a container must work under plain sh: the
# container may be a different distro and may not have bash.
container_fns() {
  bash -c 'eval "$(sed -n "/^fp_of() {/,/^}/p;/^trust_family() {/,/^}/p;/^trust_install() {/,/^}/p;/^list_files() {/,/^}/p;/^trust_remove() {/,/^}/p;/^tls_check() {/,/^}/p" "$1")"; declare -f fp_of trust_family trust_install list_files trust_remove tls_check' _ "$PUSHER" > fns.sh
}

test_container_functions_parse_under_posix_sh() {
  command -v dash >/dev/null 2>&1 || { skip "dash not installed"; return 0; }
  container_fns
  grep -q '^list_files ()' fns.sh || fail "list_files not found in CA_Pusher.sh"
  run_cmd dash -n fns.sh
  assert_rc 0
  grep -n -- '-- bash -c' "$PUSHER" && fail "a container step still runs bash"
  return 0
}

test_container_list_files_walks_nested_and_hidden_under_sh() {
  command -v dash >/dev/null 2>&1 || { skip "dash not installed"; return 0; }
  container_fns
  mkdir -p anchors/sub/deeper
  : > anchors/a.crt; : > anchors/.hidden.crt; : > anchors/sub/b.crt; : > anchors/sub/deeper/..odd.crt
  run_cmd dash -c '. ./fns.sh; list_files "$1"' _ "$PWD/anchors"
  assert_rc 0
  assert_eq "$(sort <<< "$STDOUT" | sed "s#$PWD/anchors/##")" $'.hidden.crt\na.crt\nsub/b.crt\nsub/deeper/..odd.crt' "files found"
}

test_container_tls_check_works_under_sh() {
  command -v dash >/dev/null 2>&1 || { skip "dash not installed"; return 0; }
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn other.lab.test --san "dns:other.lab.test,ip:127.0.0.1" --out-dir ./od --force-reissue
  assert_rc 0
  container_fns
  mkdir -p empty_ca_dir
  start_tls_server od || return 1
  run_cmd env SSL_CERT_FILE=od/ca/ca.crt.pem SSL_CERT_DIR="$PWD/empty_ca_dir" dash -c '. ./fns.sh; tls_check "$1"' _ "127.0.0.1:$SERVER_PORT"
  assert_rc 0
  run_cmd env SSL_CERT_FILE=od/ca/ca.crt.pem SSL_CERT_DIR="$PWD/empty_ca_dir" dash -c '. ./fns.sh; tls_check "$1"' _ "localhost:$SERVER_PORT"
  assert_rc 1
  [[ "${OUT,,}" == *"hostname mismatch"* ]] || { fail "expected a hostname mismatch"; show_out; }
  stop_tls_server
}

test_versions_report_2_0_0() {
  run_cmd "$FAKER" --version
  assert_rc 0
  assert_eq "$STDOUT" "CA_Faker.sh 2.0.0" "CA_Faker --version"
  run_cmd "$PUSHER" --version
  assert_rc 0
  assert_eq "$STDOUT" "CA_Pusher.sh 2.0.0" "CA_Pusher --version"
  run_cmd "$LAB" --version
  assert_rc 0
  assert_eq "$STDOUT" "CA_Lab.sh 2.0.0" "CA_Lab --version"
}

# CA_Pusher carries its own copy of the name rules; they must not drift.
test_name_rule_copies_are_identical() {
  local f
  for f in is_ipv4 ipv6_groups is_ipv6 is_ip_literal is_dns_name; do
    assert_eq "$(sed -n "/^$f() {/,/^}/p" "$PUSHER")" "$(sed -n "/^$f() {/,/^}/p" "$FAKER")" "$f in CA_Pusher.sh vs CA_Faker.sh"
    [[ -n "$(sed -n "/^$f() {/,/^}/p" "$FAKER")" ]] || fail "$f not found in CA_Faker.sh"
  done
}

test_pusher_rejects_bad_verify_tls() {
  make_plain_ca od
  : > clients.txt
  local ep
  for ep in ":443" "::1:443" "host" "host:0" "host:65536" "host:08" "a'b:443" 'x&y:443' \
      '*.lab.test:443' '[::1]' '[zz::1]:443' '10.1:443' 'node1.lab.test.:443'; do
    run_cmd "$PUSHER" --clients clients.txt --ca od --verify-tls "$ep"
    [[ "$RC" -eq 1 ]] || fail "expected exit 1 for --verify-tls '$ep'"
    [[ "$OUT" == *"ERROR: --verify-tls must be host:port"* ]] || fail "expected --verify-tls error for '$ep'"
  done
}

# Accepted values get past argument checks to the (empty) clients file.
test_pusher_accepts_good_verify_tls() {
  make_plain_ca od
  : > clients.txt
  local ep
  for ep in "stratusdatacore.qumulotest.local:443" "[::1]:443" "[2001:db8::10]:8000" "10.1.1.10:443" "qumulo:443"; do
    run_cmd "$PUSHER" --clients clients.txt --ca od --verify-tls "$ep"
    [[ "$OUT" == *"ERROR: No hosts found"* ]] || fail "--verify-tls '$ep' was not accepted"
  done
}

# The root script's TLS check must fail on an untrusted chain and on a name
# or IP the cert does not list (it used to check neither reliably).
test_pusher_tls_check_validates_chain_and_name() {
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn localhost --san "dns:localhost,ip:127.0.0.1" --out-dir ./od --force-reissue
  assert_rc 0
  cp -a od od_dns_only
  run_cmd "$FAKER" --cn localhost --san "dns:localhost" --out-dir ./od_dns_only --force-reissue
  assert_rc 0
  make_plain_ca other

  start_tls_server od || return 1
  run_tls_check od/ca/ca.crt.pem "127.0.0.1:$SERVER_PORT"
  assert_rc 0
  run_tls_check other/ca/ca.crt.pem "127.0.0.1:$SERVER_PORT"
  assert_rc 1
  assert_contains "unable to get local issuer certificate"
  stop_tls_server

  start_tls_server od_dns_only || return 1
  run_tls_check od_dns_only/ca/ca.crt.pem "127.0.0.1:$SERVER_PORT"
  assert_rc 1
  assert_contains "IP address mismatch"
  stop_tls_server

  # The name check: a cert that does not list "localhost" must be rejected
  # when connecting by that name, even though the chain is trusted.
  cp -a od od_other_name
  run_cmd "$FAKER" --cn other.lab.test --san "dns:other.lab.test,ip:127.0.0.1" --out-dir ./od_other_name --force-reissue
  assert_rc 0
  start_tls_server od_other_name || return 1
  run_tls_check od_other_name/ca/ca.crt.pem "localhost:$SERVER_PORT"
  assert_rc 1
  # OpenSSL 1.1.1 prints "Hostname mismatch", 3.x "hostname mismatch".
  [[ "${OUT,,}" == *"hostname mismatch"* ]] || { fail "output does not contain: hostname mismatch"; show_out; }
  stop_tls_server
}

# One lab CA dir shared by two servers (built once per run).
shared_lab() {
  if [[ ! -d "$CACHE/shared" ]]; then
    mkdir -p "$CACHE/shared"
    (cd "$CACHE/shared" \
      && "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab >/dev/null 2>&1 \
      && "$FAKER" --cn b.qumulotest.local --out-dir ./b --ca-dir ./lab >/dev/null 2>&1) \
      || { fail "could not build the shared lab fixture"; return 1; }
  fi
  cp -a "$CACHE/shared/." .
}

test_faker_readme_quick_start_keeps_todays_file_layout() {
  run_cmd "$FAKER" --cn myserver.lab.example.com --out-dir ./qumulo-tls
  assert_rc 0
  local f
  for f in private.key.insecure certbundle.pem ca/ca.crt.pem ca/ca.key.pem \
      issued/server.crt.pem csr/server.csr.pem; do
    assert_file "qumulo-tls/$f"
  done
}

test_faker_paths_with_spaces_work() {
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir "./my lab/a" --ca-dir "./my lab/lab ca"
  assert_rc 0
  assert_file "my lab/a/certbundle.pem"
  assert_eq "$(fp "my lab/a/ca/ca.crt.pem")" "$(fp "my lab/lab ca/ca.crt.pem")" "shipped root"
  [[ ! -d "my lab/lab ca/.lock" ]] || fail "lock left behind"
}

test_faker_writes_der_copy_of_root() {
  faker_outdir od || return 1
  assert_eq "$(openssl x509 -inform DER -in od/ca/ca.cer -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr a-f A-F)" \
    "$(fp od/ca/ca.crt.pem)" "ca.cer fingerprint"
}

test_faker_shared_ca_dir_serves_two_servers_with_one_root() {
  shared_lab || return 1
  local root_before
  root_before="$(fp lab/ca.crt.pem) $(fp lab/intermediate.crt.pem)"
  run_cmd "$FAKER" --cn b.qumulotest.local --out-dir ./b --ca-dir ./lab
  assert_rc 0
  assert_eq "$(fp lab/ca.crt.pem) $(fp lab/intermediate.crt.pem)" "$root_before" "lab CA after rerun"
  assert_eq "$(fp a/ca/ca.crt.pem)" "$(fp lab/ca.crt.pem)" "a/ca/ca.crt.pem"
  assert_eq "$(fp b/ca/ca.crt.pem)" "$(fp lab/ca.crt.pem)" "b/ca/ca.crt.pem"
  assert_eq "$(fp a/ca/intermediate.crt.pem)" "$(fp lab/intermediate.crt.pem)" "a/ca/intermediate.crt.pem"
  assert_no_file a/ca/ca.key.pem
  assert_no_file a/ca/intermediate.key.pem
  assert_no_file b/ca/ca.key.pem
  local h
  for h in a b; do
    run_cmd openssl verify -x509_strict -purpose sslserver -trusted lab/ca.crt.pem \
      -untrusted lab/intermediate.crt.pem -verify_hostname "$h.qumulotest.local" "$h/issued/server.crt.pem"
    assert_rc 0
  done
  printf '# none\n' > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca ./a
  assert_contains "ERROR: No hosts found"
}

test_faker_ca_dir_spelled_differently_is_still_own_ca() {
  faker_outdir od || return 1
  local root_before
  root_before="$(fp od/ca/ca.crt.pem)"
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od --ca-dir ./od/ca/
  assert_rc 0
  assert_eq "$(fp od/ca/ca.crt.pem)" "$root_before" "root fingerprint"
  assert_file od/ca/ca.key.pem
}

test_faker_shared_out_dir_rerun_without_ca_dir_fails() {
  shared_lab || return 1
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a
  assert_rc 1
  assert_contains "ERROR: ./a uses a shared lab CA; pass the same --ca-dir as before"
  assert_no_file a/ca/ca.key.pem
}

test_faker_own_ca_out_dir_given_ca_dir_fails() {
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od --ca-dir ./lab
  assert_rc 1
  assert_contains "ERROR: ./od has its own CA; use a new --out-dir for a server in a shared lab CA"
  assert_no_file lab/ca.crt.pem
}

test_faker_held_ca_lock_fails_with_rmdir_hint() {
  mkdir -p lab/.lock
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab
  assert_rc 1
  assert_contains "ERROR: another CA_Faker run is using ./lab; try again (if no run is active: rmdir $PWD/lab/.lock)"
  assert_no_file lab/ca.crt.pem
  [[ -d lab/.lock ]] || fail "the other run's lock was removed"
}

# Whichever run loses the race must fail on the lock; either way the lab
# ends up with exactly one root.
test_faker_concurrent_runs_on_one_ca_dir_build_one_root() {
  "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab >a.log 2>&1 &
  local pa=$!
  "$FAKER" --cn b.qumulotest.local --out-dir ./b --ca-dir ./lab >b.log 2>&1 &
  local pb=$! ra=0 rb=0
  wait "$pa" || ra=$?
  wait "$pb" || rb=$?
  local h rc
  for h in a b; do
    [[ "$h" == a ]] && rc=$ra || rc=$rb
    if [[ "$rc" -eq 0 ]]; then
      assert_eq "$(fp "$h/ca/ca.crt.pem")" "$(fp lab/ca.crt.pem)" "$h root"
    else
      grep -q "another CA_Faker run is using ./lab" "$h.log" || fail "$h failed for another reason: $(tail -1 "$h.log")"
    fi
  done
  [[ "$ra" -eq 0 || "$rb" -eq 0 ]] || fail "both runs failed"
  [[ ! -d lab/.lock ]] || fail "lock left behind"
}

test_faker_rebuilt_ca_dir_fails_with_hint_and_keeps_bundle() {
  shared_lab || return 1
  local bundle_before
  bundle_before="$(openssl dgst -sha256 < a/certbundle.pem)"
  rm -rf lab
  run_cmd "$FAKER" --cn b.qumulotest.local --out-dir ./b2 --ca-dir ./lab
  assert_rc 0
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab
  assert_rc 1
  assert_contains "this server's cert was issued by a different lab CA (was --ca-dir rebuilt?) — rerun with --force-reissue, then re-apply with qq and re-push"
  assert_eq "$(openssl dgst -sha256 < a/certbundle.pem)" "$bundle_before" "a/certbundle.pem"
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab --force-reissue
  assert_rc 0
  assert_eq "$(fp a/ca/ca.crt.pem)" "$(fp lab/ca.crt.pem)" "a root after reissue"
}

# With a shared lab CA two folders hold secrets; the warning names both.
test_ready_warning_names_both_secret_folders() {
  shared_lab || return 1
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab
  assert_rc 0
  assert_contains "WARNING: anyone with ./a and ./lab can issue certs your machines will trust. Keep them"
}

test_faker_old_root_in_ca_dir_is_refused_unless_key_missing() {
  mkdir -p lab
  openssl genrsa -out lab/ca.key.pem 2048 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key lab/ca.key.pem -sha256 -days 30 \
    -out lab/ca.crt.pem -subj "/C=US/O=Company Lab/CN=Company Lab Root CA" >/dev/null 2>&1
  if [[ "$(openssl x509 -in lab/ca.crt.pem -noout -text)" == *"X509v3 Key Usage"* ]]; then
    skip "this openssl.cnf adds keyUsage to req -x509, so no old-style root can be made here"
    return 0
  fi
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab
  assert_rc 1
  assert_contains "Use a new --out-dir (or new --ca-dir) to build a fresh CA."
  rm -f lab/ca.key.pem
  run_cmd "$FAKER" --cn a.qumulotest.local --out-dir ./a --ca-dir ./lab
  assert_rc 0
  [[ "$(openssl x509 -in lab/ca.crt.pem -noout -text)" == *"X509v3 Key Usage"* ]] || fail "root was not rebuilt"
}

# Option descriptions in each script's --help start in one column.
test_help_options_line_up() {
  local script cols
  for script in CA_Faker.sh CA_Pusher.sh CA_Lab.sh; do
    # Width of "  --flag [arg]" plus its padding = the description column.
    cols="$("$REPO/$script" --help 2>&1 | awk 'match($0, /^  --[^ ]+( [^ ]+)?  +/) { print RLENGTH }' | sort -u)"
    [[ "$(wc -l <<< "$cols")" -eq 1 ]] || fail "$script --help options start in columns: $(echo $cols)"
  done
}

# Every flag in a script's --help must be documented in its README table.
test_readme_documents_every_flag() {
  local script flag help n
  for script in CA_Faker.sh CA_Pusher.sh CA_Lab.sh; do
    if ! help="$("$REPO/$script" --help 2>&1)"; then
      fail "$script --help failed"
      continue
    fi
    n=0
    for flag in $(grep -oE '^ +--[a-z0-9-]+' <<< "$help" | tr -d ' ' | sort -u); do
      n=$((n+1))
      [[ "$flag" == "--help" ]] && continue
      grep -qF -- "\`$flag" "$REPO/README.md" || fail "$script $flag is not in README.md"
    done
    [[ "$n" -ge 2 ]] || fail "no flags found in $script --help"
  done
}

# CA_Pusher's "cert not applied yet" hint must name the README step that
# applies TLS to Qumulo, whatever its number.
test_pusher_hint_names_readme_apply_step() {
  local n
  n="$(sed -n 's/^### \([0-9]\)\. Apply TLS to Qumulo$/\1/p' "$REPO/README.md")"
  [[ -n "$n" ]] || { fail "README has no 'Apply TLS to Qumulo' step"; return 0; }
  local hits
  hits="$(grep -o 'README step [0-9]' "$PUSHER" | sort -u)"
  assert_eq "$hits" "README step $n" "README step named by CA_Pusher hints"
}

test_ready_points_desktops_to_readme_step_5() {
  faker_outdir od || return 1
  run_cmd "$FAKER" --cn stratusdatacore.qumulotest.local --out-dir ./od
  assert_rc 0
  assert_contains "Desktops/browsers: see README step 5"
  grep -q '^### 5. Trust the CA on admin desktops (browsers)' "$REPO/README.md" || fail "README has no step 5"
  [[ "$STDOUT" =~ SHA-1:\ +[0-9A-F]{40} ]] || fail "READY does not print a 40-hex SHA-1"
}

# The repo must not name the internal tools used to verify it. In a git
# checkout only the repo's own files count (git-ignored local files are not
# repo content).
test_repo_mentions_no_internal_tools() {
  local pattern="q""sim|sim""node|scratch""pad|cla""ude"
  if git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    run_cmd git -C "$REPO" grep --untracked -niE "$pattern"
  else
    run_cmd grep -rniE "$pattern" "$REPO" --exclude-dir=.git
  fi
  assert_rc 1
}

# Clients files edited on Windows end lines with CR; the host is still valid.
test_pusher_accepts_crlf_clients_file() {
  if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    skip "ssh client not installed"
    return 0
  fi
  make_plain_ca od
  printf '127.0.0.1\r\n' > clients.txt
  ssh-keygen -q -t ed25519 -N "" -f key >/dev/null
  run_in $'\n' "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key --key key \
    --port 1 --timeout 2 --sudo-password-stdin
  assert_rc 2
  assert_not_contains "is not a valid host"
  assert_contains $'Target: 127.0.0.1\n'
}

test_pusher_rejects_unsafe_host_lines() {
  make_plain_ca od
  printf 'good.qumulotest.local\nadmin@node1\nnode;id\n' > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key
  assert_rc 1
  assert_contains "ERROR: clients.txt line 2: 'admin@node1' is not a valid host"
  assert_contains "ERROR: clients.txt line 3: 'node;id' is not a valid host"
}

test_pusher_checks_every_verify_tls_value() {
  make_plain_ca od
  : > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od \
    --verify-tls b.qumulotest.local --verify-tls a.qumulotest.local:443
  assert_rc 1
  assert_contains "got 'b.qumulotest.local'"
  run_cmd "$PUSHER" --clients clients.txt --ca od \
    --verify-tls a.qumulotest.local:443 --verify-tls '[2001:db8::10]:443'
  assert_contains "ERROR: No hosts found"
}

test_pusher_ca_accepts_dir_holding_ca_crt() {
  make_plain_ca od
  : > clients.txt
  run_cmd "$PUSHER" --clients clients.txt --ca od/ca
  assert_contains "ERROR: No hosts found"
  mkdir empty
  run_cmd "$PUSHER" --clients clients.txt --ca empty
  assert_rc 1
  assert_contains "CA cert not found at expected path: empty/ca/ca.crt.pem (or empty/ca.crt.pem)"
}

test_pusher_remove_argument_rules() {
  : > clients.txt
  local good="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
  run_cmd "$PUSHER" --clients clients.txt --remove
  assert_rc 1
  assert_contains "ERROR: --remove needs at least one --remove-sha256"
  local bad
  for bad in "${good,,}" "${good:0:63}" "01:23" ""; do
    run_cmd "$PUSHER" --clients clients.txt --remove --remove-sha256 "$bad"
    assert_rc 1
    assert_contains "ERROR: --remove-sha256 must be 64 uppercase hex"
  done
  run_cmd "$PUSHER" --clients clients.txt --remove-sha256 "$good"
  assert_rc 1
  assert_contains "ERROR: --remove-sha256 needs --remove"
  run_cmd "$PUSHER" --clients clients.txt --remove --remove-sha256 "$good" --verify-tls a.qumulotest.local:443
  assert_rc 1
  assert_contains "ERROR: --verify-tls cannot be used with --remove"
  run_cmd "$PUSHER" --clients clients.txt --remove --remove-sha256 "$good"
  assert_contains "ERROR: No hosts found"
}

# With --sudo-password-stdin nothing prompts; an empty password means
# passwordless sudo, which is probed per host (and fails here: no sshd).
test_pusher_sudo_password_stdin_reads_without_prompt() {
  if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    skip "ssh client not installed"
    return 0
  fi
  make_plain_ca od
  echo "127.0.0.1" > clients.txt
  ssh-keygen -q -t ed25519 -N "" -f key >/dev/null
  run_in $'\n' "$PUSHER" --clients clients.txt --ca od --ssh-user u --auth key --key key \
    --port 1 --timeout 2 --sudo-password-stdin
  assert_rc 2
  assert_not_contains "Remote sudo password"
  assert_contains "[127.0.0.1] no sudo password was given and u cannot sudo without one"
}

write_lab_inputs() {
  cat > clusters.txt <<'EOF'
# <cluster FQDN>  [dns:/ip: names for the cert]  [ssh:<node> ...]
stratusdatacore.qumulotest.local  ip:10.1.1.10 dns:node1.qumulotest.local ssh:10.1.1.11
clusterb.qumulotest.local         ip:10.1.2.10 ssh:10.1.2.11
EOF
  printf 'client1.qumulotest.local\n10.1.1.11\n' > clients.txt
}

# A lab as CA_Lab leaves it after issuing stratusdatacore (no SSH key yet,
# so a dry run never contacts anything).
make_lab() {
  "$FAKER" --cn stratusdatacore.qumulotest.local --san "dns:node1.qumulotest.local,ip:10.1.1.10" \
    --out-dir lab/stratusdatacore.qumulotest.local --ca-dir lab/ca >/dev/null 2>&1 \
    || { fail "could not build the lab fixture"; return 1; }
  printf '%s\n%s\n' "stratusdatacore.qumulotest.local dns:node1.qumulotest.local ip:10.1.1.10" \
    "$(fp lab/ca/ca.crt.pem)" > lab/stratusdatacore.qumulotest.local/clusters-line.txt
}

# Listing with full timestamps; the parent entry ("..") is left out because
# the test itself writes next to the folder.
tree_state() {
  { ls -laR --time-style=full-iso "$1" 2>/dev/null || ls -laRT "$1"; } | sed '/ \.\.$/d'
}

test_lab_refuses_tracing() {
  run_cmd bash -x "$LAB" --version
  assert_rc 1
  assert_contains "ERROR: do not trace CA_Lab — it handles passwords"
}

test_lab_needs_an_input_file() {
  run_cmd "$LAB" --ssh-user admin
  assert_rc 1
  assert_contains "ERROR: give --clusters and/or --clients"
  run_cmd "$LAB" --clusters nope.txt --ssh-user admin
  assert_rc 1
  assert_contains "ERROR: file not found: nope.txt"
}

test_lab_rejects_bad_cluster_lines_before_creating_anything() {
  local -a bad=(
    "stratusdatacore ssh:10.1.1.11"
    "*.qumulotest.local ssh:10.1.1.11"
    "a.qumulotest.local foo:bar"
    "a.qumulotest.local ssh:root@10.1.1.11"
    "a.qumulotest.local dns:10.0.0.1"
    "a.qumulotest.local ip:10.0.0.999"
    "a.qumulotest.local ssh:"
  )
  local line
  for line in "${bad[@]}"; do
    printf '%s\n' "$line" > clusters.txt
    run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --new-lab
    [[ "$RC" -eq 1 ]] || fail "expected exit 1 for: $line (got $RC)"
    [[ "$OUT" == *"ERROR: clusters.txt line 1:"* ]] || fail "expected a line error for: $line"
    [[ ! -e lab-tls ]] || fail "lab-tls was created for: $line"
  done
  printf 'a.qumulotest.local\nA.qumulotest.local\n' > clusters.txt
  run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --new-lab
  assert_rc 1
  assert_contains "ERROR: clusters.txt line 2: a.qumulotest.local is listed twice"
}

# Files edited on Windows end lines with CR.
test_lab_accepts_crlf_input_files() {
  printf 'stratusdatacore.qumulotest.local ip:10.1.1.10 ssh:10.1.1.11\r\n' > clusters.txt
  printf 'client1.qumulotest.local\r\n' > clients.txt
  run_cmd "$LAB" --clusters clusters.txt --clients clients.txt --ssh-user admin --dry-run
  assert_rc 0
  assert_not_contains "ERROR:"
  assert_contains "Target 10.1.1.11: node, user admin, container qcore"
  assert_contains "Target client1.qumulotest.local: client"
}

# A machine in both files (any case) is one target, treated as a node.
test_lab_dedups_targets_case_insensitively_node_wins() {
  printf 'stratusdatacore.qumulotest.local ssh:Node1.qumulotest.local\n' > clusters.txt
  printf 'node1.qumulotest.local\nNODE1.qumulotest.local\n' > clients.txt
  run_cmd "$LAB" --clusters clusters.txt --clients clients.txt --ssh-user admin --dry-run
  assert_rc 0
  assert_eq "$(grep -c '^INFO: Target ' <<< "$OUT")" 1 "number of targets"
  assert_contains "Target node1.qumulotest.local: node, user admin, container qcore"
}

test_lab_rejects_bad_client_lines() {
  printf 'ok.qumulotest.local\nadmin@node1\n' > clients.txt
  make_lab || return 1
  run_cmd "$LAB" --clients clients.txt --ssh-user admin --lab-dir ./lab
  assert_rc 1
  assert_contains "ERROR: clients.txt line 2: 'admin@node1' is not a valid host"
}

test_lab_clients_only_needs_an_existing_lab_ca() {
  write_lab_inputs
  run_cmd "$LAB" --clients clients.txt --ssh-user admin
  assert_rc 1
  assert_contains "ERROR: no lab CA yet — run with --clusters first"
  assert_no_file lab-tls
}

test_lab_new_lab_needs_tty_or_new_lab() {
  write_lab_inputs
  run_cmd "$LAB" --clusters clusters.txt --clients clients.txt --ssh-user admin
  assert_rc 1
  assert_contains "Creating a NEW lab CA in $PWD/lab-tls"
  assert_contains "ERROR: no TTY to confirm a new lab CA; rerun with --new-lab"
  assert_no_file lab-tls
}

test_lab_dry_run_on_new_lab_writes_nothing() {
  write_lab_inputs
  run_cmd "$LAB" --clusters clusters.txt --clients clients.txt --ssh-user admin --dry-run
  assert_rc 0
  assert_contains "Would create a NEW lab CA in $PWD/lab-tls"
  assert_contains "Target 10.1.1.11: node, user admin, container qcore"
  assert_contains "Target client1.qumulotest.local: client, user admin, container (none)"
  assert_contains "client1.qumulotest.local: key push needed (untested)"
  assert_contains "stratusdatacore.qumulotest.local: would issue a cert (new cluster) and apply it"
  assert_contains "Dry run: nothing was changed"
  assert_no_file lab-tls
}

# Dry run with the given clusters.txt line; the lab folder must not change.
lab_dry_run_with_line() {
  local before
  printf '%s\n' "$1" > clusters.txt
  before="$(tree_state lab)"
  run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --lab-dir ./lab --dry-run
  assert_rc 0
  [[ "$(tree_state lab)" == "$before" ]] || fail "dry run changed the lab folder"
}

# The reissue decision is a plain text compare of the normalised line and
# the lab root: the same line (any order, case of type/FQDN, spacing) does
# not reissue.
test_lab_reissues_only_when_line_or_lab_ca_changes() {
  make_lab || return 1
  local line_file=lab/stratusdatacore.qumulotest.local/clusters-line.txt

  lab_dry_run_with_line "STRATUSDATACORE.qumulotest.local   IP:10.1.1.10   ssh:10.1.1.11 dns:node1.qumulotest.local"
  assert_contains "stratusdatacore.qumulotest.local: cert unchanged"

  lab_dry_run_with_line "stratusdatacore.qumulotest.local ip:10.1.1.10 ip:10.1.1.20 dns:node1.qumulotest.local ssh:10.1.1.11"
  assert_contains "stratusdatacore.qumulotest.local: would issue a cert (its clusters.txt line changed)"

  printf '%s\n%s\n' "stratusdatacore.qumulotest.local dns:node1.qumulotest.local ip:10.1.1.10" \
    "0000" > "$line_file"
  lab_dry_run_with_line "stratusdatacore.qumulotest.local ip:10.1.1.10 dns:node1.qumulotest.local ssh:10.1.1.11"
  assert_contains "stratusdatacore.qumulotest.local: would issue a cert (the lab CA changed)"

  rm -f "$line_file"
  lab_dry_run_with_line "stratusdatacore.qumulotest.local ip:10.1.1.10 dns:node1.qumulotest.local ssh:10.1.1.11"
  assert_contains "stratusdatacore.qumulotest.local: would issue a cert (new cluster)"
}

test_lab_lines_without_names_or_with_ipv6_do_not_reissue() {
  make_lab || return 1
  local root
  root="$(fp lab/ca/ca.crt.pem)"
  mkdir -p lab/clusterb.qumulotest.local lab/clusterc.qumulotest.local
  printf '%s\n%s\n' "clusterb.qumulotest.local" "$root" > lab/clusterb.qumulotest.local/clusters-line.txt
  printf '%s\n%s\n' "clusterc.qumulotest.local ip:2001:db8::10" "$root" > lab/clusterc.qumulotest.local/clusters-line.txt
  printf '%s\n' "clusterb.qumulotest.local ssh:10.1.2.11" "clusterc.qumulotest.local ip:2001:db8::10" > clusters.txt
  run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --lab-dir ./lab --dry-run
  assert_rc 0
  assert_contains "clusterb.qumulotest.local: cert unchanged"
  assert_contains "clusterc.qumulotest.local: cert unchanged"
  assert_contains "WARNING: clusterc.qumulotest.local has no ssh: nodes — it gets a cert, but its own processes won't trust the lab; this run will end with exit 2"
}

# Run CA_Lab's inventory functions on their own.
run_inv_update() {
  {
    sed -n '/^inv_file() {/,/^}/p;/^inv_update() {/,/^}/p' "$LAB"
    echo 'inv_update "$@"'
  } > inv.sh
  LAB_ABS="$PWD/lab" DRY_RUN=0 bash -c 'source ./inv.sh' _ "$@"
}

# Write-ahead inventory: a host is recorded before anything is pushed, every
# root ever pushed stays listed, and an installed container stays installed.
test_lab_inventory_records_every_root_and_keeps_installed() {
  mkdir -p lab
  run_inv_update node1 labu node "qcore:pending" lab ""
  assert_eq "$(cut -f4,5,6 lab/inventory.txt)" $'qcore:pending\tlab\t-' "first write, no root yet"
  run_inv_update node1 labu node "qcore:pending" lab "AAAA"
  run_inv_update node1 labu node "qcore:installed" lab "AAAA"
  run_inv_update NODE1 labu node "qcore:pending" lab "BBBB"
  run_inv_update node2 labu client "-" "own:/k" "BBBB"
  assert_eq "$(wc -l < lab/inventory.txt | tr -d ' ')" 2 "inventory lines"
  assert_eq "$(sed -n 1p lab/inventory.txt | cut -f1,4,6)" $'node1\tqcore:installed\tAAAA,BBBB' "node1 line"
  assert_eq "$(sed -n 2p lab/inventory.txt | cut -f1,4,5,6)" $'node2\t-\town:/k\tBBBB' "node2 line"
  [[ "$(sed -n 1p lab/inventory.txt | cut -f7)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "date field"
}

# A host that ever got the lab key keeps key-mode "lab", even if a later run
# used --ssh-key, so --remove still removes the lab key there.
test_lab_inventory_keeps_lab_key_mode() {
  mkdir -p lab
  run_inv_update node1 labu client "-" lab "AAAA"
  run_inv_update node1 labu client "-" "own:/k" "AAAA"
  assert_eq "$(cut -f5 lab/inventory.txt)" "lab" "key-mode after a later --ssh-key run"
}

test_lab_refuses_an_older_sibling_script() {
  cp "$FAKER" "$PUSHER" "$LAB" .
  sed -i.bak 's/^VERSION="2.0.0"$/VERSION="1.9.0"/' ./CA_Pusher.sh
  rm -f ./CA_Pusher.sh.bak
  write_lab_inputs
  run_cmd ./CA_Lab.sh --clusters clusters.txt --ssh-user admin --dry-run
  assert_rc 1
  assert_contains "ERROR: CA_Pusher.sh is older than CA_Lab.sh — update both"
}

test_lab_rejects_ssh_key_that_needs_a_prompt() {
  ssh-keygen -q -t ed25519 -N "secret-phrase" -f enc >/dev/null
  write_lab_inputs
  run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --ssh-key enc --dry-run
  assert_rc 1
  assert_contains "ERROR: --ssh-key enc can't be used without a prompt:"
  assert_contains "omit --ssh-key to use the lab key, or use an unencrypted key with mode 600"
  ssh-keygen -q -t ed25519 -N "" -f plain >/dev/null
  chmod 644 plain
  run_cmd "$LAB" --clusters clusters.txt --ssh-user admin --ssh-key plain --dry-run
  assert_rc 1
  assert_contains "ERROR: --ssh-key plain can't be used without a prompt:"
}

# Without a TTY a needed password comes only from CA_LAB_*_PASSWORD.
test_lab_no_tty_without_password_env_fails() {
  local c
  for c in ssh ssh-keygen ssh-copy-id sshpass; do
    command -v "$c" >/dev/null 2>&1 || { skip "$c not installed"; return 0; }
  done
  make_lab || return 1
  echo "127.0.0.1" > clients.txt
  run_in $'typed-secret\n' env -u CA_LAB_SSH_PASSWORD "$LAB" --clients clients.txt --ssh-user u \
    --lab-dir ./lab --port 1 --timeout 2
  assert_rc 1
  assert_contains "ERROR: no TTY — set CA_LAB_*_PASSWORD or run interactively"
  [[ ! -d lab/.lock ]] || fail "lock left behind"
}

# A run that does not hold the lab lock must leave the active run's tmp/
# (its qq credential stores and per-host files) alone.
test_lab_run_without_the_lock_keeps_tmp() {
  make_lab || return 1
  mkdir -p lab/.lock lab/tmp
  echo "4242 otherbox" > lab/.lock/owner
  echo marker > lab/tmp/active.cred
  printf 'admin@node1\n' > bad_clients.txt
  run_cmd "$LAB" --clients bad_clients.txt --ssh-user admin --lab-dir ./lab
  assert_rc 1
  printf 'h1\tu\tclient\t-\tlab\tAA\t2026-01-01\n' > lab/inventory.txt
  run_cmd "$LAB" --forget h1 --lab-dir ./lab
  assert_rc 1
  assert_file lab/tmp/active.cred
}

# Hosts that could not be cleaned need the lab folder for the rerun, so
# --remove must not tell the user to delete it.
test_lab_remove_with_hosts_left_does_not_say_delete() {
  command -v ssh >/dev/null 2>&1 || { skip "ssh client not installed"; return 0; }
  make_lab || return 1
  printf '127.0.0.1\tu\tclient\t-\tlab\tAA\t2026-01-01\n' > lab/inventory.txt
  run_cmd env CA_LAB_SUDO_PASSWORD=x "$LAB" --remove --lab-dir ./lab --port 1 --timeout 2
  assert_rc 2
  assert_contains "Not removed (rerun --remove"
  assert_not_contains "Now delete"
  assert_file lab/inventory.txt
}

test_lab_held_lock_fails_with_hint() {
  make_lab || return 1
  mkdir lab/.lock
  echo "4242 otherbox" > lab/.lock/owner
  printf 'h1\tu\tclient\t-\tlab\tAA\t2026-01-01\n' > lab/inventory.txt
  run_cmd "$LAB" --forget h1 --lab-dir ./lab
  assert_rc 1
  assert_contains "ERROR: another CA_Lab run is using $PWD/lab (4242 otherbox); if no run is active: rm -r $PWD/lab/.lock"
  [[ -d lab/.lock ]] || fail "the other run's lock was removed"
}

test_lab_forget_drops_host_with_warning() {
  make_lab || return 1
  printf 'h1\tu\tclient\t-\tlab\tAA\t2026-01-01\nH2\tu\tnode\tqcore:installed\tlab\tAA\t2026-01-01\n' > lab/inventory.txt
  run_cmd "$LAB" --forget h2 --lab-dir ./lab
  assert_rc 0
  assert_contains "WARNING: H2 was not cleaned; if it still exists it may still trust this lab"
  assert_eq "$(cut -f1 lab/inventory.txt)" "h1" "inventory hosts"
  [[ ! -d lab/.lock ]] || fail "lock left behind"
}

test_lab_remove_needs_inventory_and_own_keys() {
  make_lab || return 1
  run_cmd "$LAB" --remove --lab-dir ./lab
  assert_rc 1
  assert_contains "ERROR: no inventory at $PWD/lab/inventory.txt"
  printf 'h1\tu\tclient\t-\town:/home/u/.ssh/id_lab\tAA\t2026-01-01\n' > lab/inventory.txt
  run_cmd "$LAB" --remove --lab-dir ./lab
  assert_rc 1
  assert_contains "ERROR: --remove needs --ssh-key for h1 (was /home/u/.ssh/id_lab)"
}

test_lab_remove_dry_run_lists_and_takes_no_lock() {
  make_lab || return 1
  printf 'h1\tu\tnode\tqcore:installed\tlab\tAA,BB\t2026-01-01\n' > lab/inventory.txt
  local before
  before="$(tree_state lab)"
  run_cmd "$LAB" --remove --lab-dir ./lab --dry-run
  assert_rc 0
  assert_contains "Would remove from u@h1: roots AA BB (and container qcore); then the lab key"
  assert_eq "$(tree_state lab)" "$before" "lab folder after --remove --dry-run"
}

run_test() {
  local t="$1"
  T_FAILED=0
  T_SKIPPED=0
  WORK="$(mktemp -d)"
  pushd "$WORK" >/dev/null
  "$t" || T_FAILED=1
  popd >/dev/null
  rm -rf "$WORK"
  WORK=""
  if [[ "$T_FAILED" -eq 0 && "$T_SKIPPED" -eq 1 ]]; then
    SKIPPED=$((SKIPPED+1))
    echo "skip $t"
  elif [[ "$T_FAILED" -eq 0 ]]; then
    PASSED=$((PASSED+1))
    echo "ok   $t"
  else
    FAILED+=("$t")
    echo "FAIL $t"
  fi
}

main() {
  command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl is required" >&2; exit 1; }
  local tests=("$@")
  if [[ ${#tests[@]} -eq 0 ]]; then
    mapfile -t tests < <(declare -F | awk '{print $3}' | grep '^test_')
  fi
  local t
  for t in "${tests[@]}"; do
    run_test "$t"
  done
  echo
  echo "Passed: $PASSED"
  echo "Skipped: $SKIPPED"
  echo "Failed: ${#FAILED[@]}"
  if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '  %s\n' "${FAILED[@]}"
    exit 1
  fi
}

main "$@"
