#!/usr/bin/env bash
# tests/run_tests.sh
#
# Local checks for CA_Faker.sh and CA_Pusher.sh.
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

CACHE="$(mktemp -d)"
WORK=""
OUT=""
STDOUT=""
RC=0
T_FAILED=0
T_SKIPPED=0
PASSED=0
SKIPPED=0
FAILED=()

cleanup() {
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
  command -v shellcheck >/dev/null 2>&1 || return 0
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
  for ph in __B64_CERT__ __CONTAINER__ __VERIFY_TLS__ __VERIFY__ __TRUST_NAME__; do
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
  assert_contains "WARNING: this root can sign certs for ANY site"
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
