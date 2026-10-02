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
