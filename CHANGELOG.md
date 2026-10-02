# Changelog

## Upgrading from 1.x

- An existing out-dir fails with `ERROR: Existing Root CA ... is missing
  keyUsage`. Make a new out-dir (and push its root): the old root is rejected
  by strict clients such as Python 3.13+.
- Hosts that "passed" before may now fail honestly: a failed remote step, an
  untrusted container TLS endpoint, or a name the cert does not cover all
  count as failures now. Exit 2 means a real problem.
- An empty clients file is now `ERROR:` and exit 1.
- The root CN now carries a timestamp (`Company Lab Root CA <YYYYMMDD-HHMMSS>`).
  Remove old roots by file (README "Cleaning up after the lab") or by SHA-1,
  not by name.
- `certbundle.pem` holds 3 certificates (leaf, intermediate, root).
- CA_Faker prints the CN/SAN you asked for as "requested"; the values that
  count are read from the cert in the `READY.` block. CA_Pusher adds
  `RESULT ...` lines to stdout (see README); other output is unchanged.
- Upgrading a running lab: re-apply the new cert to the cluster (README step
  4) BEFORE re-pushing trust (step 3), or nodes reject the old served cert in
  between.

## 2.0.0 (unreleased)

### All scripts

- Each script checks its platform first: bash 4 or newer and OpenSSL (not
  LibreSSL). Stock macOS (bash 3.2, LibreSSL) gets an `ERROR:` with the
  Homebrew fix instead of a confusing failure later.
- New `--version` (prints `<script> 2.0.0`).

### CA_Pusher.sh

- A host is counted OK only when every step on it succeeded. Before, a failed
  remote step (for example an unreachable host) could still be counted OK.
- The container `--verify-tls` check now fails when the TLS endpoint does not
  validate. Before, it always reported "TLS OK (container)".
- An empty clients file (or one with only comments) is an error:
  `ERROR: No hosts found in <file>`, exit 1. Before, it reported `Total: 0`
  and exit 0.
- Removed the "best-effort check in /etc/ssl/certs", which could never fail.
- The remote root script is written to a fresh `mktemp` file instead of the
  fixed path `/tmp/_ca_push_script.sh`.
- `--container` names may contain only letters, digits, `.`, `_` and `-`.
- RHEL/Rocky/Alma targets are supported. The trust store family is detected
  on each host, and separately inside the container: `update-ca-certificates`
  (Ubuntu/Debian, checked first) or `update-ca-trust` (RHEL family). Neither
  present, or no `openssl`, is an error for that host.
- After the refresh, the script proves the system bundle contains the CA
  (`openssl verify -trusted <bundle>`), on the host and in the container.
  `--no-verify` skips exactly these checks; the host's `done` line and the
  summary then say so.
- Inside the container, every step runs with the container's own tools.
  The cert is written through `nsenter` (replaces `machinectl copy-to`,
  whose overwrite behaviour differs between systemd versions).
- A skipped container names the cause: `machinectl not found (install
  systemd-container)` or `is not running`.
- New `--trust-name <name>` (default `company-lab-root-ca`, the file name
  used before). Replacing a different root under the same name prints
  `WARNING: replacing a different lab's root on <host>`.
- The remote root script detaches its stdin first, so the sudo password line
  can never be read by a later command.
- `--verify-tls` may be given more than once. Every endpoint is checked on the
  host and in the container; one failure no longer stops the others, and the
  host fails at the end if any check failed.
- `RESULT <host> ...` lines on stdout, one per proven fact (README lists the
  format). `trust` is `NOT-VERIFIED`, never `OK`, with `--no-verify`.
  Replacing a different root also prints `RESULT <host> trust-replaced <sha256>`.
- A skipped container is shown on the host's `done` line and in the summary
  (`Container skipped on:`).
- `--sudo-password-stdin` reads the sudo password from stdin. An empty sudo
  password now means passwordless sudo (checked per host with `sudo -n true`).
- `--ca` also accepts a directory holding `ca.crt.pem` itself.
- Hosts in the clients file may contain only letters, digits, `.`, `_`, `:`
  and `-`; other lines are an `ERROR:` before anything is pushed.
- New `--remove --remove-sha256 <hex> [...]`: removes those roots from every
  host (and `--container`) and proves the refreshed bundle no longer holds
  them.
- `--verify-tls` checks the hostname (or IP) as well as the chain, on the
  host and in the container (`-verify_hostname` / `-verify_ip`; SNI is sent
  for names). The value must be `host:port`, IPv6 in brackets
  (`[2001:db8::10]:443`); anything else is an `ERROR:` before any prompt.

### CA_Faker.sh

- The chain is now root CA -> intermediate CA -> server cert, and
  `certbundle.pem` holds all three (leaf, intermediate, root). New files:
  `ca/intermediate.crt.pem`, `ca/intermediate.key.pem` and the serial files
  `ca/ca.crt.srl`, `ca/intermediate.crt.srl`.
- The root and intermediate carry `keyUsage = critical, keyCertSign, cRLSign`
  (strict clients such as Python 3.13+ rejected the old root). Every cert
  carries explicit Subject/Authority Key Identifiers, so OpenSSL 1.1.1 and
  3.x produce the same chain.
- Root and intermediate names carry a timestamp
  (`Company Lab Root CA <YYYYMMDD-HHMMSS>`), so every lab root is unique.
- What is rebuilt is a strict cascade: a new root forces a new intermediate,
  a new intermediate or server key forces a new server cert, and the CSR is
  always regenerated with the server cert (a new key or `--cn` can no longer
  be paired with an old CSR).
- Reruns work as a normal user: every file is removed before it is
  rewritten (before, the 444/400 files caused `Permission denied`).
- A reused server cert prints one fixed line saying your `--cn`/`--san`
  were not applied and how to apply them.
- After generation the script proves what it ships: chain, purpose and every
  name in the cert (`openssl verify -x509_strict -purpose sslserver
  -trusted`), keyUsage / key identifiers, that the server key matches the
  cert, and the bundle order. `certbundle.pem` is published only after all
  checks pass; on failure the previous bundle is left untouched.
- An out-dir whose root lacks keyUsage (made by an older CA_Faker) is
  refused: `ERROR: Existing Root CA at ... is missing keyUsage`.
- `READY.` lists what was created or reused, read from the certs (CN,
  expiry, root SHA-256 and SHA-1), the names covered, and the next commands.
- Names are validated before anything is generated (a bad name leaves no
  half-built CA): `ip:` values must be IP addresses, `dns:` values must not
  be; labels are letters, digits, `-` and `_`; no empty labels or trailing
  dot; the last label may not be all digits or `0x` hex; `*` only as the
  whole first label of a name with at least two more labels; `--cn` at most
  64 characters.
- Default SAN when `--san` is omitted: `ip:<cn>` for an IP CN,
  `dns:<cn>,dns:<first label>` for a dotted name (the short name is skipped
  if browsers would read it as an IP), `dns:<cn>` otherwise. The CN is added
  to `--san` when missing, with an `INFO:` line.
- `--server-days` above 825 prints a WARNING (Apple's limit).
- New `--check-names`: validates `--cn`/`--san`, prints the final SAN list
  one entry per line, writes nothing.
- New optional `--ca-dir <path>` (default `<out-dir>/ca`, today's layout).
  Give every server of one lab the same `--ca-dir` to share one root and
  intermediate; the out-dir then gets only the public `ca/ca.crt.pem` and
  `ca/intermediate.crt.pem`, so `CA_Pusher.sh --ca <out-dir>` works as
  before. Mixing an own-CA out-dir with a shared CA (or the reverse) is an
  `ERROR:` instead of a silent second CA.
- One run at a time per CA dir (`<ca-dir>/.lock`).
- New `ca/ca.cer`: DER copy of the root for double-click import on desktops.
- `READY.` points desktops/browsers to README step 5 and names every folder
  that must be kept secret.

### README.md

- Desktop/browser trust table (step 5), "Cleaning up after the lab",
  "Keep the lab CA secret", exit codes, glossary, `--san` example with node
  names and IPs, `--ca-dir` for multi-cluster labs, RHEL/Rocky support.

### CA_Lab.sh (new)

- The easy button: `./CA_Lab.sh --clusters clusters.txt --clients clients.txt
  --ssh-user <user>` issues a cert from one lab CA for every cluster, applies
  it with `qq`, makes every listed machine (and its container) trust the lab,
  and proves every machine validates every cluster. Exit 0 only when
  everything listed was done and proven.
- One-time lab SSH key push, passwords asked once each (or `CA_LAB_*_PASSWORD`
  without a TTY), `--ssh-key` for an existing key, `--dry-run`.
- `inventory.txt` and a log per run in the lab-dir; `--remove` removes every
  root this lab pushed and the lab key, with proof; `--forget <host>` for
  machines that no longer exist.
