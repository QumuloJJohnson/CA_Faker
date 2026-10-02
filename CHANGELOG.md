# Changelog

## 2.0.0 (unreleased)

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
