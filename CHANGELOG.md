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
