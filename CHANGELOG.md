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
