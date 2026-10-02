# CA Faker & CA Pusher

Generate a lab CA (root -> intermediate) and a server certificate, push the CA
trust to remote Ubuntu or RHEL/Rocky/Alma nodes (and their nspawn containers),
and apply TLS to a Qumulo cluster. Clients then validate the cluster's
certificate properly (chain AND hostname) with no warnings and no `-k`.

**IMPORTANT NOTE: This process is meant for lab and testing use only, do not use in production!!**

## How It Works

Both scripts run from any admin machine (your laptop on Linux, WSL, or macOS
with Homebrew bash and OpenSSL; a jump box, etc.) —
nothing needs to run on a Qumulo node.

1. **CA_Faker.sh** generates a root CA, an intermediate CA and a server
   certificate locally (chain: root -> intermediate -> server).
2. **CA_Pusher.sh** SSHes into each client node and installs the CA cert into
   the host's trust store (and optionally into a systemd-nspawn container).
3. You apply the server certificate to the Qumulo cluster via `qq` CLI.

Qumulo replication and portals use each cluster's own built-in identity
certificates; CA_Faker does not change or need to change them.

Terms used below:
- **out-dir**: one server's folder (`CA_Faker.sh --out-dir`): its key, cert,
  `certbundle.pem` and the public CA certs.
- **ca-dir**: where the lab CA and its keys live (`CA_Faker.sh --ca-dir`,
  default `<out-dir>/ca`). Share one per lab.
- **lab-dir**: CA_Lab's folder for one whole lab (`--lab-dir`, default
  `./lab-tls`): the lab CA, one out-dir per cluster, the lab SSH key, the
  inventory and the logs.

See [CHANGELOG.md](CHANGELOG.md), including **Upgrading from 1.x**.

## Requirements

Admin machine (where you run the scripts):
- bash 4 or newer, openssl (OpenSSL, not LibreSSL), ssh
- On macOS: `brew install bash openssl@3`, then run the scripts with
  `PATH="$(brew --prefix openssl@3)/bin:$PATH" bash ./CA_Faker.sh ...`
  (stock macOS bash and LibreSSL are refused with that hint)
- sshpass (only if using password-based SSH auth)

Remote nodes (targets of CA_Pusher.sh):
- **Ubuntu/Debian or RHEL/Rocky/Alma target machine** with a sudo-capable SSH user
- `openssl` on each node, and inside each container
- Other Linux distros and OSes are not supported as targets
- Optional: systemd-nspawn container (e.g. `qcore`); the host needs
  `machinectl` (package `systemd-container`)

## Keep the lab CA secret

A lab CA is a root that every machine you add it to will trust for ANY site.
Whoever has `ca/ca.key.pem` or `ca/intermediate.key.pem` can impersonate any
HTTPS site to those machines until the root expires or is removed.

- Treat the out-dir, ca-dir and lab-dir as **secrets**: never commit, zip,
  email or put them on shared storage. `private.key.insecure`, CA_Lab's
  `ssh/id_ed25519` (it is root on hosts with passwordless sudo) and
  `inventory.txt` are secrets too.
- When the lab ends, remove the root from every machine (see
  [Cleaning up after the lab](#cleaning-up-after-the-lab)) and delete the
  folders.
- Desktops: prefer the per-user store (see step 5); use the system store only
  when needed. Check with IT/InfoSec before adding a root to a managed laptop
  (EDR/MDM tools may flag it).

## Easy button: CA_Lab.sh

One lab = one CA. List your clusters and your other machines in two text
files, run one command, and every listed machine trusts the lab and validates
every listed cluster. CA_Lab.sh drives CA_Faker.sh, CA_Pusher.sh and `qq`;
the step-by-step Quick Start below does the same by hand.

Needs a Linux or WSL admin machine with `qq`, `ssh`, `ssh-keygen`,
`ssh-copy-id`, `sshpass` (only for the one-time key push) and `setsid`.

1. `clusters.txt`: one cluster per line, `#` comments and blank lines ignored.
   First the cluster's FQDN, then any extra `dns:`/`ip:` names for its cert,
   then its nodes as `ssh:<node>` (CA_Lab logs into them; they are never put in
   the cert):
   ```
   # <cluster FQDN>  [dns:/ip: names for the cert]  [ssh:<node> ...]
   stratusdatacore.qumulotest.local  ip:10.1.1.10 dns:node1.qumulotest.local ssh:10.1.1.11 ssh:10.1.1.12
   clusterb.qumulotest.local         ip:10.1.2.10 ssh:10.1.2.11
   ```
   Put cluster nodes here as `ssh:` entries, not in `clients.txt`: only `ssh:`
   nodes have their `qcore` container required and count toward "trusted on
   nodes".
2. `clients.txt`: every other machine that talks to the lab, one per line
   (the same format as CA_Pusher's clients file):
   ```
   client1.qumulotest.local
   10.1.3.20
   ```
3. Run it:
   ```bash
   ./CA_Lab.sh --clusters clusters.txt --clients clients.txt --ssh-user admin
   ```
   It asks each password once, hidden: the SSH password (only if the lab key
   is not installed yet), the sudo password (only where sudo needs one) and
   the Qumulo admin password. It assumes one SSH/sudo user and password for
   all `clients.txt` hosts and one for all `ssh:` nodes (`--node-user`; may be
   the same).
4. Read the summary. Exit 0 means everything listed was done AND proven;
   anything else is listed under `Not done:` and the exit code is 2.
5. Trust the lab on admin desktops per step 5 below (the summary prints the
   root CN and SHA-1).

What one run does, in order: checks both files and every name (nothing is
changed if anything is wrong); creates the lab SSH key once and pushes it to
machines that do not have it yet; issues a cert for every cluster from the lab
CA (reissued automatically when the cluster's line or the lab CA changed);
applies it with `qq` unless the cluster already serves it, then waits until
it is served; installs the lab root on every machine and its container and
checks that each one validates every cluster on port 443 (fixed); and finally
checks every name in each cert from the admin machine.

| Flag | Description |
|------|-------------|
| `--clusters <file>` / `--clients <file>` | The two files; at least one is required. `--clients` alone re-checks an existing lab |
| `--ssh-user <name>` | SSH + sudo user on every machine (prompted if omitted) |
| `--node-user <name>` | Different SSH + sudo user for `ssh:` nodes (default: `--ssh-user`) |
| `--node-container <name>` | Container on `ssh:` nodes (default `qcore`; `none` to skip) |
| `--container <name>` | Container on `clients.txt` hosts (default: none, as CA_Pusher) |
| `--lab-dir <path>` | Lab folder (default `./lab-tls`) |
| `--qq-user <name>` | Qumulo admin user (default `admin`) |
| `--port <n>`, `--timeout <sec>` | SSH port and connect timeout |
| `--ssh-key <path>` | Use an existing unencrypted key (mode 600) instead of the lab key; no key push |
| `--new-lab` | Allow creating a new lab CA when there is no TTY to confirm it |
| `--dry-run` | Show the checks, targets and which clusters would be (re)issued; change nothing |
| `--remove` | Remove this lab from every machine in the inventory, then the lab key |
| `--forget <host>` | Drop a host (e.g. a destroyed VM) from the inventory without contacting it |
| `--version` | Show version |

Good to know:
- A new lab CA lives 730 days. Creating one asks for confirmation (or
  `--new-lab` without a TTY); a mistyped `--lab-dir` is caught that way.
- Without a TTY, passwords come only from `CA_LAB_SSH_PASSWORD`,
  `CA_LAB_SUDO_PASSWORD` and `CA_LAB_QQ_PASSWORD`; stdin is never read.
- Each run writes `<lab-dir>/logs/<time>.log` (no passwords) and keeps
  `<lab-dir>/inventory.txt`: every machine and every lab root pushed to it, so
  `--remove` can clean them all.
- Each lab's root is installed as `company-lab-root-ca-<12 hex>.crt`, so
  several labs can share a machine.
- `--clients` alone checks clusters already in the lab-dir. Delete
  `<lab-dir>/<fqdn>` for clusters that no longer exist, or they keep failing.
- Rerun CA_Lab after a Qumulo upgrade, a node replacement or a new `qcore`
  image (tested with Qumulo Core 7.8.4.3 and 7.9.0).
- A cluster line with no `ssh:` nodes still gets a cert, but its own
  processes won't trust the lab; the run then ends with exit 2.

## Quick Start (doing it step by step)

### 1. Generate CA + server certificate (run on your admin machine)

```bash
./CA_Faker.sh \
  --cn myserver.lab.example.com \
  --out-dir ./qumulo-tls
```

This creates the output files locally in `--out-dir`. No root required, no
remote hosts contacted.

Clients and browsers can connect ONLY by the names and IPs listed in the
certificate. By default it lists the CN and its short name (`myserver`). If
clients use node names or IPs, list them all with `--san`:

```bash
./CA_Faker.sh \
  --cn stratusdatacore.qumulotest.local \
  --san "dns:stratusdatacore.qumulotest.local,dns:node1.qumulotest.local,ip:10.1.1.10,ip:10.1.1.11" \
  --out-dir ./stratusdatacore
```

For a lab with more than one cluster, add the same `--ca-dir ./lab1-ca` to each
cluster's CA_Faker run (each keeps its own `--out-dir`) so they share one root.

### 2. Create a clients file

List the remote nodes that need to trust your CA — one hostname or IP per line.
Blank lines and `#` comments are ignored.

```
node1.lab.example.com
node2.lab.example.com
node3.lab.example.com
```

### 3. Push CA to remote nodes (run on your admin machine)

Push the CA cert to each node and its `qcore` nspawn container, then verify
that TLS works end-to-end:

```bash
./CA_Pusher.sh \
  --clients clients.txt \
  --ca ./qumulo-tls \
  --ssh-user admin \
  --auth key \
  --container qcore \
  --verify-tls myserver.lab.example.com:443
```

If your nodes do not run nspawn containers, omit `--container`.
`--verify-tls` checks the cluster after its cert is applied (step 4); on a
first run omit it, then rerun step 3 with it after step 4 to confirm end to
end. It checks the chain AND the name: use an FQDN that resolves the same on
every node (and inside the container), or an IP that is in the cert.

### 4. Apply TLS to Qumulo

From your admin machine (where CA_Faker.sh was run, assumign the `qq` CLI is available - This is the easiest method):

```bash
qq --host your.qumulo.cluster.com login -u admin
qq --host your.qumulo.cluster.com ssl_modify_certificate \
  -c ./qumulo-tls/certbundle.pem \
  -k ./qumulo-tls/private.key.insecure
```

Or from inside a `qcore` container. CA_Pusher installs the CA cert at
`/usr/local/share/ca-certificates/company-lab-root-ca.crt` (Ubuntu/Debian) or
`/etc/pki/ca-trust/source/anchors/company-lab-root-ca.crt` (RHEL family), but
the certbundle and private key must be copied separately:

```bash
# From your admin machine, copy the files into the container via the host:
scp ./qumulo-tls/certbundle.pem ./qumulo-tls/private.key.insecure \
  admin@node1:/tmp/

# On the host, copy into the container (if repeating, first run
# sudo machinectl shell qcore /bin/rm -f /tmp/certbundle.pem /tmp/private.key.insecure):
sudo machinectl copy-to qcore /tmp/certbundle.pem /tmp/certbundle.pem
sudo machinectl copy-to qcore /tmp/private.key.insecure /tmp/private.key.insecure

# Inside the container:
qq ssl_modify_certificate \
  -c /tmp/certbundle.pem \
  -k /tmp/private.key.insecure
```

### 5. Trust the CA on admin desktops (browsers)

Run these on each desktop whose browser should open the cluster without a
warning. `ca.crt.pem` is `<out-dir>/ca/ca.crt.pem` (`ca/ca.cer` is the same
cert in DER form, for double-click import). `<SHA-1>` and `<root CN>` are
printed by CA_Faker's `READY.` output. Restart the browser after installing.

| Desktop | Install | Remove | Browsers covered |
|---------|---------|--------|------------------|
| Windows (admin prompt) | `certutil -addstore -f Root ca.crt.pem` | `certutil -delstore Root <SHA-1>` | Chrome, Edge; Firefox 120+ (imports OS roots by default) |
| macOS (local Terminal; macOS 11+ asks for GUI authorization) | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt.pem` | `sudo security remove-trusted-cert -d ca.crt.pem` then `sudo security delete-certificate -Z <SHA-1> /Library/Keychains/System.keychain` | Safari, Chrome, Edge; Firefox 120+ |
| Ubuntu desktop, Chrome/Edge | `mkdir -p ~/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "<root CN>" -i ca.crt.pem` (needs `libnss3-tools`; snap Chromium: `~/snap/chromium/current/.pki/nssdb`) | `certutil -d sql:$HOME/.pki/nssdb -D -n "<root CN>"` | Chrome, Edge, Chromium |
| Ubuntu desktop, Firefox | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import | same dialog → Delete | Firefox |
| RHEL/Fedora desktop | node commands (`update-ca-trust`, see [Cleaning up](#cleaning-up-after-the-lab) for the path) **and** the nssdb command for Chrome/Edge | reverse both | Firefox, system tools; Chrome/Edge via nssdb |

Per-user alternatives (preferred where they work for you): Windows
`certutil -user -addstore Root ca.crt.pem` (remove: `certutil -user -delstore Root <SHA-1>`);
macOS login keychain `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ca.crt.pem`
(remove: `security remove-trusted-cert ca.crt.pem` then
`security delete-certificate -Z <SHA-1> ~/Library/Keychains/login.keychain-db`).

## Cleaning up after the lab

Do this in order when the lab is gone:

1. If the `READY.` output is gone, re-print the root's CN and SHA-1:
   ```bash
   openssl x509 -in <out-dir>/ca/ca.crt.pem -noout -subject -fingerprint -sha1
   ```
2. Desktops: remove the root per the table in step 5.
3. Nodes and their containers: remove the file and refresh the trust store.
   - Ubuntu/Debian:
     `sudo rm /usr/local/share/ca-certificates/company-lab-root-ca.crt && sudo update-ca-certificates --fresh`
   - RHEL/Rocky/Alma:
     `sudo rm /etc/pki/ca-trust/source/anchors/company-lab-root-ca.crt && sudo update-ca-trust extract`
   - Inside a container: run the same commands in `sudo machinectl shell <name>`.
   (If you used `--trust-name <name>`, the file is `<name>.crt`.)
4. Delete the out-dir (and the ca-dir) **last**.

With CA_Lab, `./CA_Lab.sh --remove --lab-dir <lab-dir>` does step 3 for every
machine in the inventory (every root this lab ever pushed, host and container),
proves each removal, then removes the lab SSH key from `authorized_keys` (only
where trust was removed). It prints the desktop steps and what is left; then
delete the lab-dir.

## CA_Faker.sh Options

| Flag | Description |
|------|-------------|
| `--cn <fqdn>` | **(required)** Server Common Name (64 characters or fewer) |
| `--san <list>` | SAN list, e.g. `"dns:a.com,ip:10.0.0.1"` (default: `ip:<cn>` for an IP, `dns:<cn>,dns:<short name>` for a dotted name, else `dns:<cn>`; the CN is always added) |
| `--out-dir <path>` | Output directory (default: `./qumulo-tls`) |
| `--ca-dir <path>` | Where the root + intermediate CA live (default: `<out-dir>/ca`); give every server of one lab the same `--ca-dir` |
| `--server-days <n>` | Server cert validity in days (default: 825; Apple devices reject more) |
| `--ca-days <n>` | CA cert validity in days (default: 3650) |
| `--force-reissue` | Regenerate server key/cert even if already present |
| `--check-names` | Validate `--cn`/`--san`, print the final SAN list, write nothing |
| `--version` | Show version |

Name rules (checked before anything is written): `ip:` values must be IP
addresses and IPs must use `ip:` (browsers match IPs only against IP
entries); DNS labels use letters, digits, `-` and `_`, with no empty labels or
trailing dot; the last label may not be all digits; `*` only as the whole
first label of a name with at least two more labels (`*.lab.test`). Use
`xn--` punycode for international names.

Reruns: existing files are reused. A reused server cert keeps its names; the
script says so and prints the names read from the cert. To change names,
rerun with `--force-reissue`, then re-apply `certbundle.pem` AND
`private.key.insecure` with `qq`. A new root forces a new intermediate and a
new server cert. If a lab's ca-dir is deleted and rebuilt, rerun each out-dir
with `--force-reissue` and re-apply and re-push.

## CA_Pusher.sh Options

| Flag | Description |
|------|-------------|
| `--clients <file>` | **(required)** File with target hostnames/IPs |
| `--ca <dir>` | **(required)** Output directory from CA_Faker.sh (a server's out-dir; a dir holding `ca.crt.pem` itself, such as a `--ca-dir`, also works) |
| `--ssh-user <name>` | SSH username (prompts if omitted) |
| `--auth key\|password` | SSH auth method (prompts if omitted; `password` requires sshpass) |
| `--key <path>` | SSH private key path |
| `--port <n>` | SSH port (default: 22) |
| `--container <name>` | Also install cert into a systemd-nspawn container on each host |
| `--verify-tls <host:port>` | End-to-end TLS check from host and container after install; checks the chain AND the name or IP (port required, IPv6 as `[addr]:port`); repeatable, every endpoint is checked |
| `--no-verify` | Skip the check that the refreshed trust store contains the CA |
| `--trust-name <name>` | Trust file name on targets, without `.crt` (default: `company-lab-root-ca`) |
| `--sudo-password-stdin` | Read the sudo password from the first line of stdin instead of prompting |
| `--remove` | Remove lab roots instead of installing (host and `--container`); needs `--remove-sha256` |
| `--remove-sha256 <hex>` | SHA-256 of a root to remove (64 uppercase hex, no colons); repeatable |
| `--timeout <sec>` | SSH connect timeout (default: 8) |
| `--version` | Show version |

Each target keeps one lab root under a given trust file name: pushing a
different lab's root under the same name replaces it, with a WARNING. Use
`--ca-dir` so all clusters of a lab share one root, or a different
`--trust-name` per lab to keep several labs side by side.

A container that is not usable (no `machinectl`, or not running) gets a
WARNING naming the cause and is skipped; the host still counts as OK, its
`done` line says `(container <name> SKIPPED)` and the summary lists it under
`Container skipped on:`.

An empty sudo password means passwordless sudo: each host is checked with
`sudo -n true` and fails if it needs a password.

`--remove` deletes, on each host and in the container, every single-cert file
in the trust store directory that holds one of the listed roots (any file
name), refreshes the store, and then proves that no listed root is left in the
system bundle. A file holding several certs is never edited: it is named and
the host fails. Get a root's value with:
`openssl x509 -in ca/ca.crt.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :`

Results for scripts: besides its normal output, CA_Pusher prints one line per
proven fact on stdout. This format is stable:

```
RESULT <host> trust OK|FAILED|NOT-VERIFIED
RESULT <host> trust-replaced <old-sha256>
RESULT <host> container <name> OK|SKIPPED|FAILED|NOT-VERIFIED
RESULT <host> tls host <host:port> OK|FAILED
RESULT <host> tls container <name> <host:port> OK|FAILED
RESULT <host> trust REMOVED|FAILED                  (--remove)
RESULT <host> container <name> trust REMOVED|FAILED (--remove)
```

`<host>` is the line from the clients file. Count a fact only from its `OK`
(or `REMOVED`) line; a missing line means it was not proven. `trust-replaced`
is informational (a different root was overwritten).

## Exit Codes

| Script | 0 | 1 | 2 |
|--------|---|---|---|
| CA_Faker.sh | everything built and proven | error, nothing published | — |
| CA_Pusher.sh | every host done | bad arguments or input (nothing pushed) | one or more hosts failed |
| CA_Lab.sh | everything listed done and proven | bad input or setup error (no cluster or trust store changed) | something not done or not proven (see `Not done:`) |

## Output Files

```
<out-dir>/
  private.key.insecure   # Server private key (unencrypted)
  certbundle.pem         # Leaf + intermediate + root bundle (Qumulo order)
  ca/ca.crt.pem          # Root CA cert (distribute to clients)
  ca/ca.cer              # Same root CA cert in DER form (double-click import)
  ca/ca.key.pem          # Root CA key (protect this)
  ca/intermediate.crt.pem  # Intermediate CA cert
  ca/intermediate.key.pem  # Intermediate CA key (protect this)
  ca/ca.crt.srl, ca/intermediate.crt.srl  # Serial numbers
  issued/server.crt.pem  # Server leaf cert
  csr/server.csr.pem     # Certificate signing request
```

With `--ca-dir`, the CA keys, certs and serial files live in the ca-dir; the
out-dir's `ca/` then holds only `ca.crt.pem`, `intermediate.crt.pem` and
`ca.cer`.

## Manual Testing

The `--verify-tls` flag handles end-to-end verification automatically. The
commands below are useful for debugging if something goes wrong.  

If you have already applied the certs to a Qumulo cluster via `qq` then you can use
it as a verfication target from your non-Qumulo clients that received the self-trusted
CA certs via CA_Pusher.sh using port 443 or 9000

Verify the certificate chain and name locally:

```bash
openssl verify -trusted ./qumulo-tls/ca/ca.crt.pem \
  -untrusted ./qumulo-tls/ca/intermediate.crt.pem \
  -verify_hostname myserver.lab.example.com \
  ./qumulo-tls/issued/server.crt.pem
# Expected: ./qumulo-tls/issued/server.crt.pem: OK
```

Test a TLS connection from a Cluster B node:

```bash
echo | openssl s_client -connect <cluster-a-host>:443 \
  -verify_return_error -verify_hostname <cluster-a-host> -brief
# Look for: Verification: OK
```

## Troubleshooting

- `.local` names are also used by mDNS/Bonjour, so on macOS a name that
  "won't resolve" is a DNS issue, not a certificate issue — make sure the lab
  DNS server answers for `qumulotest.local`.
- CA_Lab turns the SSH agent off for its own SSH calls and for CA_Pusher. An
  `IdentityAgent` line in `~/.ssh/config` can still affect CA_Pusher's calls;
  the worst case is a host reported as failed, never a false pass.
