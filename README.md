# CA Faker & CA Pusher

Generate a self-signed CA and server certificate, push the CA trust to remote
Ubuntu/Debian and Rocky/RHEL nodes (and their nspawn containers), and apply TLS
to a Qumulo cluster.

**IMPORTANT NOTE: This process is meant for lab and testing use only, do not use in production!!**

## How It Works

Both scripts run from any admin machine (your laptop, a jump box, etc.) —
nothing needs to run on a Qumulo node.

1. **CA_Faker.sh** generates a root CA and server certificate locally.
2. You apply the server certificate to the Qumulo cluster via `qq` CLI.
3. **CA_Pusher.sh** SSHes into each client node and installs the CA cert into
   the host's trust store (and optionally into a systemd-nspawn container),
   then can verify TLS against the cluster configured in step 2.

## Requirements

Admin machine (where you run the scripts):
- bash 4+ (macOS's built-in `/bin/bash` 3.2 is too old; use a newer bash, e.g. from Homebrew), openssl, ssh
- sshpass (only if using password-based SSH auth)
  - Ubuntu/Debian: `sudo apt-get install -y sshpass`
  - Rocky/RHEL: `sudo dnf install -y epel-release && sudo dnf install -y sshpass`

Remote nodes (targets of CA_Pusher.sh):
- An SSH user that can `sudo` (with a password)
- openssl, plus one of the supported trust stores. CA_Pusher detects which one
  each host (and each container) has:

  | Distro family | CA installed at | Refreshed with |
  |---------------|-----------------|----------------|
  | Ubuntu / Debian | `/usr/local/share/ca-certificates/company-lab-root-ca.crt` | `update-ca-certificates` |
  | Rocky / RHEL / Fedora | `/etc/pki/ca-trust/source/anchors/company-lab-root-ca.crt` | `update-ca-trust extract` |

- Optional: systemd-nspawn container (e.g. `qcore`); it may run a different
  distro than its host

> **Apps with their own TLS library (e.g. wolfSSL):** CA_Pusher puts the CA in
> the OS trust store. Apps built on OpenSSL/GnuTLS read that automatically, but
> a wolfSSL app only uses it if it loads the system CAs
> (`wolfSSL_CTX_load_system_CA_certs()`, wolfSSL built with system CA support,
> the default) — otherwise point the app at `ca/ca.crt.pem` directly.

## Quick Start

### 1. Generate CA + server certificate (run on your admin machine)

```bash
./CA_Faker.sh \
  --cn myserver.lab.example.com \
  --out-dir ./qumulo-tls
```

This creates the output files locally in `--out-dir`. No root required, no
remote hosts contacted.

### 2. Create a clients file

List the remote nodes that need to trust your CA — one hostname or IP per line.
Blank lines and `#` comments are ignored.

```
node1.lab.example.com
node2.lab.example.com
node3.lab.example.com
```

### 3. Apply TLS to Qumulo

From your admin machine (where CA_Faker.sh was run, assuming the `qq` CLI is available - This is the easiest method):

```bash
qq --host your.qumulo.cluster.com ssl_modify_certificate \
  -c ./qumulo-tls/certbundle.pem \
  -k ./qumulo-tls/private.key.insecure
```

Or from inside a `qcore` container. Copy the certbundle and private key in
first (the CA cert itself is installed by CA_Pusher in step 4):

```bash
# From your admin machine, copy the files into the container via the host:
scp ./qumulo-tls/certbundle.pem ./qumulo-tls/private.key.insecure \
  admin@node1:/tmp/

# On the host, copy into the container:
sudo machinectl copy-to qcore /tmp/certbundle.pem /tmp/certbundle.pem
sudo machinectl copy-to qcore /tmp/private.key.insecure /tmp/private.key.insecure

# Inside the container:
qq ssl_modify_certificate \
  -c /tmp/certbundle.pem \
  -k /tmp/private.key.insecure
```

### 4. Push CA to remote nodes (run on your admin machine)

Push the CA cert to each node and its `qcore` nspawn container, then verify
that TLS works end-to-end against the cluster you configured in step 3:

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
If the cluster isn't serving the new certificate yet, omit `--verify-tls`.

A node is counted as OK only if the install, the trust check (unless
`--no-verify`) and the `--verify-tls` handshakes (if given) all succeed.
`--verify-tls` needs an explicit port, and the name you give must be one the
server certificate covers (use the same name as `--cn`/`--san` in CA_Faker.sh).
If only the container check fails while the host check passes, look at the
container's DNS/network: in `qcore`, networking (including DNS) is configured
inside the container, not on the host.

The script exits `2` and lists the failed nodes if any node fails.

## CA_Faker.sh Options

| Flag | Description |
|------|-------------|
| `--cn <fqdn>` | **(required)** Server Common Name |
| `--san <list>` | SAN list, e.g. `"dns:a.com,ip:10.0.0.1"` (default: `dns:<cn>`) |
| `--out-dir <path>` | Output directory (default: `./qumulo-tls`) |
| `--server-days <n>` | Server cert validity in days (default: 825) |
| `--ca-days <n>` | CA cert validity in days (default: 3650) |
| `--force-reissue` | Regenerate server key/cert even if already present |

## CA_Pusher.sh Options

| Flag | Description |
|------|-------------|
| `--clients <file>` | **(required)** File with target hostnames/IPs |
| `--ca <dir>` | **(required)** Output directory from CA_Faker.sh |
| `--ssh-user <name>` | SSH username (prompts if omitted) |
| `--auth key\|password` | SSH auth method (prompts if omitted; `password` requires sshpass) |
| `--key <path>` | SSH private key path |
| `--port <n>` | SSH port (default: 22) |
| `--container <name>` | Also install cert into a systemd-nspawn container on each host |
| `--verify-tls <host:port>` | After install, TLS handshake to `host:port` from the host (and container) must verify against the system trust store, and the server cert must match `host` (DNS name or IP). The port is required. Host and container are both checked even if one fails; any failure fails the node |
| `--no-verify` | Skip the post-install check that the CA is trusted by the system store (`openssl verify`) |
| `--timeout <sec>` | SSH connect timeout (default: 8) |

## Output Files

```
<out-dir>/
  private.key.insecure   # Server private key (unencrypted)
  certbundle.pem         # Leaf + CA bundle (Qumulo order)
  ca/ca.crt.pem          # Root CA cert (distribute to clients)
  ca/ca.key.pem          # Root CA key (protect this)
  ca/ca.srl              # CA serial number file
  issued/server.crt.pem  # Server leaf cert
  csr/server.csr.pem     # Certificate signing request
```

## Manual Testing

The `--verify-tls` flag handles end-to-end verification automatically. The
commands below are useful for debugging if something goes wrong.  

If you have already applied the certs to a Qumulo cluster via `qq` then you can use
it as a verification target from your non-Qumulo clients that received the self-trusted
CA certs via CA_Pusher.sh using port 443 or 9000

Verify the certificate chain locally:

```bash
openssl verify -CAfile ./qumulo-tls/ca/ca.crt.pem \
  ./qumulo-tls/issued/server.crt.pem
# Expected: server.crt.pem: OK
```

Test a TLS connection from a Cluster B node:

```bash
echo | openssl s_client -connect <cluster-a-host>:443 -brief
# Look for: Verification: OK
```
