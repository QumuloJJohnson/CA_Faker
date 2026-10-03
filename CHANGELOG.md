# Changelog

## 2.0.0 (unreleased)

CA_Faker now builds a proper lab CA. Browsers, `curl`, Python and other
clusters can connect to a lab cluster by name or IP without certificate
warnings, and CA_Pusher works on Rocky/RHEL as well as Ubuntu. There's also a
new script, `CA_Lab.sh`, that sets up a whole lab in one go.

### New

- **CA_Lab.sh.** List your clusters in `clusters.txt` and everything else in
  `clients.txt`, run one command, and it issues and applies every cluster's
  certificate, installs the lab CA everywhere, and tells you which machines
  can talk to which clusters. `CA_Lab.sh --remove` takes it all back out
  again. See "Easy button" in the README.
- **Rocky/RHEL support** in CA_Pusher, on hosts and inside `qcore`
  containers, including SELinux.
- **One CA for a whole lab.** Give every cluster's CA_Faker run the same
  `--ca-dir` and they share one root, so clients only need to trust one CA.
- **Removing a lab.** `CA_Pusher.sh --remove` takes a lab's root back out of a
  host's trust store, and the README has cleanup steps for nodes and desktops.
- **Desktop instructions** for Windows, macOS and Linux browsers (README
  step 5).
- `--version` on every script.

### Changed

- The certificate chain is now root → intermediate → server, so
  `certbundle.pem` has three certificates instead of two.
- Certificates list the short name as well as the full name by default, and
  an IP CN gets an IP entry. Add node names and IPs with `--san`.
- `--verify-tls` now checks that the certificate matches the name or IP you
  connect to, not just that it's signed by the lab CA. It needs a port
  (`host:443`).
- CA_Faker checks names before creating anything. Names that a browser would
  reject (an IP passed as `dns:`, `foo*.lab.test`, and so on) are refused up
  front.
- The README Quick Start now applies TLS to the cluster (step 3) before
  pushing the CA (step 4), matching upstream.

### Fixed

- Python 3.13+ and other strict clients rejected the old root CA. They
  accept the new one.
- CA_Pusher could report a host as OK when something on it had failed, and
  the container TLS check could pass against a server it didn't trust.
- Running CA_Faker a second time as a normal user failed with
  `Permission denied`.
- Deleting the server key and rerunning could leave a certificate that didn't
  match the new key.
- An empty clients file was reported as a success.

### Upgrading from 1.x

- **Make a new out-dir.** Roots made by the old CA_Faker are missing a
  setting strict clients need, so CA_Faker refuses to reuse them. Create a
  new out-dir and push the new root.
- **Apply the new certificate before pushing the new root** (README step 3,
  then step 4). Otherwise nodes reject the cluster's old certificate in
  between.
- **Expect some hosts to fail that used to pass.** Those were real problems
  the old version didn't catch. Exit code 2 means look at the failed hosts.
- **Remove old roots by file name or fingerprint, not by name.** New root
  names include a timestamp so each lab's root is easy to tell apart.
