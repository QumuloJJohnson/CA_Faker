# Changelog

## 2.0.0 (unreleased)

CA_Faker now builds a proper lab CA. Browsers, `curl`, Python and other
clusters can connect to a lab cluster by name or IP without certificate
warnings. There's also a new script, `CA_Lab.sh`, that sets up a whole lab in
one go.

This release builds on Joe Costa's Rocky 9.3 update, which added Rocky/RHEL
trust stores to CA_Pusher (with `restorecon` and container support), checks
the hostname and requires a port in `--verify-tls`, counts a host as failed
when its install fails, and moved "apply TLS" before "push the CA" in the
Quick Start.

### New

- **CA_Lab.sh.** List your clusters in `clusters.txt` and everything else in
  `clients.txt`, run one command, and it issues and applies every cluster's
  certificate, installs the lab CA everywhere, and tells you which machines
  can talk to which clusters. `CA_Lab.sh --remove` takes it all back out
  again. See "Easy button" in the README.
- **One CA for a whole lab.** Give every cluster's CA_Faker run the same
  `--ca-dir` and they share one root, so clients only need to trust one CA.
- **Removing a lab.** `CA_Pusher.sh --remove` takes a lab's root back out of a
  host's trust store, and the README has cleanup steps for nodes and desktops.
- **Desktop instructions** for Windows, macOS and Linux browsers (README
  step 5).
- **More from CA_Pusher.** It checks that the CA really landed in the system
  bundle, works with confined SELinux containers, accepts passwordless sudo,
  and `--verify-tls` can be given more than once.
- `--version` on every script.

### Changed

- The certificate chain is now root → intermediate → server, so
  `certbundle.pem` has three certificates instead of two.
- Certificates list the short name as well as the full name by default, and
  an IP CN gets an IP entry. Add node names and IPs with `--san`.
- CA_Faker checks names before creating anything. Names that a browser would
  reject (an IP passed as `dns:`, `foo*.lab.test`, and so on) are refused up
  front.

### Fixed

- Python 3.13+ and other strict clients rejected the old root CA. They
  accept the new one.
- Running CA_Faker a second time as a normal user failed with
  `Permission denied`.
- Deleting the server key and rerunning could leave a certificate that didn't
  match the new key.
- An empty clients file was reported as a success.

### Upgrading from the old scripts

- **Make a new out-dir.** Roots made by the old CA_Faker are missing a
  setting strict clients need, so CA_Faker refuses to reuse them. Create a
  new out-dir and push the new root.
- **Apply the new certificate before pushing the new root** (README step 3,
  then step 4). Otherwise nodes reject the cluster's old certificate in
  between.
- **Expect some hosts to fail that used to pass.** Those are real problems
  the old checks didn't catch. Exit code 2 means look at the failed hosts.
- **Remove old roots by fingerprint** (`CA_Pusher.sh --remove
  --remove-sha256 <hex>`). Root names now include a timestamp, so don't match
  on the name.
