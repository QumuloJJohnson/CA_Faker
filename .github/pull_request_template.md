<!--
Write this for a person, the way you'd explain the change to a teammate:
short sentences, plain words, no marketing language, no filler. Bullets for
lists, not for every sentence. If a section doesn't apply, write "None".
-->

## Summary

<!--
What this PR does and why, in a few plain sentences. Someone who has not
read the diff must be able to follow it. Link the issue if there is one.
-->

Issue: #

## What was broken or missing

<!--
The concrete problem, as a lab user would see it (for example: "a browser
still warns when the cluster is opened by IP"). Write "nothing — new
feature" if that is the case.
-->

## What this PR changes

<!--
One sentence per change, saying what the scripts do now. Name the script
(CA_Faker.sh, CA_Pusher.sh, CA_Lab.sh, README.md, CHANGELOG.md).
-->

## User-facing changes

<!--
Anything a current user of the scripts will notice: new or changed flags,
output files, messages, exit codes, README step order. Say whether today's
commands still work the same way. Write "None" if there are none.
-->

- [ ] `CHANGELOG.md` updated (and "Upgrading from the old scripts" if existing users must act)
- [ ] Every new or changed flag is in the script's `--help` and in the README tables

## How it was tested

<!--
List what you ran and what you checked by hand. Say what you did NOT test.
-->

- [ ] `bash tests/run_tests.sh` passes (paste the `Passed/Skipped/Failed` lines)
- [ ] `shellcheck -S error` is clean on the changed scripts
- [ ] Target distros exercised, if CA_Pusher/CA_Lab changed: Ubuntu/Debian, Rocky/RHEL (SELinux enforcing), nspawn container
- [ ] Against a real Qumulo cluster, if the cert or `qq` steps changed
- [ ] Not tested:

## Security and cleanup

<!--
This is a lab tool, but it installs a trusted root and touches remote hosts.
-->

- [ ] No password, key or secret reaches a command line, a log or the repo
- [ ] Anything the change installs on a host can be removed again (README "Cleaning up after the lab")

## Notes for the reviewer

<!-- Anything that deserves extra attention, or decisions you want checked. -->
