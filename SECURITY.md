# Security Policy

cybersecuritykit is **teaching software**, and everything in it is simulated:
toy ciphers with short keys and variable-time arithmetic, a toy virtual
machine for memory-safety bugs, synthetic network traffic, logs and power
traces, and epidemic models in place of malware. These are documented model
boundaries, not vulnerabilities. Never use cybersecuritykit to protect real
secrets, and never adapt it to act on systems you do not own.

## Scope rule for contributions

The package must never:

- open sockets, send or capture packets, resolve names, or scan hosts;
- contain working exploits, shellcode, or payloads for real software;
- contain code that replicates, persists, or evades detection;
- ship real personal data or real leaked credentials.

Simulated hosts use the reserved `.test` domain (RFC 2606) and the
documentation address blocks of RFC 5737. Pull requests that cross this line
are closed, whatever their teaching value.

## What counts as a vulnerability here

- A bug that makes an experiment teach something false, for example a
  detector whose reported false-positive rate is wrong, or a cipher whose
  attack succeeds for the wrong reason.
- Code execution or resource exhaustion from loading data the package claims
  to validate.
- Any code path that reaches the network or the file system outside a
  temporary directory.

Vulnerabilities in real software should be reported to those projects, not
here.

## Reporting a Vulnerability

Please **do not open a public GitHub issue**. Instead, use GitHub's private
vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.

If that's not available, open an issue asking a maintainer to contact you
privately, without describing the vulnerability itself.

## Supported Versions

Only the latest released version on PyPI is supported with fixes.
