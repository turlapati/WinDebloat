# Security Policy

## Supported versions

Please report vulnerabilities against the latest commit on `main` and any tagged `v*` release.

## Reporting a vulnerability

Do not open a public GitHub issue for security reports.

Email a private report to the maintainer listed in this repository's profile (Hari Turlapati) and include:

- A description of the issue and its impact
- Affected binary (`windebloat.exe`, `windebloat-daemon.exe`, or `windebloat-cli.exe`)
- Steps to reproduce, or a proof of concept that does not include exploit-ready payloads
- Your preferred contact for coordinated disclosure

You should receive an acknowledgement within 7 days. Please allow time for a fix and a signed release before public discussion.

## Hardening notes

- Install under `%ProgramFiles%\WinDebloat`. The elevated daemon accepts **unsigned** community-build peers only from that directory (admin-writable only). Portable zip layouts run from Downloads or other user-writable folders are rejected.
- Invalid, untrusted, tampered, or foreign-signed binaries are always rejected, even in community builds.
- After a code-signing certificate is available, production builds enable the `require-signed-peers` Cargo feature and pin the publisher CN. See [docs/RELEASING.md](docs/RELEASING.md).
- Custom manifests executed by the elevated daemon or the headless CLI must be signed by a key in `HKLM\SOFTWARE\Policies\WinDebloat\TrustedKeys`.
- The `--dev-no-verify` daemon flag exists only in debug builds.
