# Security policy

## Reporting a vulnerability

Email **security@voidwire.app**. Please do not open a public issue, pull
request or discussion for a security problem.

Include what you found, the version (the release tag or the version shown in the app),
the platform, and the steps to reproduce. A proof of concept helps but is not
required. Do not send real links, files or pairing QR codes from your own
devices; test data is enough.

What happens next:

- We aim to confirm we got the report within 7 days.
- We keep you updated while we work on a fix, and agree a disclosure date
  with you. The default is 90 days after the report, sooner once a fix ships.
- Fixed issues are listed in the release notes. We credit you there unless
  you ask us not to.

This is a small open-source project run on a best-effort basis. There is
**no bug bounty** and no payment for reports.

## Scope

In scope:

- The Voidwire apps: Windows, Linux, Android and the browser extension.
- The core library and the protocol (pairing, envelope, pairing links,
  file transfer); see [docs/PROTOCOL.md](docs/PROTOCOL.md).
- The self-host relay and mailbox (`voidwire-mailbox`), the Docker relay
  bundle and the shipped configuration templates.
- The update channel: manifests, signatures and the in-app updater
  ([docs/UPDATES.md](docs/UPDATES.md)).
- The release pipeline in this repository (the GitHub Actions workflows and
  the scripts they run) and the published release files.
- The voidwire.app website.

Out of scope:

- Risks already documented and accepted in
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) (for example DNS rebinding,
  private-network hosts, metadata visible to the relay), unless you find a way
  past the stated mitigation.
- Attacks that need malware already running as the same user, a rooted or
  jailbroken phone, or physical access to an unlocked device.
- Relays or mailboxes run by third parties, and misconfiguration of a
  self-hosted relay that the docs warn against.
- Denial of service by flooding a relay, spam, and social engineering.
- Findings from automated scanners without a demonstrated impact, missing
  security headers with no exploit, and the unsigned Windows installer
  warning (SmartScreen) that is already documented.
- Vulnerabilities in dependencies that do not affect Voidwire; report those
  upstream.

## Safe harbor

Good-faith research that follows this policy is welcome. Only test against
your own devices, accounts and relays. Do not access other people's data,
degrade the public relay for other users, or keep data you come across.

## Audit status

Voidwire has not been independently audited yet. An outside review of the
cryptography is planned when resources allow. The design and its known
limits are in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
