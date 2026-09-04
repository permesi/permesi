# Security Policy

## Supported versions

Permesi is under active development and has not reached a stable release. We do
not currently maintain supported release lines or backport security fixes to
older tags. Security fixes are made on the default branch and may be included in
later development releases without compatibility guarantees.

Please confirm that a suspected vulnerability is still present in the latest
default-branch revision before reporting it. This policy will be updated with a
version support matrix when the project establishes stable release lines.

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected security
vulnerability. Report it privately by emailing
[nbari@tequila.io](mailto:nbari@tequila.io).

Include enough information to reproduce and assess the issue, where possible:

- The affected component and commit or tag.
- The expected and observed behavior, potential impact, and attack conditions.
- Minimal reproduction steps or a proof of concept.
- Relevant configuration and logs with credentials, tokens, personal data, and
  other secrets removed.
- Any mitigation or remediation you have already identified.

Do not include live credentials or data belonging to other people. If sensitive
material is essential to the report, first ask by email for a suitable encrypted
channel.

We aim to acknowledge reports within three business days. After validation, we
will coordinate remediation and disclosure timing with the reporter. Fix timing
depends on severity, complexity, and the project's development state, so these
targets are not guarantees. Please allow time for a fix to be prepared and
distributed before publishing details.

Good-faith research should avoid privacy violations, data destruction, service
disruption, social engineering, and accessing more data than is necessary to
demonstrate the issue. Stop testing and report immediately if you encounter
sensitive data or cause service instability.

## Deployment security boundary

Permesi applies PostgreSQL-backed authentication limits across replicas and
validates forwarded IP values before using them. The service cannot prove that
`CF-Connecting-IP`, `X-Forwarded-For`, or `X-Real-IP` was written by a trusted
proxy, so production deployments must prevent direct public access to Permesi,
strip inbound copies of those headers, and set the canonical client address at
the last trusted proxy hop. This is required for per-IP limits to be reliable;
per-account limits remain independent of those headers.
