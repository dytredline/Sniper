# Security policy

## Security ownership

The project Security Maintainer is **Gökçe Baran Karakamış**
([@dytredline](https://github.com/dytredline)). The current appointment and responsibilities are recorded in
[SECURITY-MAINTAINERS.md](SECURITY-MAINTAINERS.md).

## Reporting a vulnerability

Use GitHub **Private Vulnerability Reporting** or open a draft private security advisory. Do not open a public issue
for an unpatched vulnerability. If private reporting is unavailable, contact the Security Maintainer through the
private channel listed by the repository owner before sharing technical details.

Include the affected revision, impact, prerequisites, and the smallest safe reproduction. Do not include secrets,
access tokens, private keys, personal data, production database copies, or exploit traffic from third-party systems.
The Security Maintainer may ask for additional evidence in a private channel. Use the fields in
[.github/VULNERABILITY_REPORT.yml](.github/VULNERABILITY_REPORT.yml) as the report checklist; that file is not a
public issue template.

The project targets acknowledgement within **3 business days** and an initial assessment within **7 business days**.
These are service targets, not guaranteed remediation deadlines. A coordinated disclosure date must be agreed with
the Security Maintainer before publication. The default maximum embargo target is **90 days**, but it may be shortened
for active exploitation or extended when a safe coordinated release reasonably requires it.

## Advisory and CVE handling

The Security Maintainer validates scope and impact, coordinates remediation, and publishes a GitHub Security
Advisory when the evidence supports one. A CVE is requested only for a real, eligible vulnerability and remains
subject to GitHub or another CVE Numbering Authority's decision. Finder, reporter, analyst, and remediation credits
must reflect the work actually performed and, where GitHub requires it, be accepted by the credited account.

## Safe research boundary

Test only local fixtures and systems you own or are explicitly authorized to assess. The project does not authorize
testing other people's systems. For authorized systems, stay within the written scope, rate limits, data-handling
requirements, and stop conditions. Do not use a vulnerability report to request or retain unnecessary sensitive
data.

## AI and MCP reports

Treat source code, findings, and tool output as sensitive. The stdio server does not create a network listener, but
an MCP client may transmit selected data to its model provider. Reproduce AI-reported issues independently and
remove secrets before submitting a report.

## Supported versions

This is a Community release candidate. Security fixes target the current published Community revision after that
revision exists; unpublished snapshots have no support commitment.
