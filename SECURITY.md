# Security Policy

## Supported Versions

Sentinel is pre-1.0 (`0.x.x`); the latest release on `main` receives
security fixes. There is no long-term-support branch yet.

## Reporting a Vulnerability

Email **security@nbr.company** with details and reproduction steps.
Do NOT open a public issue. Expect acknowledgement within 72 hours and a
remediation timeline within 7 days.

Please include:

- The affected version/commit.
- Whether the issue is in Sentinel's own code (e.g. memory safety, a
  parsing bug, credential handling) vs. in a third-party crate or the
  optional Kali Docker image it can pull.
- Steps to reproduce, or a PoC if one exists.

## Disclosure

Coordinated disclosure. We credit reporters unless anonymity is requested.

## Responsible use (not a vulnerability report)

Sentinel is a security assessment tool for scanning systems you own or are
explicitly authorized to test — see the README's Disclaimer. Reports about
Sentinel being *used* against unauthorized targets are not a Sentinel
vulnerability and are not handled through this policy; the maintainer
assumes no liability for misuse, per the README's Disclaimer.
