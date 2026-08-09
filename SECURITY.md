# Security policy

## Supported versions

Security fixes are provided for the latest published release. Until `1.0.0`, minor releases may include necessary hardening changes to provider adapters or defaults.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** private reporting form in the repository Security tab. Do not open a public issue for suspected vulnerabilities and do not include production credentials, message contents, phone numbers, or personal data in a report.

Include, when possible:

- affected version and provider adapter;
- a minimal reproduction using dummy secrets and synthetic payloads;
- security impact and required preconditions;
- suggested remediation, if known.

You should receive an acknowledgement within 7 days. Valid reports will be investigated, fixed, tested, and credited when the reporter wants attribution. Timelines depend on severity and whether coordination with an SMS provider is required.

## Scope

In scope:

- signature bypass or canonicalization flaws;
- timestamp or replay-protection bypass;
- unsafe secret exposure;
- redaction failure with a clear supported pattern;
- CLI behavior that could test a remote target without explicit authorization;
- release or dependency-chain compromise.

Provider outages, vulnerabilities in third-party provider infrastructure, social engineering, and testing endpoints you do not own are out of scope.

## Safe harbor

Good-faith research must use systems and data you own or have explicit permission to test, minimize access, avoid privacy violations and service disruption, and allow a reasonable remediation period before disclosure.
