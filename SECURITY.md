# Security policy for VELUM//TEGRA development

This is a **public source repository**. It is not an authorization to operate anyone's production or test servers.

- Never add credentials, private keys, signing identities, database copies, host-specific SSH config, production domains/IPs or operator logs to source control.
- Tests requiring a real VPS, real SSH, device provisioning, certificate publication, deployment or backup creation are **out of scope** for unattended CI and automation. The `tools/live-*` scripts act on a real target only when the operator supplies it explicitly (for example `VELUM_LIVE_HOST`, `VELUM_LIVE_PORT`, `VELUM_LIVE_SSH_KEY`, `ANDROID_SERIAL`); addresses inside them are RFC 5737 placeholders.
- A network-affecting or state-changing operation requires an explicitly authorized target, fresh read-only preflight, exact identity/pinning checks, user review and a verified postcondition.
- Store required secrets only in approved local credential stores or the explicitly configured secrets mechanism. Release signing comes only from `VELUM_RELEASE_*` environment variables. Do not put secrets in issues, PR descriptions or logs.
- Keep protected branches, mandatory review, and non-mutating CI checks. Do not allow auto-merge into `main`.
- Do not label simulated fixture acceptance as evidence for real-server restore/backup or production release readiness.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
"Report a vulnerability" (private security advisory) on this repository.
