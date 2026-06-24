# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub Security Advisories:
👉 [Report a vulnerability](https://github.com/niksecops-crypto/ebpf-shield/security/advisories/new)

Or email: **security@niksecops.dev**

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

## Security Considerations

- ebpf-shield requires `CAP_BPF` (or root on older kernels) — do not expose the binary to untrusted users
- IP blacklist rules in `shield.yaml` are loaded at startup; validate the config file's ownership and permissions (`chmod 600`)
- Running in a container requires `--privileged` or specific capabilities — review your threat model before deployment
- XDP programs run in kernel space; always verify BPF object integrity before loading
