# Security Policy

## Supported Versions

The following versions of Reversecore MCP currently receive security updates:

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | ✅ Active support  |
| 2.x.x   | ⚠️ Critical fixes only |
| < 2.0   | ❌ End of life     |

## Reporting a Vulnerability

We take security vulnerabilities seriously. **Please do not report security
vulnerabilities through public GitHub issues.**

### How to Report

**Option 1 — GitHub Private Vulnerability Reporting (preferred)**

Use [GitHub's private vulnerability reporting](https://github.com/sjkim1127/Reversecore_MCP/security/advisories/new)
to submit a security advisory directly to the maintainers. This keeps the
details private until a fix is released.

**Option 2 — Email**

Send a detailed report to the maintainer via GitHub. Navigate to
[sjkim1127's profile](https://github.com/sjkim1127) and use the contact
information available there.

### What to Include

Please include as much of the following information as possible to help us
understand and reproduce the issue:

- Type of vulnerability (e.g., path traversal, command injection, SSRF)
- Full paths of source files related to the issue
- Location of the affected source code (tag, branch, commit, or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment — what an attacker could achieve

### Response Timeline

| Milestone | Target |
|-----------|--------|
| Initial acknowledgement | Within **48 hours** |
| Severity assessment | Within **5 business days** |
| Fix or mitigation plan | Within **30 days** for critical/high |
| Public disclosure | Coordinated with reporter |

We follow [coordinated vulnerability disclosure (CVD)](https://vuls.cert.org/confluence/display/CVD/Executive+Summary)
practices. We will credit researchers in release notes unless anonymity is
requested.

## Security Considerations for Deployment

Reversecore MCP executes binary analysis tools (Radare2, YARA, angr) on
potentially malicious input. Before deploying:

- **Run inside Docker** — use the provided `docker-compose.yml` with
  resource limits
- **Restrict workspace paths** — set `REVERSECORE_WORKSPACE` to an isolated
  directory
- **Limit tool access** — the MCP server runs with the privileges of the
  host process; use a dedicated low-privilege user
- **Validate all file paths** — the server enforces path validation, but
  defence-in-depth is recommended
- **Network isolation** — the MCP server does not require outbound internet
  access during analysis; consider blocking it at the firewall level

## Scope

The following are **in scope** for vulnerability reports:

- Path traversal or workspace escape via `file_path` parameters
- Command injection through tool arguments
- Denial of service via resource exhaustion (CPU/memory/disk)
- Arbitrary code execution via malformed binary files
- Authentication/authorization bypass (if applicable)

The following are **out of scope**:

- Vulnerabilities in Radare2, YARA, angr, or other third-party tools
  themselves (report those upstream)
- Issues requiring physical access to the host
- Social engineering attacks

## Security Updates

Security fixes are released as patch versions (e.g., `3.0.x`). Subscribe to
[GitHub releases](https://github.com/sjkim1127/Reversecore_MCP/releases) to
be notified of updates.
