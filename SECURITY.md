# Security Policy

## Reporting a Vulnerability

Report vulnerabilities privately to your internal security contact or repository maintainers.
Do not create public issues for active security weaknesses.

Include:
- affected version/commit
- impact and realistic attack path
- reproduction steps or proof-of-concept
- proposed mitigation/fix (if available)

## Security Baseline

- Run `nss-quarry` as unprivileged `nssquarry` user.
- Keep app server bound to localhost (`127.0.0.1:9191`) behind authenticated reverse proxy.
- Keep HTTPS enabled and `auth.secure_cookie = true` in production.
- Keep `security.max_query_window_hours` constrained (default: 168h / 7d).
- Keep audit logging enabled and protect audit files via filesystem permissions.
- Trust `X-Forwarded-For` / `X-Real-IP` only from a loopback reverse proxy on the same host.
- PCAP uploads are staged in an app-owned private temp directory; keep that directory on local trusted storage.
- Restrict ingestor dashboard passthrough (`/ingestor/*`) to admin-only users.

## Current Assessment

See [pentest.md](./pentest.md) for the latest internal penetration test summary and residual risks.
See [docs/threat-model.md](./docs/threat-model.md) for trust boundaries, threat scenarios, and mapped controls.

## Dependency Audit Allowlist Policy

`cargo audit` is enforced in CI with warnings denied.
`cargo deny` advisories checks are also enforced in CI via [`deny.toml`](./deny.toml).

Temporary exceptions are managed in [`audit-allowlist.txt`](./audit-allowlist.txt) and must include:
- reason and business context,
- owner responsible for tracking,
- scheduled reassessment and removal target.

Current temporary exceptions:
- `RUSTSEC-2023-0071` (`rsa`, transitive via `openidconnect`)  
  Owner: platform engineering. Status: no fixed upgrade available in current chain.

## Release Artifact Verification

Verify release binaries before deployment.

1. Download release assets from the tag (example: `v0.1.0`):
   - `nss-quarry-linux-x86_64`
   - `checksums.txt`
   - `checksums.txt.sig`
   - `checksums.txt.pem`
   - `sbom.cdx.json`
2. Validate SHA-256 checksum:

```bash
mkdir -p dist
cp nss-quarry-linux-x86_64 dist/nss-quarry-linux-x86_64
sha256sum -c checksums.txt
```

3. Verify keyless signature provenance (requires `cosign`):

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/.+/.+/.github/workflows/release-artifacts.yml@refs/tags/.+" \
  checksums.txt
```

4. Optionally validate SBOM structure:

```bash
jq -r '.bomFormat, .specVersion, (.components | length)' sbom.cdx.json
```
