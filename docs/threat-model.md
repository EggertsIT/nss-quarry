# nss-quarry Threat Model

Updated: April 4, 2026

## Scope and Assets

In scope:
- `nss-quarry` application (`axum` service on `127.0.0.1:9191`)
- Nginx reverse proxy (`https://<host>/...`)
- local auth session state and cookies
- audit log files under `/var/lib/nss-quarry/`
- NSS Parquet data under `data.parquet_root` (typically `/var/lib/nss-ingestor/data`)

Primary assets:
- confidentiality of user/IP/device fields in logs
- integrity of query and audit results
- availability of search/export and dashboards
- integrity of authn/authz decisions

Out of scope:
- upstream IdP tenant hardening (Okta/Entra configuration details)
- host/network controls outside this node

## Trust Boundaries

1. Browser/User -> Nginx (TLS boundary)
2. Nginx -> `nss-quarry` app on loopback
3. `nss-quarry` -> Parquet files (filesystem ACL boundary)
4. `nss-quarry` -> audit log files (filesystem ACL boundary)
5. `nss-quarry` -> OIDC provider over HTTPS (external trust boundary)

## Data Flow Summary

1. User authenticates (`local_users` or OIDC via callback).
2. Session cookie is issued (`HttpOnly`, `SameSite=Lax`, `Secure` in production).
3. Authenticated API calls execute guarded routes:
   - `helpdesk+`: `/api/search`, `/api/export/csv`, `/api/dashboards/*`, `/api/schema`
   - `admin`: `/api/audit*`, `/authz/ingestor`, `/api/admin/ingestor/force-finalize-open-files`
4. Queries run in DuckDB against Parquet partitions.
5. Security-relevant actions are appended to audit logs.

## Threats and Mitigations

## T1: Unauthorized data access (broken authz)
- Risk: non-admin users reaching admin endpoints or unauthed access to query APIs.
- Mitigations:
  - centralized `require_user(.., min_role)` enforcement in handlers
  - explicit admin gate for `/authz/ingestor`, `/api/audit*`, and ingestor force-finalize control API
  - security tests covering unauthenticated/role-mismatched access

## T2: Session theft/misuse
- Risk: stolen cookies used for impersonation.
- Mitigations:
  - `HttpOnly` and `SameSite=Lax` cookies
  - production install defaults to HTTPS and `secure_cookie = true`
  - bounded `session_ttl_minutes`
  - logout invalidates in-memory session and clears cookie

## T3: Injection via search filters
- Risk: SQL injection into DuckDB query generation.
- Mitigations:
  - strict field identifier validation (`[A-Za-z_][A-Za-z0-9_]*`)
  - constrained filter value regex and escaping
  - bounded query time windows and row limits

## T4: Excessive data exposure to helpdesk
- Risk: sensitive fields broadly visible.
- Mitigations:
  - role-based masking for `helpdesk` (`security.helpdesk_mask_fields`)
  - narrow default columns and controlled export paths

## T5: Audit tampering or loss
- Risk: missing or altered forensic trail.
- Mitigations:
  - append-only JSONL style logging by service user
  - optional rotation + retention controls
  - admin-only read/export APIs for audit trail
  - recommend filesystem ACL hardening for audit path

## T6: Dependency supply-chain risk
- Risk: vulnerable transitive crates in auth stack.
- Mitigations:
  - CI-enforced `cargo audit` with explicit allowlist ownership
  - CI-enforced `cargo deny` advisories check
  - periodic review and removal of allowlist exceptions

## Residual Risks

- In-memory session store is cleared on restart (operational tradeoff).
- OIDC transitive advisories remain open until upstream fixed versions are available.
- Local-user mode is suitable for small/trusted environments; enterprise should prefer OIDC + HTTPS.

## Verification and Review Cadence

- Per PR/release:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `./scripts/run_audit.sh`
  - `cargo deny --config deny.toml check advisories`
- Monthly:
  - reevaluate `audit-allowlist.txt` and `deny.toml` ignore entries
  - refresh pentest evidence and update `pentest.md`
