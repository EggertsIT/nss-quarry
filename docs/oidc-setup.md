# OIDC Setup Guide (Microsoft Entra ID and Okta)

This guide configures `nss-quarry` SSO with role-based access control.

It is written for production-minded deployments where `nss-quarry` is behind HTTPS (reverse proxy or load balancer) and only internal users should access it.

## 1. How `nss-quarry` Uses OIDC

`nss-quarry` expects:
- an OIDC issuer (`auth.oidc.issuer_url`)
- client credentials (`client_id`, `client_secret`)
- redirect URL (`redirect_url`)
- one claim for username (`claim_username`)
- one claim containing role-mapping values (`claim_groups`)

At login callback, `nss-quarry` reads the ID token claims and maps `claim_groups` values to:
- `helpdesk`
- `analyst`
- `admin`

Mapping is configured in:
- `auth.oidc.role_map.helpdesk_groups`
- `auth.oidc.role_map.analyst_groups`
- `auth.oidc.role_map.admin_groups`

Important behavior:
- If no mapping matches, login is denied.
- `claim_groups` can be an array or comma-separated string.
- If you use HTTPS in front of the app, set `auth.secure_cookie = true`.

## 2. Production Prerequisites

Before IdP setup:

1. Choose the public URL users will access, for example:
- `https://nss-quarry.company.internal`

2. Keep app bind local/private:
- `server.bind_addr = "127.0.0.1:9191"` (or private subnet only)

3. Terminate TLS in reverse proxy / ingress.

4. Use callback URL matching your external URL:
- `https://nss-quarry.company.internal/auth/callback`

5. Use a strong cookie/session policy:
- `auth.secure_cookie = true`
- `auth.session_ttl_minutes = 30` or `60`

Tip: `install.sh` already applies HTTPS-first baseline (`bind_addr=127.0.0.1:9191`, `secure_cookie=true`) and generates Nginx config.

## 3. Config Template (OIDC Mode)

Use this as baseline in `config.toml`:

```toml
[auth]
mode = "oidc_entra" # or "oidc_okta"
cookie_name = "nssq_session"
session_ttl_minutes = 60
secure_cookie = true

[auth.oidc]
issuer_url = "REPLACE_ME"
client_id = "REPLACE_ME"
client_secret = "REPLACE_ME"
redirect_url = "https://nss-quarry.company.internal/auth/callback"
scopes = ["openid", "profile", "email"]
claim_username = "preferred_username"
claim_groups = "roles" # or "groups"

[auth.oidc.role_map]
helpdesk_groups = ["nss-helpdesk"]
analyst_groups = ["nss-analyst"]
admin_groups = ["nss-admin"]
```

## 4. Microsoft Entra ID Setup

## 4.1 Register App

1. Entra admin center -> App registrations -> New registration.
2. Name: `nss-quarry`.
3. Supported account types: single tenant (recommended).
4. Redirect URI:
- Platform: `Web`
- URI: `https://nss-quarry.company.internal/auth/callback`
5. Create app registration.

## 4.2 Create Client Secret

1. Certificates & secrets -> New client secret.
2. Copy secret value immediately.
3. Store in secret manager (not in Git).

## 4.3 Choose Role Claim Strategy

Recommended: **App Roles** (`claim_groups = "roles"`), because it is clean and avoids group overage issues.

Option A (recommended): App roles
1. In App registration -> App roles, create:
- `nss-helpdesk`
- `nss-analyst`
- `nss-admin`
2. In Enterprise applications -> `nss-quarry` -> Users and groups:
- Assign users/groups to these app roles.
3. In `config.toml`:
- `claim_groups = "roles"`
- `role_map.*_groups` values must match role values exactly.

Option B: Security groups claim (`claim_groups = "groups"`)
1. Create Entra groups with names/IDs representing roles.
2. Enterprise app -> Token configuration -> Add groups claim (ID token).
3. In `config.toml`:
- `claim_groups = "groups"`
- map to group names/IDs returned in token.

Note: if users are in many groups, Entra may not include full groups in token (overage behavior). `nss-quarry` currently does not call Graph to expand overage results. For large enterprises, prefer App Roles.

## 4.4 Set Issuer and Client Values

Use:
- `issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"`
- `client_id = <Application (client) ID>`
- `client_secret = <secret value>`
- `redirect_url = <exact callback URL>`

## 4.5 Username Claim

Recommended:
- `claim_username = "preferred_username"`

Fallbacks in code include `upn`, `email`, and `sub`.

## 5. Okta Setup

## 5.1 Create OIDC Web App

1. Okta Admin -> Applications -> Create App Integration.
2. Sign-in method: OIDC.
3. Application type: Web.
4. Redirect URI:
- `https://nss-quarry.company.internal/auth/callback`
5. Assign users/groups allowed to sign in.

## 5.2 Authorization Server and Claims

Use a custom authorization server (commonly `default`) for custom claims.

1. Security -> API -> Authorization Servers -> `default`.
2. Confirm issuer, usually:
- `https://<okta-domain>/oauth2/default`
3. Add claim for roles/groups:
- Name: `roles` (recommended) or `groups`
- Include in: ID Token
- Value type: Groups (filter regex like `^nss-`) or expression output.
4. If using groups scope, add `groups` scope and include it in app settings.

Recommended in `nss-quarry`:
- `claim_groups = "roles"` (or `groups` if that is the claim name you created)
- `role_map` values must match emitted claim values.

## 5.3 Set Issuer and Client Values

Set:
- `issuer_url = "https://<okta-domain>/oauth2/default"`
- `client_id = <Okta client id>`
- `client_secret = <Okta client secret>`
- `redirect_url = <exact callback URL>`
- `claim_username = "preferred_username"` (or `email` if that is your policy)

## 6. End-to-End Validation

1. Validate config:

```bash
cargo run -- validate-config --config ./config.toml
```

2. Start service:

```bash
cargo run -- run --config ./config.toml
```

3. Open login:
- `GET /auth/login`

4. Verify session:
- `GET /api/me`

5. Verify role enforcement:
- log in as each role and test `/api/search`, `/api/audit`.

## 7. Hardening Checklist

- Run behind HTTPS only; set `auth.secure_cookie = true`.
- Restrict inbound access to trusted internal networks.
- Do not expose `nss-quarry` directly to internet.
- Keep `client_secret` in vault/secret manager.
- Rotate OIDC secrets on a schedule.
- Keep `auth.mode = "local_users"` disabled in production unless explicitly required.
- Minimize admin assignments and enforce least privilege.
- Review audit log (`audit.path`) for auth failures and privileged access.

## 8. Troubleshooting

Login loops or callback failure:
- Check `redirect_url` exact match in IdP and config.

OIDC discovery failure:
- Check `issuer_url` and outbound connectivity from host.

User authenticated but denied by app:
- role mapping did not match `claim_groups`; inspect token claims and `auth.oidc.role_map`.

No username resolved:
- set `claim_username` to an emitted claim (`preferred_username`, `email`, etc).

Cookie not set in browser:
- if HTTPS is used, ensure `secure_cookie = true`;
- if plain HTTP is used for local lab only, use `secure_cookie = false`.
