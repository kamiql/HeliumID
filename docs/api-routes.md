# HeliumID HTTP routes

Generated from the Ktor routing tree by `RouteInventoryTest`. Do not edit by hand:
regenerate with

```sh
cd backend && ./gradlew :api-http:test --tests '*RouteInventoryTest*' -Dhelium.routes.write=true
```

`:app:integrationTest` additionally fails if any route below is not exercised by an
end-to-end test — see `docs/testing.md`.

## OAuth 2.0 / OpenID Connect

| Method | Path |
| --- | --- |
| `GET` | `/.well-known/jwks.json` |
| `GET` | `/.well-known/openid-configuration` |
| `GET` | `/oauth2/authorize` |
| `POST` | `/oauth2/introspect` |
| `POST` | `/oauth2/revoke` |
| `POST` | `/oauth2/token` |
| `GET` | `/userinfo` |

## Operational

| Method | Path |
| --- | --- |
| `GET` | `/health` |
| `GET` | `/health/ready` |
| `GET` | `/metrics` |

## Administration (`/v1/admin`)

| Method | Path |
| --- | --- |
| `GET` | `/v1/admin/audit` |
| `GET` | `/v1/admin/clients` |
| `POST` | `/v1/admin/clients` |
| `DELETE` | `/v1/admin/clients/{clientId}` |
| `GET` | `/v1/admin/clients/{clientId}` |
| `PATCH` | `/v1/admin/clients/{clientId}` |
| `POST` | `/v1/admin/clients/{clientId}/rotate-secret` |
| `GET` | `/v1/admin/permissions` |
| `GET` | `/v1/admin/roles` |
| `DELETE` | `/v1/admin/roles/{name}` |
| `PUT` | `/v1/admin/roles/{name}` |
| `GET` | `/v1/admin/scopes` |
| `DELETE` | `/v1/admin/scopes/{name}` |
| `PUT` | `/v1/admin/scopes/{name}` |
| `GET` | `/v1/admin/users` |
| `GET` | `/v1/admin/users/{userId}` |
| `POST` | `/v1/admin/users/{userId}/revoke-sessions` |
| `PUT` | `/v1/admin/users/{userId}/roles` |
| `GET` | `/v1/admin/users/{userId}/sessions` |
| `PUT` | `/v1/admin/users/{userId}/status` |

## Authentication (`/v1/auth`)

| Method | Path |
| --- | --- |
| `POST` | `/v1/auth/email/resend` |
| `POST` | `/v1/auth/email/verify` |
| `POST` | `/v1/auth/login` |
| `POST` | `/v1/auth/logout` |
| `POST` | `/v1/auth/mfa/challenge` |
| `POST` | `/v1/auth/mfa/verify` |
| `GET` | `/v1/auth/password-requirements` |
| `POST` | `/v1/auth/password-reset/complete` |
| `POST` | `/v1/auth/password-reset/request` |
| `GET` | `/v1/auth/providers` |
| `GET` | `/v1/auth/providers/{provider}/callback` |
| `GET` | `/v1/auth/providers/{provider}/start` |
| `POST` | `/v1/auth/reauthenticate` |
| `POST` | `/v1/auth/reauthenticate/mfa` |
| `POST` | `/v1/auth/register` |
| `GET` | `/v1/auth/session` |

## Account (`/v1/me`)

| Method | Path |
| --- | --- |
| `GET` | `/v1/me` |
| `PUT` | `/v1/me` |
| `GET` | `/v1/me/authorizations` |
| `DELETE` | `/v1/me/authorizations/{clientId}` |
| `POST` | `/v1/me/delete` |
| `POST` | `/v1/me/email-change` |
| `POST` | `/v1/me/email-change/confirm` |
| `GET` | `/v1/me/mfa` |
| `POST` | `/v1/me/mfa/recovery-codes` |
| `POST` | `/v1/me/mfa/totp/confirm` |
| `POST` | `/v1/me/mfa/totp/disable` |
| `POST` | `/v1/me/mfa/totp/enroll` |
| `POST` | `/v1/me/mfa/webauthn/confirm` |
| `POST` | `/v1/me/mfa/webauthn/enroll` |
| `POST` | `/v1/me/mfa/webauthn/remove` |
| `PUT` | `/v1/me/password` |
| `GET` | `/v1/me/providers` |
| `DELETE` | `/v1/me/providers/{provider}` |
| `GET` | `/v1/me/sessions` |
| `DELETE` | `/v1/me/sessions/{sessionId}` |
| `DELETE` | `/v1/me/trusted-devices` |
| `GET` | `/v1/me/trusted-devices` |
| `DELETE` | `/v1/me/trusted-devices/{id}` |

Total: 69 routes.
