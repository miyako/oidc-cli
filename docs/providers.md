# Provider setup

Use an OpenID Connect provider with discovery, Authorization Code flow, and PKCE
S256. Register a **public/native client**: no client secret belongs in this CLI.
Use the discovery issuer, not an authorization endpoint URL. Provider issuer
matching is exact, including any path. Production issuers must use HTTPS.

The callback is an HTTP loopback listener, by default `127.0.0.1` with an
OS-assigned port and `/callback`. A provider must accept the actual redirect URI,
including that port and path. Native-app providers commonly allow dynamic
loopback ports; others require a fixed registered port. For those providers,
register e.g. `http://127.0.0.1:42813/callback` and send
`"listen_address":"127.0.0.1:42813"`. Do not register a remote callback, a LAN
address, or a redirect wildcard on an Internet host.

## Disposable Keycloak

Requirements: Docker with a running daemon and Compose v2. These commands start
services only when explicitly run by the developer:

```sh
docker compose -f testdata/keycloak/compose.yaml up -d
curl --fail http://127.0.0.1:8080/realms/oidc-cli/.well-known/openid-configuration
```

Wait for discovery to become available. The pinned development image imports
`testdata/keycloak/realm.json` into a disposable server (no persistent
volume). The local admin credentials are `disposable-admin` /
`disposable-admin-password`. The public client is `oidc-cli`; its test user is
`test-user` / `test-password-not-for-production`. **These published credentials,
HTTP transport, and `start-dev` configuration are never for production.**
The host port binds only to `127.0.0.1`.

The realm registers the exact callback `http://127.0.0.1:42813/callback`.
The request and optional E2E script both set `listen_address` to
`127.0.0.1:42813`; keep that port free while testing. To change it, update the
realm registration and request together, recreate the fixture, and adjust the
E2E script's `CALLBACK` constant (its listener is derived from that URI).

The general CLI supports OS-assigned callback ports, but accepting them depends
on provider registration and matching rules. Keycloak dynamic-port/wildcard
matching is **unverified by a real E2E run here** and is deliberately not used by
this fixture. Do not work around redirect rejection by allowing arbitrary
remote redirects.

```sh
printf '%s\n' '{"protocol_version":1,"issuer":"http://127.0.0.1:8080/realms/oidc-cli","client_id":"oidc-cli","listen_address":"127.0.0.1:42813","scopes":["openid","profile","email"],"allow_insecure_loopback_http":true}' \
  | go run ./cmd/oidc-cli authenticate
```

`allow_insecure_loopback_http` opts into this local HTTP issuer; it does not
permit non-loopback HTTP issuers. Browser-disabled automation sets
`open_browser:false` and consumes the authorization URL event on **stderr**;
stdout remains the single result JSON object. Treat the URL as sensitive
ephemeral state and do not retain it in CI logs. Tokens are omitted unless
`include_tokens:true` is explicitly requested. There is no refresh-token
persistence.

For an optional bounded real-provider check (Python 3 standard library only):

```sh
go build -o build/oidc-cli ./cmd/oidc-cli
python3 scripts/keycloak_e2e.py --binary build/oidc-cli
```

This submits the published test credentials to the local Keycloak login form,
using the core's `authorization_required` event and `authorization_url` field,
follows only the fixture and fixed loopback callback origins, and checks the
verified identity and requested tokens without printing them. It uses a 60-second
authentication timeout and bounded network/process waits. It does not replace
interactive browser testing or claim support for MFA/custom login themes. The
manual-only **Optional Keycloak E2E** workflow runs the same check and tears down
the fixture even on failure. Ordinary source CI does not start Keycloak.

Stop and reset the fixture before repeat imports or after use:

```sh
docker compose -f testdata/keycloak/compose.yaml down --volumes --remove-orphans
```

Realm import does not overwrite an existing realm in a running server. Recreate
the disposable container after changing `realm.json`.

## Later acceptance: Microsoft Entra ID

Entra is a future compatibility target, **not a verified provider for this RC**.
No customer tenant or human MFA session was available. A later acceptance run
must register a public/native desktop application in a controlled tenant, use its
tenant-specific v2 discovery issuer and public client ID, and verify that the
registered loopback IP, path and dynamic/fixed port rules match the actual
authorization request. Do not assume Keycloak registration rules transfer.

Acceptance must cover interactive consent/MFA, cancellation and tenant policy,
the exact returned issuer/audience/authorized party, fresh nonce, expiry and
multiple-user identity separation. Record the tenant/account types and redirect
registration actually tested without logging tokens. Do not weaken issuer,
signature, audience or nonce checks to accommodate a failed test. Any future
4D Server login still requires a separate server-controlled, transaction-bound
acceptance protocol; desktop identity JSON or opt-in token output alone does
not implement one.
