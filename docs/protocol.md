# Protocol v1

`oidc-cli authenticate` accepts exactly one UTF-8 JSON object on stdin, at most
65,536 bytes including whitespace, followed by EOF. Unknown, duplicate,
case-mismatched, null, incorrectly typed fields, trailing objects and malformed
JSON are rejected. No configuration or token values are accepted in argv.
`oidc-cli version` requires no input and reports
`{"protocol_version":1,"ok":true,"version":"0.1.0-rc.1"}`.

One process = one attempt = one final newline-terminated stdout JSON object.
Object key order is not contractual. Consumers must check both `ok` and exit
status and reject unknown protocol versions. Optional response fields may be
added within v1; incompatible semantics require a new protocol version.
No token or credential cache is written to disk.

## Authentication configuration

| Field | Type | Default / constraint |
| --- | --- | --- |
| `protocol_version` | integer | Required, exactly `1` |
| `issuer` | string | Required, trusted exact discovery issuer, HTTPS, no credentials/query/fragment |
| `client_id` | string | Required public client, nonempty without surrounding whitespace |
| `scopes` | string array | `["openid"]`; must include `openid`; no whitespace/empty entries or `offline_access` |
| `listen_address` | string | `127.0.0.1:0`; numeric loopback IP only, numeric port 0–65535; `0` chooses an available exclusive port |
| `callback_path` | string | `/callback`; exact simple absolute path with letters, digits, `/`, `_`, `-`, `.`; no `//` or `/.` segments |
| `timeout_seconds` | integer | `180`; 1–900; `0` selects default |
| `http_timeout_seconds` | integer | `15`; 1–60 per HTTP request; `0` selects default |
| `open_browser` | boolean | `true`; false emits a sensitive authorization URL event on stderr instead of opening the browser |
| `allow_insecure_loopback_http` | boolean | `false`; explicitly permits HTTP issuer and provider endpoints **only for numeric loopback IPs**, for local testing |
| `include_tokens` | boolean | `false`; explicit sensitive output described below |
| `parent_pid` | integer | `0` disables process monitoring; otherwise accessible live PID 1–2147483647 |

Issuer and client registration are application-controlled trust configuration.
HTTPS endpoints retain normal OS CA verification. Discovery issuer matching is
exact, not a string-prefix trust rule. All advertised authorization, token and
JWKS endpoints must satisfy the transport policy. HTTP redirects for discovery,
token and JWKS requests are rejected (credentials are never forwarded);
environment proxy variables are not used. There is no insecure TLS switch.
Browser navigation itself is outside CLI transport control.

The overall deadline starts after input decoding/validation, covers discovery,
browser launch, callback, token exchange and JWKS verification, and is never
extended by incoming requests. The parent must close stdin promptly: input has a
size limit but no separate input deadline. SIGINT/SIGTERM cancellation is honored
even while waiting for EOF.

## Results and errors

```json
{"protocol_version":1,"ok":true,"identity":{"issuer":"https://id.example.com","subject":"opaque-subject"}}
```

Treat `(issuer, subject)` as the identity key. Do not substitute email, display
name or username. Profile fields are deliberately not returned by default.
Returned identity JSON is a local observation, not an authenticated assertion
to another process or server.

```json
{"protocol_version":1,"ok":false,"error":{"code":"token_invalid","message":"ID token verification failed"}}
```

| Exit status | Error codes |
| --- | --- |
| `0` | Success |
| `2` | `invalid_input` (including inaccessible parent PID) |
| `3` | `discovery_failed`, `listener_failed`, `browser_failed`, `oauth_error`, `token_exchange_failed`, `token_invalid` |
| `4` | `timeout` (overall deadline) |
| `5` | `cancelled` (signal or monitored process disappearance) |
| `10` | `internal_error`, or failure writing stdout |

Per-request HTTP timeouts before the overall deadline use the operation's error
code, not `timeout`. Error messages are sanitized constants, never provider
response bodies, authorization codes, tokens, error descriptions or private
filesystem details. No diagnostic logging is emitted during normal browser mode.
Output write failures cannot guarantee a complete final JSON object. Forced OS
termination/crashes likewise cannot guarantee protocol output.

## Headless browser injection and callback rules

With `open_browser:false`, stderr receives one newline-terminated event:

```json
{"protocol_version":1,"event":"authorization_required","authorization_url":"https://id.example.com/authorize?..."}
```

This URL contains state/nonce/PKCE challenge and can initiate the attempt. Treat
it as sensitive, do not log it persistently, and expose it only to the same user.
It contains no token values. No callback URL is a server-login proof.
The stdin/stdout protocol is unchanged; the CLI still waits on its listener.

The exact configured path, actual listener Host, GET method, exactly one matching
state and exactly one nonempty code or provider error are required. If present,
the response `iss` must match the configured issuer. Invalid state, malformed or
ambiguous queries, unrelated paths, wrong methods and wrong response issuers
receive HTTP errors **without consuming** the pending attempt. A structurally
valid matching response consumes the attempt once; a code exchange/verification
failure is final (no automatic retry). The browser response says only that the
response was received, not that verification succeeded.

The listener is exclusively bound before opening the browser, never to all
interfaces. Each attempt has 256-bit cryptographically random state, nonce and
PKCE verifier. The maintained `go-oidc` / `oauth2` libraries perform discovery,
code exchange, JWKS signature/issuer/audience/expiry validation and S256 PKCE.
Signing algorithms are restricted to RS256/384/512, PS256/384/512 and
ES256/384/512: no `none` or symmetric signing. Subject and exact nonce are
mandatory; `iat` must be positive, no later than expiry and no more than 60
seconds in the future; `nbf` if present allows at most 60 seconds of future
clock skew. Expiry is enforced by the verifier. Multiple audiences require
matching `azp`, and any supplied `azp` must match the client. If `at_hash` is
present it must match the access token.

## Explicit sensitive-token option

Only when `include_tokens:true`, success additionally includes:

```json
{"tokens":{"id_token":"<sensitive JWT>","access_token":"<sensitive bearer token>","token_type":"Bearer","expires_at":"2026-11-11T12:00:00Z"}}
```

This is a fragment of the same success response, not a second output line.
Refresh tokens are never returned or persisted even if the provider sends one.
`expires_at` is the access-token expiry supplied by the OAuth library; a missing
provider expiry becomes Go's zero time `0001-01-01T00:00:00Z`, **not** an unlimited
validity promise. Keep stdout in memory, do not log it or store it on disk, and
do not pass tokens in argv. Use a protected IPC boundary and TLS if forwarding.
No token output is needed for the default desktop identity use case.

An arbitrary signed ID token is **not transaction-bound server login proof**.
A future server integration needs its own threat model and explicit acceptance
protocol: server-controlled challenge/nonce, audience, issuer and replay policy,
expiry and authorized-party validation, and binding to the requesting session.
Do not treat an access token minted for another resource as authorization for
4D Server. The current CLI nonce is generated by the CLI, not a 4D Server.
This option alone does not implement such a server protocol.

## Signals and 4D worker lifetime

The wrapper owns process lifetime. Write JSON, close stdin, read stdout and stderr
independently, and never synchronously block the 4D UI thread. Cancel using
SIGINT/SIGTERM on Unix or the worker's supported termination API on Windows;
Windows force termination may produce no final JSON. Set a parent-side deadline
slightly beyond the configured CLI deadline and always reap the process.
Timeout/error paths close the listener and active HTTP requests.

`parent_pid` polls every 250 ms and cancels when the designated process exits.
On Unix it uses process-existence checks (PID reuse is a limitation); on Windows
it keeps a synchronization handle to that process. This is supplementary safety,
not an OS job object, an ownership/authentication check, or a substitute for
explicit worker termination. Without it, a surviving worker exits at its own
deadline after input closes, even if its owner exits. If the owner exits before
closing stdin, EOF normally ends the read; do not rely on that if another process
inherits a pipe handle. SIGKILL/process crashes cannot run cleanup; the OS closes
process-owned listener sockets. No unattended background service is installed.
