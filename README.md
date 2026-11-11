# oidc-cli

Standalone Go OpenID Connect authentication CLI for desktop applications, including
asynchronous invocation by a separately maintained 4D wrapper using
`4D.SystemWorker`. No NetKit, native 4D plugin, or wrapper source is required.

**Protocol version 1.** The [source version](cmd/oidc-cli/version.txt) is embedded
in local builds. Uses discovery,
Authorization Code + PKCE S256, state, nonce, an exclusive numeric-loopback HTTP
listener and the external system browser. The default result is only the verified
`issuer` + `subject` identity pair. It is **not server-login proof** and does not
replace native 4D Client/Server authentication.

## Build and authenticate

Go 1.26 or newer (the module pins the Go 1.26.10 toolchain):

```sh
go build -o oidc-cli ./cmd/oidc-cli
./oidc-cli version
printf '%s\n' '{"protocol_version":1,"issuer":"https://id.example.com/realms/example","client_id":"desktop"}' |
  ./oidc-cli authenticate
```

Configure a trusted issuer and public client registration first. The CLI starts
its listener before launching the browser. The default callback is
`http://127.0.0.1:<OS-assigned-port>/callback`; your provider must support that
registration pattern, or configure a registered fixed loopback port. Browser
SSO/MFA occurs in the provider UI, not inside 4D.

Success (one UTF-8 JSON object, newline terminated):

```json
{"protocol_version":1,"ok":true,"identity":{"issuer":"https://id.example.com/realms/example","subject":"opaque-subject"}}
```

Failure has `ok:false`, an `error` object, and a nonzero process exit status.
Stdout is exclusively protocol output. Configuration is read from stdin to EOF;
never put tokens or credentials in command arguments. One invocation performs
one authentication attempt and exits without storing credentials.

## Integration and limits

See the [versioned protocol and lifecycle contract](docs/protocol.md), including
exit codes, cancellation, process parenting and the explicit sensitive-token
option. The future wrapper must keep its worker asynchronous, close stdin, parse
stdout separately from stderr, enforce its own deadline, and terminate the worker
when the owning application/task ends.

See [provider registration and disposable Keycloak setup](docs/providers.md) and
[release assets, checksums and pinned downloads](docs/releases.md).
Maintainers can use **Actions → Bump version → Run workflow** on `main` to bump,
tag, build and publish a release.
The Keycloak fixtures are test-only; no production credentials are shipped.
Entra tenant/MFA acceptance and actual 4D host integration are later compatibility
work, not established support.

No client secret, persistent credential cache, refresh-token output or persistence,
automatic retry, userinfo request, token refresh, or provider-wide logout is in
this release. Successful browser login may leave an existing provider browser
session active. Restrict trusted issuer configuration in the embedding application;
do not accept issuer/client IDs supplied by an untrusted login claimant.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests use a local mock issuer and real RSA signatures/JWKS, with injected browser
navigation. They do not imply real-provider, Windows-runtime, MFA, customer-tenant
or 4D acceptance. Release binaries are unsigned and not notarized; distribution
policy and OS trust prompts remain the consumer's responsibility.
