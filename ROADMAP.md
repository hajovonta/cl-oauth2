# Roadmap

## v0.2.0

- [ ] ES256 (ECDSA P-256) signature verification in `verify-jwt`
- [ ] Token caching/storage layer (in-memory + optional file-backed)
- [ ] Auto-refresh: wrap API calls to transparently refresh expired tokens
- [ ] `introspect-token` — RFC 7662 token introspection endpoint support
- [ ] `revoke-token` — RFC 7009 token revocation

## v0.3.0

- [ ] Full test coverage for `exchange-code`, `client-credentials-grant`, `poll-device-token` (mock HTTP layer)
- [ ] HS256 (HMAC) signature verification
- [ ] JWK thumbprint calculation (RFC 7638)
- [ ] Token response hooks (for logging, metrics)
- [ ] Configurable clock skew tolerance for JWT expiration

## Future

- [ ] Authorization server implementation (issue tokens, not just consume)
- [ ] PKCE for device flow (RFC 9449)
- [ ] DPoP (Demonstrating Proof of Possession) support
- [ ] PAR (Pushed Authorization Requests, RFC 9126)
- [ ] CIBA (Client-Initiated Backchannel Authentication)
- [ ] Integration examples: Hunchentoot middleware, cl-mastodon auth
