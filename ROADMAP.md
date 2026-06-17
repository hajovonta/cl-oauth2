# Roadmap

## v0.2.0 ✅

- [x] ES256 (ECDSA P-256) signature verification in `verify-jwt`
- [x] Token caching/storage layer (in-memory with max-entries eviction)
- [x] Auto-refresh: `with-token` wraps API calls with automatic token management
- [x] `introspect-token` — RFC 7662 token introspection endpoint support
- [x] `revoke-token` — RFC 7009 token revocation

## v0.3.0 ✅

- [x] HS256 (HMAC) signature verification
- [x] JWK thumbprint calculation (RFC 7638)
- [x] Token response hooks (`on-token-response` generic function)
- [x] Configurable clock skew tolerance for JWT expiration
- [ ] Full test coverage for `exchange-code`, `client-credentials-grant`, `poll-device-token` (mock HTTP layer)

## Future

- [ ] Authorization server implementation (issue tokens, not just consume)
- [ ] PKCE for device flow (RFC 9449)
- [ ] DPoP (Demonstrating Proof of Possession) support
- [ ] PAR (Pushed Authorization Requests, RFC 9126)
- [ ] CIBA (Client-Initiated Backchannel Authentication)
- [ ] Integration examples: Hunchentoot middleware, cl-mastodon auth
