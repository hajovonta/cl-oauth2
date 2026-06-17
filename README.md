# cl-oauth2

An **OAuth 2.0 and OpenID Connect** client library for Common Lisp. Supports authorization code (with PKCE), client credentials, device authorization, token refresh, JWT verification (RS256/ES256/HS256), OIDC discovery, and token caching. Built with TDD — 48/48 tests passing.

## Key Features

### OAuth2 Flows
- **Authorization Code** — Full redirect-based flow with optional PKCE (RFC 7636)
- **Client Credentials** — Service-to-service token acquisition
- **Device Authorization** — Polling flow for CLI tools and headless devices (RFC 8628)
- **Token Refresh** — Automatic refresh with error handling

### JWT Processing
- **Decode** — Parse header and claims without verification
- **RS256** — RSA PKCS#1 v1.5 signature verification
- **ES256** — ECDSA P-256 signature verification
- **HS256** — HMAC-SHA256 with constant-time comparison (timing-attack safe)
- **Claims Validation** — Issuer, audience, expiration with configurable clock skew
- **JWK Thumbprint** — RFC 7638 calculation for RSA, EC, and symmetric keys

### Token Management
- **In-Memory Cache** — LRU-style with configurable max entries and auto-eviction
- **Auto-Refresh** — `with-token` transparently fetches, caches, and refreshes
- **Introspection** — RFC 7662 token introspection endpoint
- **Revocation** — RFC 7009 token revocation endpoint
- **Response Hooks** — `on-token-response` generic for logging/metrics

### Discovery
- **OIDC Discovery** — Fetch `/.well-known/openid-configuration`
- **JWKS Fetching** — Retrieve provider's JSON Web Key Sets

## Quick Start

```lisp
(ql:quickload :cl-oauth2)

;; Create a client
(defparameter *client*
  (cl-oauth2:make-client
   :client-id "your-id"
   :client-secret "your-secret"
   :authorize-uri "https://provider.com/authorize"
   :token-uri "https://provider.com/token"
   :redirect-uri "http://localhost:8080/callback"
   :scopes '("openid" "profile")))

;; Build authorization URL and redirect user
(cl-oauth2:authorization-url *client* :state "csrf-token")

;; Exchange code after callback
(let ((token (cl-oauth2:exchange-code *client* "auth-code")))
  (cl-oauth2:format-auth-header token))  ; => "Bearer eyJ..."

;; Service-to-service (no user interaction)
(cl-oauth2:client-credentials-grant *client*)

;; Refresh expired token
(cl-oauth2:refresh *client* token)
```

### PKCE (Proof Key for Code Exchange)

```lisp
(multiple-value-bind (verifier challenge) (cl-oauth2:generate-pkce)
  (cl-oauth2:authorization-url *client*
    :code-challenge challenge
    :code-challenge-method "S256")
  ;; On callback:
  (cl-oauth2:exchange-code *client* code :code-verifier verifier))
```

### JWT Verification

```lisp
;; Decode without verification
(cl-oauth2:jwt-claims token-string)
;; => (("sub" . "user123") ("iss" . "https://auth.example.com") ...)

;; Full verification with JWKS
(let* ((config (cl-oauth2:discover "https://accounts.google.com"))
       (jwks (cl-oauth2:fetch-jwks
              (cdr (assoc "jwks_uri" config :test #'string=)))))
  (cl-oauth2:verify-jwt id-token jwks
    :issuer "https://accounts.google.com"
    :audience "your-client-id"
    :clock-skew 30))
```

### Token Cache

```lisp
(let ((cache (cl-oauth2:make-cache :max-entries 64)))
  ;; Auto-manage tokens: fetch, cache, refresh
  (cl-oauth2:with-token *client* cache "my-service"
    (lambda (access-token)
      (dex:get "https://api.example.com/data"
               :headers `(("Authorization" . ,(format nil "Bearer ~A" access-token)))))))
```

### Device Authorization Flow

```lisp
(let* ((resp (cl-oauth2:device-authorization-request *client*
               "https://provider.com/device/code"))
       (user-code (cdr (assoc "user_code" resp :test #'string=)))
       (verify-uri (cdr (assoc "verification_uri" resp :test #'string=)))
       (device-code (cdr (assoc "device_code" resp :test #'string=))))
  (format t "Go to ~A and enter: ~A~%" verify-uri user-code)
  (cl-oauth2:poll-device-token *client* device-code))
```

## Installation

```bash
cd ~/quicklisp/local-projects/
git clone git@git.sr.ht:~hajovonta/cl-oauth2
```

```lisp
(ql:quickload :cl-oauth2)
```

## Dependencies

- **dexador** — HTTP client
- **yason** — JSON parsing
- **cl-base64** — Base64 encoding/decoding
- **ironclad** — Cryptographic operations (RSA, ECDSA, HMAC, SHA-256)
- **quri** — URL encoding
- **babel** — String/octets conversion

## Running Tests

```lisp
(ql:quickload :cl-oauth2-tests)
(asdf:test-system :cl-oauth2)
```

## Module Structure

| File | Description |
|------|-------------|
| `core.lisp` | Client config, token response, error condition, epoch constant |
| `token.lisp` | Token endpoint interactions, introspect, revoke, hooks |
| `jwt.lisp` | JWT decode, signature verification (RS256/ES256/HS256), claims validation, JWK thumbprint |
| `discovery.lisp` | OIDC discovery and JWKS fetching |
| `flows.lisp` | Authorization URL, PKCE, device authorization, polling |
| `cache.lisp` | In-memory token cache with auto-refresh |

## Error Handling

All OAuth2 errors signal `cl-oauth2:oauth2-error`:

```lisp
(handler-case (cl-oauth2:exchange-code *client* "bad-code")
  (cl-oauth2:oauth2-error (e)
    (format t "~A: ~A~%"
            (cl-oauth2:oauth2-error-code e)
            (cl-oauth2:oauth2-error-description e))))
```

## Security

- HMAC signature comparison uses `ironclad:constant-time-equal` (timing-attack safe)
- PKCE with S256 challenge method for public clients
- No secrets stored in source — all configuration via `make-client`

## License

MIT
