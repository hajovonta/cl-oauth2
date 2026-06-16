# cl-oauth2

OAuth 2.0 and OpenID Connect client library for Common Lisp.

## Features

- Authorization Code flow (with PKCE)
- Client Credentials flow (service-to-service)
- Token refresh with automatic error handling
- JWT decode and verification (RS256)
- OpenID Connect discovery
- Device Authorization flow (for CLI tools)

## Installation

```lisp
(ql:quickload :cl-oauth2)
```

## Dependencies

dexador, yason, cl-base64, ironclad, quri, babel

## Quick Start

```lisp
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

## PKCE (Proof Key for Code Exchange)

Required for public clients (SPAs, native apps, CLI tools):

```lisp
(multiple-value-bind (verifier challenge) (cl-oauth2:generate-pkce)
  ;; Include challenge in authorization URL
  (cl-oauth2:authorization-url *client*
    :code-challenge challenge
    :code-challenge-method "S256")
  ;; Include verifier when exchanging code
  (cl-oauth2:exchange-code *client* code :code-verifier verifier))
```

## JWT Verification

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
    :audience "your-client-id"))
```

## Device Authorization Flow

For CLI tools and devices without a browser:

```lisp
(let* ((resp (cl-oauth2:device-authorization-request *client*
               "https://provider.com/device/code"))
       (user-code (cdr (assoc "user_code" resp :test #'string=)))
       (verify-uri (cdr (assoc "verification_uri" resp :test #'string=)))
       (device-code (cdr (assoc "device_code" resp :test #'string=))))
  (format t "Go to ~A and enter: ~A~%" verify-uri user-code)
  ;; Polls until user authorizes (or timeout)
  (cl-oauth2:poll-device-token *client* device-code))
```

## Error Handling

All OAuth2 errors signal `cl-oauth2:oauth2-error`:

```lisp
(handler-case (cl-oauth2:exchange-code *client* "bad-code")
  (cl-oauth2:oauth2-error (e)
    (format t "Error: ~A - ~A~%"
            (cl-oauth2:oauth2-error-code e)
            (cl-oauth2:oauth2-error-description e))))
```

## API Reference

### Core
- `make-client` — Create client configuration
- `token-expired-p` — Check if token needs refresh
- `format-auth-header` — Format "Bearer xxx" header value

### Token Operations
- `exchange-code` — Authorization code → tokens
- `client-credentials-grant` — Service-to-service tokens
- `refresh` — Refresh expired token

### JWT
- `decode-jwt` — Decode without verification (header, claims, sig)
- `jwt-header` / `jwt-claims` — Extract parts
- `verify-jwt` — Full verification (RS256, claims, expiration)

### Discovery
- `discover` — Fetch OIDC configuration
- `fetch-jwks` — Fetch JSON Web Key Set

### Flows
- `authorization-url` — Build redirect URL
- `generate-pkce` — Generate verifier/challenge pair
- `device-authorization-request` — Start device flow
- `poll-device-token` — Poll until authorized

## License

MIT
