# cl-oauth2

OAuth 2.0 and OpenID Connect client library for Common Lisp.

## Features

- Authorization Code flow (with PKCE)
- Client Credentials flow (service-to-service)
- Token refresh
- JWT decode and verification (RS256)
- OIDC discovery (/.well-known/openid-configuration)
- Device Authorization flow (for CLI tools)

## Dependencies

dexador, yason, cl-base64, ironclad, quri, babel

## Quick Start

```lisp
(ql:quickload :cl-oauth2)

(defparameter *client*
  (cl-oauth2:make-client
   :client-id "your-id"
   :client-secret "your-secret"
   :authorize-uri "https://provider.com/authorize"
   :token-uri "https://provider.com/token"
   :redirect-uri "http://localhost:8080/callback"
   :scopes '("openid" "profile")))

;; Build authorization URL
(cl-oauth2:authorization-url *client* :state "csrf-token")

;; Exchange code after redirect
(cl-oauth2:exchange-code *client* "auth-code")

;; Service-to-service
(cl-oauth2:client-credentials-grant *client*)

;; Refresh expired token
(cl-oauth2:refresh *client* token)
```

## Modules

- **core** — Client config, token response, error condition
- **token** — Token endpoint interactions (exchange, refresh, client credentials)
- **jwt** — JWT decoding and RS256 signature verification
- **discovery** — OIDC discovery and JWKS fetching
- **flows** — Authorization URL building, PKCE, device flow

