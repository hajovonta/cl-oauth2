# JWT Verification

Decode and verify JSON Web Tokens from OAuth2/OIDC providers.

## Decode without verification

```lisp
(cl-oauth2:jwt-claims token-string)
;; => (("sub" . "user123") ("iss" . "https://auth.example.com") ...)

(cl-oauth2:jwt-header token-string)
;; => (("alg" . "RS256") ("kid" . "key-id-1"))
```

## Full verification with JWKS

```lisp
;; Fetch provider's public keys
(let* ((config (cl-oauth2:discover "https://accounts.google.com"))
       (jwks (cl-oauth2:fetch-jwks (cdr (assoc "jwks_uri" config :test #'string=)))))
  ;; Verify signature, issuer, audience, expiration
  (cl-oauth2:verify-jwt id-token jwks
                        :issuer "https://accounts.google.com"
                        :audience "your-client-id"))
```

## Supported algorithms

- RS256 (RSA + SHA-256) — full signature verification
- Others — claims validation only (issuer, audience, expiration)

