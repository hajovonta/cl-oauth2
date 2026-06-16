# Authorization Code Flow

The most common OAuth2 flow for web applications.

## Steps

1. Generate authorization URL and redirect user
2. User authenticates at the provider
3. Provider redirects back with authorization code
4. Exchange code for tokens

## Basic Usage

```lisp
(let ((url (cl-oauth2:authorization-url *client* :state "random")))
  ;; Redirect user to url
  )

;; After callback with ?code=xxx&state=random
(let ((token (cl-oauth2:exchange-code *client* "xxx")))
  (cl-oauth2:access-token token)   ; the bearer token
  (cl-oauth2:refresh-token token)  ; for refreshing later
  (cl-oauth2:id-token token))      ; OIDC id_token if requested
```

## With PKCE (recommended)

```lisp
(multiple-value-bind (verifier challenge) (cl-oauth2:generate-pkce)
  (let ((url (cl-oauth2:authorization-url *client*
               :code-challenge challenge
               :code-challenge-method "S256")))
    ;; redirect user to url, store verifier in session
    )
  ;; On callback:
  (cl-oauth2:exchange-code *client* "code" :code-verifier verifier))
```

