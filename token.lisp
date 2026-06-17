(in-package #:cl-oauth2)

(defun refresh (client token-response)
  "Refresh an expired token using its refresh-token."
  (let ((rt (refresh-token token-response)))
    (unless rt
      (error 'oauth2-error :error-code "no_refresh_token"
                           :error-description "Token response has no refresh_token"))
    (let ((params (list (cons "grant_type" "refresh_token")
                        (cons "refresh_token" rt)
                        (cons "client_id" (client-id client)))))
      (when (client-secret client)
        (push (cons "client_secret" (client-secret client)) params))
      (request-token client params))))
(defun request-token (client params)
  "POST to token endpoint and parse response into token-response."
  (let* ((body (dex:post (token-uri client)
                         :content params
                         :headers '(("Accept" . "application/json"))))
         (json (yason:parse body :object-as :alist :object-key-fn #'identity)))
    (let ((err (cdr (assoc "error" json :test #'string=))))
      (when err
        (error 'oauth2-error
               :error-code err
               :error-description (cdr (assoc "error_description" json :test #'string=))
               :error-uri (cdr (assoc "error_uri" json :test #'string=)))))
    (let ((expires-in (cdr (assoc "expires_in" json :test #'string=))))
      (make-instance 'token-response
                     :access-token (cdr (assoc "access_token" json :test #'string=))
                     :token-type (or (cdr (assoc "token_type" json :test #'string=)) "Bearer")
                     :expires-at (when expires-in
                                   (+ (get-universal-time) (floor expires-in)))
                     :refresh-token (cdr (assoc "refresh_token" json :test #'string=))
                     :id-token (cdr (assoc "id_token" json :test #'string=))
                     :scope (cdr (assoc "scope" json :test #'string=))))))
(defun client-credentials-grant (client &key scopes)
  "Obtain token via client_credentials grant (service-to-service)."
  (let ((params (list (cons "grant_type" "client_credentials")
                      (cons "client_id" (client-id client))
                      (cons "client_secret" (client-secret client)))))
    (let ((s (or scopes (client-scopes client))))
      (when s
        (push (cons "scope" (format nil "~{~A~^ ~}" s)) params)))
    (request-token client params)))
(defun exchange-code (client code &key code-verifier redirect-uri)
  "Exchange authorization code for tokens."
  (let ((params (list (cons "grant_type" "authorization_code")
                      (cons "code" code)
                      (cons "client_id" (client-id client))
                      (cons "redirect_uri" (or redirect-uri (redirect-uri client))))))
    (when (client-secret client)
      (push (cons "client_secret" (client-secret client)) params))
    (when code-verifier
      (push (cons "code_verifier" code-verifier) params))
    (request-token client params)))

(defun revoke-token (client token &key token-type-hint revocation-uri)
  "Revoke a token at the provider's revocation endpoint (RFC 7009)."
  (let ((params (list (cons "token" token)
                      (cons "client_id" (client-id client)))))
    (when (client-secret client)
      (push (cons "client_secret" (client-secret client)) params))
    (when token-type-hint
      (push (cons "token_type_hint" token-type-hint) params))
    (dex:post (or revocation-uri
                  (format nil "~A/revoke" (token-uri client)))
              :content params
              :headers '(("Accept" . "application/json")))
    (values)))

(defun introspect-token (client token &key token-type-hint introspection-uri)
  "Introspect a token at the provider's introspection endpoint (RFC 7662)."
  (let ((params (list (cons "token" token)
                      (cons "client_id" (client-id client)))))
    (when (client-secret client)
      (push (cons "client_secret" (client-secret client)) params))
    (when token-type-hint
      (push (cons "token_type_hint" token-type-hint) params))
    (let ((body (dex:post (or introspection-uri
                              (format nil "~A/introspect" (token-uri client)))
                          :content params
                          :headers '(("Accept" . "application/json")))))
      (yason:parse body :object-as :alist :object-key-fn #'identity))))
