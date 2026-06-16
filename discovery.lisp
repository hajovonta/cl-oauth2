(in-package #:cl-oauth2)

(defun fetch-jwks (jwks-uri)
  "Fetch JSON Web Key Set from a jwks_uri."
  (let ((body (dex:get jwks-uri :headers '(("Accept" . "application/json")))))
    (yason:parse body :object-as :alist :object-key-fn #'identity)))
(defun discover (issuer-url)
  "Fetch and parse OpenID Connect discovery document from issuer URL."
  (let* ((url (format nil "~A/.well-known/openid-configuration"
                      (string-right-trim "/" issuer-url)))
         (body (dex:get url :headers '(("Accept" . "application/json")))))
    (yason:parse body :object-as :alist :object-key-fn #'identity)))
