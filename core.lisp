(in-package #:cl-oauth2)

(defun format-auth-header (token-response)
  "Return Authorization header value (e.g. \"Bearer xxx\")."
  (format nil "~A ~A" (token-type token-response) (access-token token-response)))
(defun token-expired-p (token-response)
  "Return T if token has expired (with 30s grace period)."
  (let ((expires (expires-at token-response)))
    (or (null expires)
        (< expires (+ (get-universal-time) 30)))))
(defun make-client (&key client-id client-secret authorize-uri token-uri redirect-uri scopes)
  "Create an oauth2-client instance."
  (make-instance 'oauth2-client
                 :client-id client-id
                 :client-secret client-secret
                 :authorize-uri authorize-uri
                 :token-uri token-uri
                 :redirect-uri redirect-uri
                 :scopes scopes))
(define-condition oauth2-error (error)
  ((error-code :initarg :error-code :reader oauth2-error-code)
   (error-description :initarg :error-description :reader oauth2-error-description
                      :initform nil)
   (error-uri :initarg :error-uri :reader oauth2-error-uri :initform nil))
  (:report (lambda (c s)
             (format s "OAuth2 error ~A~@[: ~A~]"
                     (oauth2-error-code c) (oauth2-error-description c)))))
(defclass token-response ()
  ((access-token :initarg :access-token :reader access-token)
   (token-type :initarg :token-type :reader token-type :initform "Bearer")
   (expires-at :initarg :expires-at :reader expires-at :initform nil)
   (refresh-token :initarg :refresh-token :reader refresh-token :initform nil)
   (id-token :initarg :id-token :reader id-token :initform nil)
   (scope :initarg :scope :reader token-scope :initform nil))
  (:documentation "Parsed token response."))
(defclass oauth2-client ()
  ((client-id :initarg :client-id :reader client-id)
   (client-secret :initarg :client-secret :reader client-secret :initform nil)
   (authorize-uri :initarg :authorize-uri :reader authorize-uri)
   (token-uri :initarg :token-uri :reader token-uri)
   (redirect-uri :initarg :redirect-uri :reader redirect-uri :initform nil)
   (scopes :initarg :scopes :reader client-scopes :initform nil))
  (:documentation "OAuth2 client configuration."))
