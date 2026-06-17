;;;; cl-oauth2.asd

(asdf:defsystem #:cl-oauth2
  :description "OAuth 2.0 and OpenID Connect client library for Common Lisp"
  :author "Hajovonta"
  :license "MIT"
  :version "0.1.0"
  :depends-on (#:babel #:cl-base64 #:dexador #:ironclad #:quri #:yason)
  :serial t
  :components ((:file "package")
               (:file "core")
               (:file "token")
               (:file "jwt")
               (:file "discovery")
               (:file "flows")
               (:file "cache")))
