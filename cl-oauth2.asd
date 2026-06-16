;;;; cl-oauth2.asd

(asdf:defsystem #:cl-oauth2
  :description "Describe cl-oauth2 here"
  :author "Your Name <your.name@example.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :components ((:file "package")
               (:file "core")
               (:file "token")
               (:file "jwt")
               (:file "discovery")
               (:file "flows")))
