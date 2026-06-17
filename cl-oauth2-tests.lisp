(defpackage #:cl-oauth2-tests
  (:use #:cl #:fiveam #:cl-oauth2))

(in-package #:cl-oauth2-tests)

(def-suite :cl-oauth2 :description "Tests for cl-oauth2")

(in-suite :cl-oauth2)

(test make-client-basic
  (let ((c (cl-oauth2:make-client :client-id "id" :client-secret "sec"
                                :authorize-uri "https://a.com/auth"
                                :token-uri "https://a.com/token"
                                :scopes '("openid"))))
  (is (string= "id" (cl-oauth2:client-id c)))
  (is (string= "sec" (cl-oauth2:client-secret c)))
  (is (equal '("openid") (cl-oauth2:client-scopes c)))))

(test format-auth-header-basic
  (let ((tok (make-instance 'cl-oauth2:token-response
                          :access-token "abc" :token-type "Bearer"
                          :expires-at (+ (get-universal-time) 3600))))
  (is (string= "Bearer abc" (cl-oauth2:format-auth-header tok)))))

(test token-expired-p-cases
  (let ((fresh (make-instance 'cl-oauth2:token-response
                            :access-token "x" :expires-at (+ (get-universal-time) 3600)))
      (expired (make-instance 'cl-oauth2:token-response
                              :access-token "x" :expires-at (- (get-universal-time) 100)))
      (no-exp (make-instance 'cl-oauth2:token-response :access-token "x")))
  (is (not (cl-oauth2:token-expired-p fresh)))
  (is (cl-oauth2:token-expired-p expired))
  (is (cl-oauth2:token-expired-p no-exp))))

(test authorization-url-basic
  (let* ((c (cl-oauth2:make-client :client-id "cid"
                                  :authorize-uri "https://x.com/auth"
                                  :token-uri "https://x.com/token"
                                  :redirect-uri "http://localhost/cb"
                                  :scopes '("read" "write")))
       (url (cl-oauth2:authorization-url c :state "s1")))
  (is (search "response_type=code" url))
  (is (search "client_id=cid" url))
  (is (search "state=s1" url))
  (is (search "scope=read" url))))

(test generate-pkce-basic
  (multiple-value-bind (verifier challenge) (cl-oauth2:generate-pkce)
  (is (> (length verifier) 30))
  (is (> (length challenge) 30))
  (is (not (string= verifier challenge)))))

(test decode-jwt-basic
  (let* ((jwt "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnRlc3QifQ.fakesig")
       (header (cl-oauth2:jwt-header jwt))
       (claims (cl-oauth2:jwt-claims jwt)))
  (is (string= "RS256" (cdr (assoc "alg" header :test #'string=))))
  (is (string= "key1" (cdr (assoc "kid" header :test #'string=))))
  (is (string= "user123" (cdr (assoc "sub" claims :test #'string=))))
  (is (string= "https://auth.test" (cdr (assoc "iss" claims :test #'string=))))))

(test error-condition
  (handler-case
    (error 'cl-oauth2:oauth2-error :error-code "invalid_grant"
                                   :error-description "Code expired")
  (cl-oauth2:oauth2-error (e)
    (is (string= "invalid_grant" (cl-oauth2:oauth2-error-code e)))
    (is (string= "Code expired" (cl-oauth2:oauth2-error-description e))))))

(test authorization-url-pkce
  (let* ((c (cl-oauth2:make-client :client-id "cid" :client-secret "sec"
                                  :authorize-uri "https://x.com/auth"
                                  :token-uri "https://x.com/token"
                                  :scopes '("api")))
       (url (cl-oauth2:authorization-url c :code-challenge "ch1" :code-challenge-method "S256")))
  (is (search "code_challenge=ch1" url))
  (is (search "code_challenge_method=S256" url))))

(test decode-jwt-parts
  (let ((jwt "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"))
  (multiple-value-bind (h p s) (cl-oauth2:decode-jwt jwt)
    (is (string= "RS256" (cdr (assoc "alg" h :test #'string=))))
    (is (string= "user" (cdr (assoc "sub" p :test #'string=))))
    (is (stringp s)))))

(test refresh-no-token-signals
  (let ((no-refresh (make-instance 'cl-oauth2:token-response :access-token "x"))
      (c (cl-oauth2:make-client :client-id "id" :token-uri "https://x.com/token"
                                :authorize-uri "https://x.com/auth")))
  (5am:signals (cl-oauth2:oauth2-error) (cl-oauth2:refresh c no-refresh))))

(test verify-jwt-claim-checks
  (let* ((jwt "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnRlc3QiLCJhdWQiOiJteWFwcCIsImV4cCI6OTk5OTk5OTk5OX0.fakesig")
       (jwks (list (cons "keys" (list (list (cons "kid" "key1") (cons "alg" "RS256")))))))
  ;; issuer mismatch
  (5am:signals (cl-oauth2:oauth2-error)
    (cl-oauth2:verify-jwt jwt jwks :issuer "https://wrong.issuer"))
  ;; audience mismatch
  (5am:signals (cl-oauth2:oauth2-error)
    (cl-oauth2:verify-jwt jwt jwks :audience "wrong-aud"))))

(test verify-jwt-no-key
  (let ((jwks (list (cons "keys" nil))))
  (5am:signals (cl-oauth2:oauth2-error)
    (cl-oauth2:verify-jwt "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig" jwks))))

(test authorization-url-defaults
  (let* ((c (cl-oauth2:make-client :client-id "cid" :client-secret "sec"
                                  :authorize-uri "https://x.com/auth"
                                  :token-uri "https://x.com/token"
                                  :redirect-uri "http://localhost/cb"))
       (url (cl-oauth2:authorization-url c)))
  ;; Verify default behavior (no PKCE, no state)
  (is (search "response_type=code" url))
  (is (search "client_id=cid" url))
  (is (search "redirect_uri=" url))
  (is (not (search "state=" url)))))

(test verify-jwt-valid-claims
  (let* ((jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwiaXNzIjoiaHR0cHM6Ly9vay5jb20iLCJhdWQiOiJhcHAiLCJleHAiOjk5OTk5OTk5OTl9.")
       (jwks (list (cons "keys" (list (list (cons "alg" "none"))))))
       (claims (cl-oauth2:verify-jwt jwt jwks :issuer "https://ok.com" :audience "app")))
  (is (string= "user" (cdr (assoc "sub" claims :test #'string=))))))

(test cache-put-get
  (let ((c (cl-oauth2:make-cache :max-entries 2)))
  (is (= 0 (hash-table-count (cl-oauth2:cache-entries c))))
  (cl-oauth2:cache-put c "k1" (make-instance 'cl-oauth2:token-response
                                             :access-token "t1" :expires-at (+ (get-universal-time) 3600)))
  (is (= 1 (hash-table-count (cl-oauth2:cache-entries c))))
  (let ((tok (cl-oauth2:cache-get c "k1")))
    (is (string= "t1" (cl-oauth2:access-token tok))))))

(test cache-expired-eviction
  (let ((c (cl-oauth2:make-cache :max-entries 2)))
  (cl-oauth2:cache-put c "k1" (make-instance 'cl-oauth2:token-response
                                             :access-token "old" :expires-at (- (get-universal-time) 100)))
  ;; Expired token should be evicted on get
  (is (null (cl-oauth2:cache-get c "k1")))))

(test cache-max-entries
  (let ((c (cl-oauth2:make-cache :max-entries 2)))
  (cl-oauth2:cache-put c "k1" (make-instance 'cl-oauth2:token-response :access-token "t1" :expires-at (+ (get-universal-time) 3600)))
  (cl-oauth2:cache-put c "k2" (make-instance 'cl-oauth2:token-response :access-token "t2" :expires-at (+ (get-universal-time) 3600)))
  ;; At capacity — next put should evict one
  (cl-oauth2:cache-put c "k3" (make-instance 'cl-oauth2:token-response :access-token "t3" :expires-at (+ (get-universal-time) 3600)))
  (is (<= (hash-table-count (cl-oauth2:cache-entries c)) 2))))

(test make-cache-defaults
  (is (= 64 (cl-oauth2:cache-max-entries (cl-oauth2:make-cache))))
(is (= 10 (cl-oauth2:cache-max-entries (cl-oauth2:make-cache :max-entries 10)))))

(test base64url-decode-basic
  (let ((bytes (cl-oauth2::base64url-decode "SGVsbG8")))
  (is (string= "Hello" (babel:octets-to-string bytes :encoding :utf-8)))))

(test base64url-decode-special-chars
  ;; base64url uses - and _ instead of + and /
(let* ((standard "ab+c/d==")
       (urlsafe "ab-c_d")
       (result (cl-oauth2::base64url-decode urlsafe)))
  (is (equalp result (cl-base64:base64-string-to-usb8-array standard)))))

;;; Coverage: 12/24 functions tested
