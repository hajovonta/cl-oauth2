(in-package #:cl-oauth2)

(defun poll-device-token (client device-code &key (interval 5) (timeout 300))
  "Poll token endpoint until device code is authorized or timeout."
  (let ((deadline (+ (get-universal-time) timeout)))
    (loop
      (when (> (get-universal-time) deadline)
        (error 'oauth2-error :error-code "timeout"
                             :error-description "Device authorization timed out"))
      (handler-case
          (return (request-token client
                                 (list (cons "grant_type" "urn:ietf:params:oauth:grant-type:device_code")
                                       (cons "device_code" device-code)
                                       (cons "client_id" (client-id client)))))
        (oauth2-error (e)
          (let ((code (oauth2-error-code e)))
            (cond ((string= code "authorization_pending") (sleep interval))
                  ((string= code "slow_down") (sleep (* interval 2)))
                  (t (error e)))))))))
(defun device-authorization-request (client device-authorize-uri &key scopes)
  "Initiate device authorization flow. Returns alist with device-code, user-code, verification-uri."
  (let ((params (list (cons "client_id" (client-id client)))))
    (let ((s (or scopes (client-scopes client))))
      (when s (push (cons "scope" (format nil "~{~A~^ ~}" s)) params)))
    (let ((body (dex:post device-authorize-uri
                          :content params
                          :headers '(("Accept" . "application/json")))))
      (yason:parse body :object-as :alist :object-key-fn #'identity))))
(defun generate-pkce ()
  "Generate PKCE code-verifier and code-challenge pair. Returns (values verifier challenge)."
  (let* ((random-bytes (ironclad:random-data 32))
         (verifier (cl-base64:usb8-array-to-base64-string random-bytes :uri t))
         (digest (ironclad:digest-sequence :sha256
                                           (babel:string-to-octets verifier :encoding :utf-8)))
         (challenge (cl-base64:usb8-array-to-base64-string digest :uri t)))
    (values verifier challenge)))
(defun authorization-url (client &key state scopes code-challenge code-challenge-method)
  "Build authorization URL for redirect-based flows (code grant)."
  (let ((params (list (cons "response_type" "code")
                      (cons "client_id" (client-id client)))))
    (when (redirect-uri client)
      (push (cons "redirect_uri" (redirect-uri client)) params))
    (let ((s (or scopes (client-scopes client))))
      (when s (push (cons "scope" (format nil "~{~A~^ ~}" s)) params)))
    (when state (push (cons "state" state) params))
    (when code-challenge
      (push (cons "code_challenge" code-challenge) params)
      (push (cons "code_challenge_method" (or code-challenge-method "S256")) params))
    (format nil "~A?~{~A=~A~^&~}"
            (authorize-uri client)
            (loop for pair in params
                  collect (quri:url-encode (car pair))
                  collect (quri:url-encode (cdr pair))))))
