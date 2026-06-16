(in-package #:cl-oauth2)

(defun jwt-header (jwt-string)
  "Extract JOSE header from a JWT."
  (multiple-value-bind (header payload sig) (decode-jwt jwt-string)
    (declare (ignore payload sig))
    header))
(defun jwt-claims (jwt-string)
  "Extract claims (payload) from a decoded JWT."
  (multiple-value-bind (header payload sig) (decode-jwt jwt-string)
    (declare (ignore header sig))
    payload))
(defun verify-jwt (jwt-string jwks &key issuer audience)
  "Verify a JWT signature against a JWK set. Returns claims on success."
  (multiple-value-bind (header claims sig-b64) (decode-jwt jwt-string)
    (let* ((alg (cdr (assoc "alg" header :test #'string=)))
           (kid (cdr (assoc "kid" header :test #'string=)))
           (keys (cdr (assoc "keys" jwks :test #'string=)))
           (jwk (or (find kid keys :key (lambda (k) (cdr (assoc "kid" k :test #'string=)))
                                    :test #'string=)
                    (first keys))))
      (unless jwk
        (error 'oauth2-error :error-code "invalid_key" :error-description "No matching JWK found"))
      ;; Verify claims
      (when issuer
        (unless (string= issuer (cdr (assoc "iss" claims :test #'string=)))
          (error 'oauth2-error :error-code "invalid_issuer")))
      (when audience
        (let ((aud (cdr (assoc "aud" claims :test #'string=))))
          (unless (if (listp aud) (member audience aud :test #'string=) (string= audience aud))
            (error 'oauth2-error :error-code "invalid_audience"))))
      ;; Check expiration
      (let ((exp (cdr (assoc "exp" claims :test #'string=))))
        (when (and exp (numberp exp) (< exp (- (get-universal-time) 2208988800)))
          (error 'oauth2-error :error-code "token_expired")))
      ;; Verify signature (RS256)
      (when (string= alg "RS256")
        (let* ((n-b64 (cdr (assoc "n" jwk :test #'string=)))
               (e-b64 (cdr (assoc "e" jwk :test #'string=)))
               (signing-input (subseq jwt-string 0 (position #\. jwt-string :from-end t)))
               (sig-bytes (cl-base64:base64-string-to-usb8-array
                           (substitute #\+ #\- (substitute #\/ #\_ 
                             (let ((m (mod (length sig-b64) 4)))
                               (if (zerop m) sig-b64
                                   (concatenate 'string sig-b64 (make-string (- 4 m) :initial-element #\=))))))))
               (n-bytes (cl-base64:base64-string-to-usb8-array
                         (substitute #\+ #\- (substitute #\/ #\_
                           (let ((m (mod (length n-b64) 4)))
                             (if (zerop m) n-b64
                                 (concatenate 'string n-b64 (make-string (- 4 m) :initial-element #\=))))))))
               (e-bytes (cl-base64:base64-string-to-usb8-array
                         (substitute #\+ #\- (substitute #\/ #\_
                           (let ((m (mod (length e-b64) 4)))
                             (if (zerop m) e-b64
                                 (concatenate 'string e-b64 (make-string (- 4 m) :initial-element #\=))))))))
               (pub-key (ironclad:make-public-key :rsa
                          :n (ironclad:octets-to-integer n-bytes)
                          :e (ironclad:octets-to-integer e-bytes))))
          (unless (ironclad:verify-signature pub-key :sha256
                    (ironclad:digest-sequence :sha256
                      (babel:string-to-octets signing-input :encoding :utf-8))
                    sig-bytes)
            (error 'oauth2-error :error-code "invalid_signature"))))
      claims)))
(defun decode-jwt (jwt-string)
  "Decode a JWT into header and payload alists without verification.
Returns (values header-alist payload-alist signature-bytes)."
  (let* ((parts (uiop:split-string jwt-string :separator "."))
         (header-b64 (first parts))
         (payload-b64 (second parts))
         (sig-b64 (third parts)))
    (flet ((decode-part (b64)
             (let* ((padded (let ((m (mod (length b64) 4)))
                              (if (zerop m) b64
                                  (concatenate 'string b64
                                               (make-string (- 4 m) :initial-element #\=)))))
                    (bytes (cl-base64:base64-string-to-usb8-array
                            (substitute #\+ #\- (substitute #\/ #\_ padded))))
                    (json-str (babel:octets-to-string bytes :encoding :utf-8)))
               (yason:parse json-str :object-as :alist :object-key-fn #'identity))))
      (values (decode-part header-b64)
              (decode-part payload-b64)
              sig-b64))))
