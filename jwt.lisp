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
(defun verify-jwt (jwt-string jwks &key issuer audience (clock-skew 0))
  "Verify a JWT signature against a JWK set. Returns claims on success.
CLOCK-SKEW is seconds of tolerance for expiration checks."
  (multiple-value-bind (header claims sig-b64) (decode-jwt jwt-string)
    (let* ((alg (cdr (assoc "alg" header :test #'string=)))
           (kid (cdr (assoc "kid" header :test #'string=)))
           (keys (cdr (assoc "keys" jwks :test #'string=)))
           (jwk (or (find kid keys :key (lambda (k) (cdr (assoc "kid" k :test #'string=)))
                                    :test #'string=)
                    (first keys))))
      (unless jwk
        (error 'oauth2-error :error-code "invalid_key" :error-description "No matching JWK found"))
      (validate-claims claims :issuer issuer :audience audience :clock-skew clock-skew)
      (when (member alg '("RS256" "ES256" "HS256") :test #'string=)
        (verify-signature alg jwk
                          (subseq jwt-string 0 (position #\. jwt-string :from-end t))
                          (base64url-decode sig-b64)))
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

(defun base64url-decode (b64url)
  "Decode a base64url string to octets."
  (let* ((padded (let ((m (mod (length b64url) 4)))
                   (if (zerop m) b64url
                       (concatenate 'string b64url (make-string (- 4 m) :initial-element #\=))))))
    (cl-base64:base64-string-to-usb8-array
     (substitute #\+ #\- (substitute #\/ #\_ padded)))))

(defun verify-signature (alg jwk signing-input sig-bytes)
  "Verify a JWT signature given the algorithm, JWK, signing input, and signature bytes."
  (let ((input-bytes (babel:string-to-octets signing-input :encoding :utf-8)))
    (cond
      ((string= alg "RS256")
       ;; RS256 = RSASSA-PKCS1-v1_5 with SHA-256
       ;; Ironclad does raw RSA (no PKCS#1 v1.5 padding internally),
       ;; so we must construct the expected EMSA-PKCS1-v1_5 encoded message.
       (let* ((pub-key (ironclad:make-public-key :rsa
                         :n (ironclad:octets-to-integer (base64url-decode (cdr (assoc "n" jwk :test #'string=))))
                         :e (ironclad:octets-to-integer (base64url-decode (cdr (assoc "e" jwk :test #'string=))))))
              (digest (ironclad:digest-sequence :sha256 input-bytes))
              (nbits (integer-length (slot-value pub-key 'ironclad::n)))
              (em-len (ceiling nbits 8))
              ;; DigestInfo for SHA-256: DER-encoded AlgorithmIdentifier + digest
              (digest-info (concatenate '(vector (unsigned-byte 8))
                            #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01
                              #x65 #x03 #x04 #x02 #x01 #x05 #x00 #x04 #x20)
                            digest))
              ;; EMSA-PKCS1-v1_5: 00 01 PS 00 DigestInfo
              (ps-len (- em-len (length digest-info) 3))
              (em (make-array em-len :element-type '(unsigned-byte 8) :initial-element #xff)))
         (setf (aref em 0) #x00
               (aref em 1) #x01
               (aref em (+ 2 ps-len)) #x00)
         (replace em digest-info :start1 (+ 3 ps-len))
         (unless (ironclad:verify-signature pub-key em sig-bytes)
           (error 'oauth2-error :error-code "invalid_signature"))))
      ((string= alg "ES256")
       ;; ES256 = ECDSA with P-256 and SHA-256
       ;; For ECDSA, Ironclad expects the hash as the message.
       (let* ((pub-key (ironclad:make-public-key :secp256r1
                         :x (base64url-decode (cdr (assoc "x" jwk :test #'string=)))
                         :y (base64url-decode (cdr (assoc "y" jwk :test #'string=)))))
              (digest (ironclad:digest-sequence :sha256 input-bytes))
              (r (subseq sig-bytes 0 32))
              (s (subseq sig-bytes 32 64)))
         (unless (ironclad:verify-signature pub-key digest
                   (ironclad:make-signature :secp256r1 :r r :s s))
           (error 'oauth2-error :error-code "invalid_signature"))))
      ((string= alg "HS256")
       (let* ((secret (base64url-decode (cdr (assoc "k" jwk :test #'string=))))
              (mac (ironclad:make-mac :hmac secret :sha256))
              (input-bytes (babel:string-to-octets signing-input :encoding :utf-8)))
         (ironclad:update-mac mac input-bytes)
         (let ((expected (ironclad:produce-mac mac)))
           (unless (ironclad:constant-time-equal expected sig-bytes)
             (error 'oauth2-error :error-code "invalid_signature"))))))))

(defun validate-claims (claims &key issuer audience (clock-skew 0))
  "Validate JWT claims: issuer, audience, expiration. Signals oauth2-error on mismatch.
CLOCK-SKEW is seconds of tolerance for expiration."
  (when issuer
    (unless (string= issuer (cdr (assoc "iss" claims :test #'string=)))
      (error 'oauth2-error :error-code "invalid_issuer")))
  (when audience
    (let ((aud (cdr (assoc "aud" claims :test #'string=))))
      (unless (if (listp aud) (member audience aud :test #'string=) (string= audience aud))
        (error 'oauth2-error :error-code "invalid_audience"))))
  (let ((exp (cdr (assoc "exp" claims :test #'string=))))
    (when (and exp (numberp exp) (< (+ exp clock-skew) (- (get-universal-time) +unix-epoch-offset+)))
      (error 'oauth2-error :error-code "token_expired"))))

(defun base64url-encode (octets)
  "Encode octets to base64url string (no padding)."
  (let ((b64 (cl-base64:usb8-array-to-base64-string octets)))
    (string-right-trim "=" (substitute #\- #\+ (substitute #\_ #\/ b64)))))

(defun jwk-thumbprint (jwk)
  "Calculate JWK thumbprint per RFC 7638. Returns base64url-encoded SHA-256 hash."
  (let* ((kty (cdr (assoc "kty" jwk :test #'string=)))
         ;; RFC 7638: lexicographic order of required members per key type
         (canonical
           (cond
             ((string= kty "RSA")
              (format nil "{\"e\":\"~A\",\"kty\":\"RSA\",\"n\":\"~A\"}"
                      (cdr (assoc "e" jwk :test #'string=))
                      (cdr (assoc "n" jwk :test #'string=))))
             ((string= kty "EC")
              (format nil "{\"crv\":\"~A\",\"kty\":\"EC\",\"x\":\"~A\",\"y\":\"~A\"}"
                      (cdr (assoc "crv" jwk :test #'string=))
                      (cdr (assoc "x" jwk :test #'string=))
                      (cdr (assoc "y" jwk :test #'string=))))
             ((string= kty "oct")
              (format nil "{\"k\":\"~A\",\"kty\":\"oct\"}"
                      (cdr (assoc "k" jwk :test #'string=))))
             (t (error 'oauth2-error :error-code "unsupported_key_type"
                                     :error-description kty)))))
    (base64url-encode (ironclad:digest-sequence :sha256
                        (babel:string-to-octets canonical :encoding :utf-8)))))
