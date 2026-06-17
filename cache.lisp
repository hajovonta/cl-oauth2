(in-package #:cl-oauth2)

(defun with-token (client cache key fn &key scopes)
  "Call FN with a valid access token. Fetches, caches, and refreshes automatically.
FN receives the access-token string as its argument."
  (let ((tok (cache-get cache key :client client)))
    (unless tok
      (setf tok (client-credentials-grant client :scopes scopes))
      (cache-put cache key tok))
    (funcall fn (access-token tok))))
(defun cache-get (cache key &key client)
  "Get a valid token from cache, refreshing if expired. Returns token-response or nil."
  (let ((tok (gethash key (cache-entries cache))))
    (when tok
      (cond ((not (token-expired-p tok)) tok)
            ((and client (refresh-token tok))
             (let ((new-tok (refresh client tok)))
               (setf (gethash key (cache-entries cache)) new-tok)
               new-tok))
            (t (remhash key (cache-entries cache))
               nil)))))
(defun cache-put (cache key token-response)
  "Store a token-response in the cache under a key."
  (let ((ht (cache-entries cache)))
    (when (>= (hash-table-count ht) (cache-max-entries cache))
      ;; Evict oldest expired entry, or first entry
      (block evict
        (maphash (lambda (k v)
                   (when (token-expired-p v)
                     (remhash k ht)
                     (return-from evict)))
                 ht)
        (maphash (lambda (k v)
                   (declare (ignore v))
                   (remhash k ht)
                   (return-from evict))
                 ht)))
    (setf (gethash key ht) token-response)))
(defun make-cache (&key (max-entries 64))
  "Create a token cache instance."
  (make-instance 'token-cache :max-entries max-entries))
(defclass token-cache ()
  ((entries :initform (make-hash-table :test #'equal) :reader cache-entries)
   (max-entries :initarg :max-entries :reader cache-max-entries :initform 64))
  (:documentation "In-memory token cache. Stores token-responses keyed by scope set."))
