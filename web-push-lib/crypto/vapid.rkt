#lang racket/base

(require base64
         crypto
         json
         net/url
         racket/contract/base
         "web-push/private/contract.rkt"
         "web-push/private/pk.rkt")

(provide
 (contract-out
  [generate-ecdh-private-key (->* [] [crypto-factory/c] pk-key?)] ;; noqa
  [rename encode-ecdh-private-key pk->vapid-key-data (-> pk-key? (values bytes? bytes?))] ;; noqa
  [rename decode-ecdh-private-key vapid-key-data->pk (->* [bytes? bytes?] [crypto-factory/c] pk-key?)] ;; noqa
  [make-vapid-token
   (->* [pk-key? url? #:sub string?]
        [#:aud string?
         #:exp integer?]
        string?)]))

(define (make-vapid-token
         pk u
         #:sub sub
         #:aud [aud (url->audience u)]
         #:exp [exp (+ (current-seconds) 3600)])
  (define header
    (base64-encode
     #:endcodes 'url
     (jsexpr->bytes
      (hasheq
       'typ "JWT"
       'alg "ES256"))))
  (define payload
    (base64-encode
     #:endcodes 'url
     (jsexpr->bytes
      (hasheq
       'aud aud
       'exp exp
       'sub sub))))
  (define message
    (format "~a.~a" header payload))
  (define signature-bs
    (digest/sign pk 'sha256 (string->bytes/utf-8 message)))
  (define signature
    (base64-encode
     #:endcodes 'url
     (der-signature->jwt-signature signature-bs)))
  (format "~a.~a" message signature))

(define (der-signature->jwt-signature der-bs)
  (define in (open-input-bytes der-bs))
  (read-byte in) ;; 0x30 SEQUENCE
  (read-byte in) ;; total length
  (read-byte in) ;; 0x02 INTEGER tag for R
  (define r-len (read-byte in))
  (define r-raw (read-bytes r-len in))
  (read-byte in) ;; 0x02 INTEGER tag for S
  (define s-len (read-byte in))
  (define s-raw (read-bytes s-len in))
  (bytes-append
   (pad-or-trim r-raw 32)
   (pad-or-trim s-raw 32)))

(define (pad-or-trim bs n)
  (define len (bytes-length bs))
  (cond
    [(= len n) bs]
    [(> len n) (subbytes bs (- len n))]
    [else (bytes-append (make-bytes (- n len) 0) bs)]))

(define (url->audience u)
  (format "~a://~a"
          (or (url-scheme u) "https")
          (if (url-port u)
              (format "~a:~a"
                      (url-host u)
                      (url-port u))
              (url-host u))))
