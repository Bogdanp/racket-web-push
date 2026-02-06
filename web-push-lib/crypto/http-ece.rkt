#lang racket/base

(require crypto
         racket/contract/base
         racket/match
         "web-push/private/contract.rkt")

(provide
 (contract-out
  [http-ece-decrypt
   (->* [input-port?
         output-port?
         (or/c bytes? (-> bytes? bytes?))]
        [#:factories crypto-factory/c]
        void?)]
  [http-ece-encrypt
   (->* [input-port? output-port? bytes?]
        [#:salt bytes?
         #:key-id bytes?
         #:record-size (integer-in 18 (sub1 (expt 2 31)))
         #:factories crypto-factory/c]
        void?)]))

(define (http-ece-decrypt
         in out secret
         #:factories [factories (crypto-factories)])
  (define who 'http-ece-decrypt)
  (define salt (expect-bytes who 'salt 16 in))
  (define rs (integer-bytes->integer (expect-bytes who 'rs 4 in) #f #t))
  (define idlen (bytes-ref (expect-bytes who 'idlen 1 in) 0))
  (define keyid (expect-bytes who 'keyid idlen in))
  (let ([secret (if (procedure? secret) (secret keyid) secret)])
    (define-values (prk nonce)
      (derive-key salt secret factories))
    (define ci (get-cipher '(aes gcm) factories))
    (for ([(record-bs idx) (in-indexed (in-producer (λ () (read-bytes rs in)) eof))])
      (define last? (eof-object? (peek-byte in)))
      (define delimiter (if last? #x02 #x01))
      (define decrypted-bs (decrypt ci prk (iv nonce idx) record-bs))
      (write-bytes (unpad decrypted-bs delimiter) out))))

(define (http-ece-encrypt
         in out secret
         #:salt [salt (crypto-random-bytes 16)]
         #:key-id [keyid #""]
         #:record-size [rs 4096]
         #:factories [factories (crypto-factories)])
  (unless ((bytes-length salt) . = . 16)
    (raise-argument-error 'http-ece-encrypt "(bytes-length=/c 16)" salt))
  (define idlen (bytes-length keyid))
  (when (idlen . > . 255)
    (raise-argument-error 'http-ece-encrypt "(bytes-length</c 256)" keyid))
  (write-bytes salt out)
  (write-bytes (integer->integer-bytes rs 4 #f #t) out)
  (write-byte idlen out)
  (write-bytes keyid out)
  (define-values (prk nonce)
    (derive-key salt secret factories))
  (define ci (get-cipher '(aes gcm) factories))
  (define rs-17 (- rs 17))
  (define rs-16 (- rs 16))
  (define record-bs (make-bytes rs-17))
  (for ([(n-read idx) (in-indexed (in-producer (λ () (read-bytes-avail! record-bs in)) eof))])
    (define last? (eof-object? (peek-byte in)))
    (define delimiter (if last? #x02 #x01))
    (define padded-bs (pad record-bs delimiter (if last? 0 rs-16) 0 n-read))
    (define encrypted-bs (encrypt ci prk (iv nonce idx) padded-bs))
    (write-bytes encrypted-bs out)))

;; https://datatracker.ietf.org/doc/html/rfc8188#section-2.2
(define (derive-key salt secret [factories (crypto-factories)])
  (define hmac-sha256 (get-kdf '(hkdf sha256) factories))
  (unless hmac-sha256
    (error 'derive-key "HMAC SHA256 implementation not found"))
  (define key-info #"Content-Encoding: aes128gcm\x00")
  (define key-length 16)
  (define key-params
    `((info ,key-info)
      (key-size ,key-length)))
  (define nonce-info #"Content-Encoding: nonce\x00")
  (define nonce-length 12)
  (define nonce-params
    `((info ,nonce-info)
      (key-size ,nonce-length)))
  (define key (kdf hmac-sha256 secret salt key-params))
  (define nonce (kdf hmac-sha256 secret salt nonce-params))
  (values key nonce))

(define (iv nonce idx)
  (bytes-append
   (subbytes nonce 0 4)
   (integer->integer-bytes
    (bitwise-xor
     (integer-bytes->integer
      nonce
      #;signed? #f
      #;big-endian? #t
      #;start 4)
     idx)
    #;size-n 8
    #;signed? #f
    #;big-endian? #t)))

(define (pad bs delim len [start 0] [end (bytes-length bs)])
  (bytes-append
   (subbytes bs start end)
   (bytes delim)
   (make-bytes (max 0 (- len (- end start) 1)))))

(define (unpad bs delim)
  (match (for*/first ([p (in-range (sub1 (bytes-length bs)) -1 -1)]
                      [b (in-value (bytes-ref bs p))]
                      #:unless (zero? b))
           (cons p b))
    [#f (error 'unpad "no delimiter")]
    [(cons p (== delim)) (subbytes bs 0 p)]
    [_ (error 'unpad "invalid delimiter")]))

(define (expect-bytes who what amt in)
  (define bs (read-bytes amt in))
  (unless (= (bytes-length bs) amt)
    (error who "unexpected end of input while decoding ~a" what))
  bs)
