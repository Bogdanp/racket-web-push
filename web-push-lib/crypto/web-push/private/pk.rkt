#lang racket/base

(require crypto
         crypto/util/asn1
         racket/match)

(provide
 generate-ecdh-private-key
 encode-ecdh-private-key
 decode-ecdh-private-key
 decode-ecdh-public-key)

(define prime256v1-curve-name
  'prime256v1)
(define prime256v1-curve-oid
  (curve-name->oid prime256v1-curve-name))

(define (generate-ecdh-private-key [factories (crypto-factories)])
  (generate-private-key
   (get-pk 'ec factories)
   `((curve ,prime256v1-curve-name))))

;; Returns the raw, uncompressed public key (ANSI X9.62) and the private
;; key encoded as bytes in big endian order.
(define (encode-ecdh-private-key pk)
  (match-define `(ec private ,_ ,public-bs ,x)
    (pk-key->datum pk 'rkt-private))
  (define private-bs
    (for/fold ([n x]
               [bs null]
               #:result (apply bytes bs))
              ([_ (in-range (quotient 256 8))])
      (values
       (arithmetic-shift n -8)
       (cons (bitwise-and n #xFF) bs))))
  (values public-bs private-bs))

;; The reverse of encode-ecdh-private-key.
(define (decode-ecdh-private-key public-bs private-bs [factories (crypto-factories)])
  (define x
    (for/fold ([n 0])
              ([b (in-bytes private-bs)])
      (bitwise-ior (arithmetic-shift n 8) b)))
  (define spec `(ec private ,prime256v1-curve-oid ,public-bs ,x))
  (datum->pk-key spec 'rkt-private factories))

;; The reverse of encode-ecdh-private-key, but for a public key only.
(define (decode-ecdh-public-key bs [factories (crypto-factories)])
  (datum->pk-key `(ec public ,prime256v1-curve-oid ,bs) 'rkt-public factories))
