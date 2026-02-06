#lang racket/base

(require crypto
         racket/match)

(provide
 generate-ecdh-private-key
 decode-ecdh-private-key
 decode-ecdh-public-key
 encode-ecdh-private-key)

;; XXX: It would be nice if crypto-lib made curve-alias->oid public.
(define prime256v1-curve-oid
  '(1 2 840 10045 3 1 7))

(define (generate-ecdh-private-key [factories (crypto-factories)])
  (generate-private-key
   (get-pk 'ec factories)
   '((curve "prime256v1"))))

(define (decode-ecdh-private-key public-bs private-bs [factories (crypto-factories)])
  (define x
    (for/fold ([n 0])
              ([b (in-bytes private-bs)])
      (bitwise-ior (arithmetic-shift n 8) b)))
  (define spec `(ec private ,prime256v1-curve-oid ,public-bs ,x))
  (datum->pk-key spec 'rkt-private factories))

(define (decode-ecdh-public-key bs [factories (crypto-factories)])
  (datum->pk-key `(ec public ,prime256v1-curve-oid ,bs) 'rkt-public factories))

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
