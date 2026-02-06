#lang racket/base

(require crypto
         racket/contract/base
         "http-ece.rkt"
         "web-push/private/contract.rkt"
         "web-push/private/pk.rkt")

(provide
 (contract-out
  [web-push-encrypt
   (->* [input-port?
         output-port?
         #:auth-secret bytes?
         #:user-agent-key bytes?]
        [#:salt bytes?
         #:private-key pk-key?
         #:factories crypto-factory/c]
        void?)]))

(define (web-push-encrypt
         in out
         #:salt [salt (crypto-random-bytes 16)]
         #:auth-secret auth-secret
         #:user-agent-key ua-public-bs
         #:factories [factories (crypto-factories)]
         #:private-key [as-private (generate-ecdh-private-key factories)])
  (define as-public (pk-key->public-only-key as-private))
  (define as-public-bs (cadddr (pk-key->datum as-public 'rkt-public)))
  (define ua-public (decode-ecdh-public-key ua-public-bs factories))
  (define shared-secret (pk-derive-secret as-private ua-public))
  (define auth-info
    (bytes-append
     #"WebPush: info\x00"
     ua-public-bs
     as-public-bs))
  (define auth-params
    `((info ,auth-info)
      (key-size 32)))
  (define hmac-sha256 (get-kdf '(hkdf sha256) factories))
  (define secret (kdf hmac-sha256 shared-secret auth-secret auth-params))
  (http-ece-encrypt
   in out secret
   #:salt salt
   #:key-id as-public-bs
   #:factories factories))
