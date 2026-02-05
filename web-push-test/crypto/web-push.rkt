#lang racket/base

(require crypto
         crypto/libcrypto
         crypto/pem
         crypto/web-push
         racket/match
         racket/port
         rackunit
         "common.rkt")

(define (decode-pem str)
  (match-define (cons _label pem)
    (call-with-input-string str read-pem))
  (datum->pk-key pem 'PrivateKeyInfo libcrypto-factory))

;; https://datatracker.ietf.org/doc/html/rfc8291#section-5
(test-case "encrypt example 1"
  ;; Converted to PEM format using Claude.
  (define as-private-key
    (decode-pem
     #<<PEM
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyfWPiYE+n46HLnH0
KqZOF1fJJU3MYrct3AELtAQ+oRyhRANCAAT+M/SrDepxkU21WCP3O1SUj0EwbZIH
Mtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP
-----END PRIVATE KEY-----
PEM
     ))
  (define in (open-input-string "When I grow up, I want to be a watermelon"))
  (define out (open-output-bytes))
  (web-push-encrypt
   in out
   #:salt (base64-urldecode "DGv6ra1nlYgDCS1FRnbzlw")
   #:auth-secret (base64-urldecode "BTBZMqHH6r4Tts7J_aSIgg")
   #:user-agent-key (base64-urldecode "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
   #:private-key as-private-key
   #:factories libcrypto-factory)
  (check-equal?
   (base64-urlencode
    (get-output-bytes out))
   (string-append
    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
    "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
    "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")))
