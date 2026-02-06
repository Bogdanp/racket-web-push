#lang racket/base

(require crypto/libcrypto
         crypto/vapid
         crypto/web-push
         rackunit
         "common.rkt")

;; https://datatracker.ietf.org/doc/html/rfc8291#section-5
(define as-private-key
  (vapid-key-data->pk
   (base64-urldecode "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")
   (base64-urldecode "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
   libcrypto-factory))
(define ua-public-key
  (base64-urldecode "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"))
(define ua-private-key
  (vapid-key-data->pk
   (base64-urldecode "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
   (base64-urldecode "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
   libcrypto-factory))
(define example1-plaintext
  #"When I grow up, I want to be a watermelon")
(define example1-auth-secret
  (base64-urldecode "BTBZMqHH6r4Tts7J_aSIgg"))
(define example1-encrypted+encoded
  (string-append
   "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
   "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
   "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"))

(test-case "encrypt example 1"
  (define in (open-input-bytes example1-plaintext))
  (define out (open-output-bytes))
  (web-push-encrypt
   in out
   #:salt (base64-urldecode "DGv6ra1nlYgDCS1FRnbzlw")
   #:auth-secret example1-auth-secret
   #:user-agent-key ua-public-key
   #:private-key as-private-key
   #:factories libcrypto-factory)
  (check-equal?
   (base64-urlencode
    (get-output-bytes out))
   example1-encrypted+encoded))

(test-case "decrypt example 1"
  (define in (open-input-bytes (base64-urldecode example1-encrypted+encoded)))
  (define out (open-output-bytes))
  (web-push-decrypt
   in out
   #:auth-secret example1-auth-secret
   #:private-key ua-private-key
   #:factories libcrypto-factory)
  (check-equal?
   (get-output-bytes out)
   example1-plaintext))
