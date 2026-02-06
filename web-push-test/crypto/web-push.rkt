#lang racket/base

(require crypto/libcrypto
         crypto/vapid
         crypto/web-push
         rackunit
         "common.rkt")

;; https://datatracker.ietf.org/doc/html/rfc8291#section-5
(test-case "encrypt example 1"
  (define as-private-key
    (vapid-key-data->pk
     (base64-urldecode "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")
     (base64-urldecode "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
     libcrypto-factory))
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
