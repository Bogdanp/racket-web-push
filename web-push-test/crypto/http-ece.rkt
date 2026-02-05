#lang racket/base

(require crypto/http-ece
         crypto/libcrypto
         rackunit
         "common.rkt")

;; https://datatracker.ietf.org/doc/html/rfc8188#section-3.1
(test-case "decrypt example 1"
  (define example "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg")
  (define example-bs (base64-urldecode example))
  (check-equal?
   (let ([out (open-output-bytes)])
     (http-ece-decrypt
      #;in (open-input-bytes example-bs)
      #;out out
      #;secret (base64-urldecode "yqdlZ-tYemfogSmv7Ws5PQ")
      #:factories libcrypto-factory)
     (get-output-bytes out))
   #"I am the walrus"))

(test-case "decrpyt example 2"
  (define example "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA")
  (define example-bs (base64-urldecode example))
  (check-equal?
   (let ([out (open-output-bytes)])
     (http-ece-decrypt
      #;in (open-input-bytes example-bs)
      #;out out
      #;secret (lambda (id)
                 (check-equal? id #"a1")
                 (base64-urldecode "BO3ZVPxUlnLORbVGMpbT1Q"))
      #:factories libcrypto-factory)
     (get-output-bytes out))
   #"I am the walrus"))

(test-case "encrypt example 1"
  (check-equal?
   (base64-urlencode
    (let ([out (open-output-bytes)])
      (http-ece-encrypt
       #;in (open-input-bytes #"I am the walrus")
       #;out out
       #;secret (base64-urldecode "yqdlZ-tYemfogSmv7Ws5PQ")
       #:salt (base64-urldecode "I1BsxtFttlv3u_Oo94xnmw")
       #:record-size 4096
       #:factories libcrypto-factory)
      (get-output-bytes out)))
   "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"))

(test-case "encrypt example 2"
  (check-equal?
   (base64-urlencode
    (let ([out (open-output-bytes)])
      (define-values (in-in in-out)
        (make-pipe))
      (thread
       (lambda ()
         (write-bytes #"I am th" in-out)
         (flush-output in-out)
         (sync (system-idle-evt))
         (write-bytes #"e walrus" in-out)
         (close-output-port in-out)))
      (http-ece-encrypt
       #;in in-in
       #;out out
       #;secret (base64-urldecode "BO3ZVPxUlnLORbVGMpbT1Q")
       #:salt (base64-urldecode "uNCkWiNYzKTnBN9ji3-qWA")
       #:key-id #"a1"
       #:record-size 25
       #:factories libcrypto-factory)
      (get-output-bytes out)))
   "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA"))

(test-case "roundtrip with different record sizes"
  (for ([record-size (in-list '(18 25 128 1024))])
    (define input #"I am the walrus")
    (define secret (base64-urldecode "BO3ZVPxUlnLORbVGMpbT1Q"))
    (define encrypted
      (let ([out (open-output-bytes)])
        (http-ece-encrypt
         #;in (open-input-bytes input)
         #;out out
         #;secret secret
         #:record-size record-size
         #:factories libcrypto-factory)
        (get-output-bytes out)))
    (define decrypted
      (let ([out (open-output-bytes)])
        (http-ece-decrypt
         #;in (open-input-bytes encrypted)
         #;out out
         #;secret secret
         #:factories libcrypto-factory)
        (get-output-bytes out)))
    (check-equal? input decrypted)))
