#lang racket/base

(require base64
         crypto/http-ece
         crypto/libcrypto
         rackunit)

(define (base64-urldecode str)
  (base64-decode #:endcodes 'url str))

(define (base64-urlencode bs)
  (bytes->string/utf-8
   (base64-encode #:endcodes 'url bs)))

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
