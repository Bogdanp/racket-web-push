#lang racket/base

(require base64)
(provide (all-defined-out))

(define (base64-urldecode str)
  (base64-decode #:endcodes 'url str))

(define (base64-urlencode bs)
  (bytes->string/utf-8
   (base64-encode #:endcodes 'url bs)))
