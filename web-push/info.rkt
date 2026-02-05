#lang info

(define license 'BSD-3-Clause)
(define collection "crypto")
(define deps
  '("base"
    "web-push-lib"))
(define build-deps
  '("racket-doc"
    "scribble-lib"))
(define implies
  '("web-push-lib"))
(define scribblings
  '(("scribblings/web-push.scrbl")))
