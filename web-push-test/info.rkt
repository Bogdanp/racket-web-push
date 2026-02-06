#lang info

(define license 'BSD-3-Clause)
(define collection "tests")
(define deps
  '("base"))
(define build-deps
  '("base64-lib"
    "crypto-lib"
    "rackunit-lib"
    "web-push-lib"))
(define update-implies
  '("web-push-lib"))
