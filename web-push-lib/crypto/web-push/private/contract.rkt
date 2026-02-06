#lang racket/base

(require crypto
         racket/contract/base)

(provide
 crypto-factory/c)

(define crypto-factory/c
  (or/c crypto-factory? (listof crypto-factory?)))
