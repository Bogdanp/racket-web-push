#lang racket/base

(require base64
         crypto
         crypto/libcrypto
         crypto/vapid
         crypto/web-push
         net/http-easy
         threading)

(define auth-secret (make-parameter #f))
(define endpoint (make-parameter #f))
(define vapid-private-key (make-parameter #f))
(define vapid-public-key (make-parameter #f))
(define ua-public (make-parameter #f))

(define (base64-urldecode str)
  (base64-decode #:endcodes 'url str))

(define (base64-urlencode bs)
  (base64-encode #:endcodes 'url bs))

(define (get-vapid-key)
  (vapid-key-data->pk
   (vapid-public-key)
   (vapid-private-key)
   libcrypto-factory))

(define ((vapid-auth pk) url headers params)
  (define authorization-hdr (format "WebPush ~a" (make-vapid-token pk url #:sub "mailto:bogdan@defn.io")))
  (define crypto-key-hdr (format "p256ecdsa=~a" (base64-urlencode (vapid-public-key))))
  (values
   (~> headers
       (hash-set 'authorization authorization-hdr)
       (hash-set 'crypto-key crypto-key-hdr))
   params))

(define ((aes128gcm-payload message) headers)
  (define-values (in out)
    (make-pipe))
  (thread
   (lambda ()
     (web-push-encrypt
      (open-input-string message) out
      #:auth-secret (auth-secret)
      #:user-agent-key (ua-public))
     (close-output-port out)))
  (values (hash-set headers 'content-encoding "aes128gcm") in))

(define (send-message message)
  (response-body
   (post
    #:auth (vapid-auth (get-vapid-key))
    #:data (buffered-payload (aes128gcm-payload message))
    #:headers (hasheq 'TTL "3600")
    (endpoint))))

(module+ main
  (require racket/cmdline)
  (crypto-factories libcrypto-factory)
  (command-line
   #:once-each
   [("--auth-secret")
    AUTH_SECRET "the shared auth secret"
    (auth-secret (base64-urldecode AUTH_SECRET))]
   [("--endpoint")
    ENDPOINT "the endpoint to send the message to"
    (endpoint ENDPOINT)]
   [("--vapid-private-key")
    VAPID_PRIVATE_KEY "the VAPID private key of the server"
    (vapid-private-key (base64-urldecode VAPID_PRIVATE_KEY))]
   [("--vapid-public-key")
    VAPID_PUBLIC_KEY "the VAPID public key of the server"
    (vapid-public-key (base64-urldecode VAPID_PUBLIC_KEY))]
   [("--ua-public-key")
    UA_PUBLIC "the User Agent's public key"
    (ua-public (base64-urldecode UA_PUBLIC))]
   #:args [message]
   (send-message message)))
