#lang racket/base

(require base64
         crypto/vapid
         crypto/web-push
         net/http-easy
         threading)

(provide
 send-web-push-message)

(define (base64-urldecode str)
  (base64-decode #:endcodes 'url str))

(define (base64-urlencode bs)
  (base64-encode #:endcodes 'url bs))

(define ((vapid-auth as-public-key as-private-key subject) url headers params)
  (define pk (vapid-key-data->pk as-public-key as-private-key))
  (define authorization-hdr (format "WebPush ~a" (make-vapid-token pk url #:sub subject)))
  (define crypto-key-hdr (format "p256ecdsa=~a" (base64-urlencode as-public-key)))
  (values
   (~> headers
       (hash-set 'authorization authorization-hdr)
       (hash-set 'crypto-key crypto-key-hdr))
   params))

(define ((aes128gcm-payload auth-secret ua-public-key message) headers)
  (define-values (in out)
    (make-pipe))
  (thread
   (lambda ()
     (web-push-encrypt
      (open-input-string message) out
      #:auth-secret auth-secret
      #:user-agent-key ua-public-key)
     (close-output-port out)))
  (values (hash-set headers 'content-encoding "aes128gcm") in))

(define (send-web-push-message
         #:ttl [ttl 3600]
         #:endpoint endpoint
         #:auth-secret auth-secret
         #:as-private-key as-private-key
         #:as-public-key as-public-key
         #:ua-public-key ua-public-key
         #:subject subject
         message)
  (post
   #:auth (vapid-auth as-public-key as-private-key subject)
   #:data (aes128gcm-payload auth-secret ua-public-key message)
   #:headers (hasheq 'TTL (number->string ttl))
   endpoint))

(module+ main
  (require racket/cmdline)
  (define ttl 3600)
  (define endpoint #f)
  (define auth-secret #f)
  (define as-private-key #f)
  (define as-public-key #f)
  (define ua-public-key #f)
  (define subject "mailto:someone@example.com")
  (define message
    (command-line
     #:once-each
     [("--ttl")
      TTL "the TTL for the message, in seconds"
      (define ttl-seconds (string->number TTL))
      (unless ttl-seconds
        (eprintf "error: TTL must be a number")
        (exit 1))
      (set! ttl ttl-seconds)]
     [("--endpoint")
      ENDPOINT "the endpoint to send a message to"
      (set! endpoint ENDPOINT)]
     [("--auth-secret")
      AUTH_SECRET "the shared secret between the application server and the user agent"
      (set! auth-secret (base64-urldecode AUTH_SECRET))]
     [("--vapid-private-key")
      AS_PRIVATE_KEY "the application server's private key"
      (set! as-private-key (base64-urldecode AS_PRIVATE_KEY))]
     [("--vapid-public-key")
      AS_PUBLIC_KEY "the application server's public key"
      (set! as-public-key (base64-urldecode AS_PUBLIC_KEY))]
     [("--vapid-subject")
      SUBJECT "the VAPID subject"
      (set! subject SUBJECT)]
     [("--ua-public-key")
      UA_PUBLIC_KEY "the user agent's public key"
      (set! ua-public-key (base64-urldecode UA_PUBLIC_KEY))]
     #:args [message]
     message))
  (define (required flag v)
    (unless v
      (eprintf "error: the ~a flag is required~n" flag)
      (exit 1))
    v)
  (define res
    (send-web-push-message
     #:ttl ttl
     #:endpoint (required '--endpoint endpoint)
     #:auth-secret (required '--auth-secret auth-secret)
     #:as-private-key (required '--as-private-key as-private-key)
     #:as-public-key (required '--as-public-key as-public-key)
     #:ua-public-key (required '--ua-public-key ua-public-key)
     #:subject subject
     message))
  (printf "[~a]: ~a"
          (response-status-code res)
          (response-body res)))
