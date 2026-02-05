#lang scribble/manual

@(require (for-label crypto/http-ece
                     racket/base
                     racket/contract/base
                     racket/random))

@title{Web Push}
@author[(author+email "Bogdan Popa" "bogdan@defn.io")]

@(define rfc8188
   (hyperlink "https://datatracker.ietf.org/doc/html/rfc8188" "RFC 8188"))
@(define rfc8291
   (hyperlink "https://datatracker.ietf.org/doc/html/rfc8291" "RFC 8291"))

This library provides implementations of @rfc8188 and @|rfc8291|.

@section{Reference}
@subsection{Encrypted Content-Encoding for HTTP}
@defmodule[crypto/http-ece]

@defproc[
 (http-ece-decrypt
  [in input-port?]
  [out output-port?]
  [secret (or/c bytes? (-> bytes? bytes?))]
  [#:factories factories (or/c crypto-factory? (listof crypto-factory?)) (crypto-factories)])
 void?]{

 Decrypts the contents of @racket[in] to @racket[out] using
 @racket[secret] and the provided @racket[factories]. When
 @racket[secret] is a procedure, it receives the @emph{key id} read from
 the input header. It must then provide a secret based on that key id.
}

@defproc[
 (http-ece-encrypt
  [in input-port?]
  [out input-port?]
  [secret bytes?]
  [#:salt salt bytes? (crypto-random-bytes 16)]
  [#:key-id key-id bytes? #""]
  [#:record-size record-size (integer-in 18 (sub1 (expt 2 31))) 4096]
  [#:factories factories (or/c crypto-factory? (listof crypto-factory?)) (crypto-factories)])
 void?]{

 Encrypts the contents of @racket[in] and writes the output to
 @racket[out] using @racket[secret] and the provided @racket[factories].
 The content is split into @racket[#:record-size] chunks. The
 @racket[#:key-id] argument can be used to signal to the recipient what
 key they should use to decrypt the data. The @emph{key id} may be at
 most 255 bytes long.
}

@subsection{Message Encryption for Web Push}
@defmodule[crypto/web-push]

@defproc[
 (web-push-encrypt
  [in input-port?]
  [out output-port?]
  [#:salt salt bytes? (crypto-random-bytes 16)]
  [#:auth-secret auth-secret bytes?]
  [#:private-key as-private pk-key? (generate-ecdh-private-key)]
  [#:user-agent-key ua-public bytes?]
  [#:factories factories (or/c crypto-factory? (listof crypto-factory?)) (crypto-factories)])
 void?]{

 Encrypts the contents of @racket[in] and writes the output
 to @racket[out] after exchanging the @racket[as-private] and
 @racket[ua-public] keys in order to generate a shared encryption
 secret.

 If @racket[#:private-key] is not provided, a key is generated
 automatically on every invocation. This is the normal use case.
 Do not reuse keys outside of testing scenarios.
}
