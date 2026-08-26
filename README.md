# kotoba-lang/org-ietf-hpke

**[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE — Hybrid Public Key
Encryption — in portable `.cljc`.**

One cipher suite: **DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
ChaCha20Poly1305** (`0x0020 / 0x0001 / 0x0003`). One mode: **base**.

## Use

```clojure
(require '[hpke.core :as hpke] '[hpke.dhkem :as dhkem])

(def kp  (dhkem/derive-key-pair recipient-ikm))
(def eph (dhkem/derive-key-pair fresh-random-32-bytes))   ; ONE per message

(def s (hpke/setup-base-sender (:public kp) info eph))
(def m (hpke/seal (:context s) aad plaintext))
;; send (:enc s) and (:bytes m)

(def r (hpke/setup-base-recipient (:enc s) kp info))
(hpke/open (:context r) aad (:bytes m))
```

`seal` and `open` return a **new context** alongside the bytes. A context is
a value; a mutable counter shared by two callers is how a nonce gets reused,
and the AEAD underneath is a stream cipher.

`hpke/export` derives an independent secret and does **not** advance the
sequence number — exporting is not sending.

## The rule the construction depends on

**A fresh ephemeral key pair per `setup-base-sender`.** Reusing one gives two
encapsulations the same key and the same base nonce. Randomness is a
capability, so this library *takes* the ephemeral rather than making one —
which also means a caller who reuses one is doing so visibly rather than by
accident.

`open` advances the sequence number **only on success**: a rejected message
must not consume a nonce, or an attacker can desynchronise the two sides by
injecting garbage.

## Why only one suite and one mode

Every other suite needs a primitive this workspace does not have. AES-GCM,
P-256, P-384, P-521, X448 and SHA-384/512 are each an implementation, not a
parameter, and a suite table listing identifiers nothing can execute is the
kind of completeness that reads as capability.

The PSK, Auth and AuthPSK modes are the same key schedule with two more
inputs. Adding them without a consumer would ship three untested code paths;
`mode-base` is a named constant rather than a literal so the shape is there
the day one is needed.

## Dependencies — three, all first-party, all implementations

| | |
|---|---|
| `org-nist-sha2` | SHA-256 and HMAC-SHA256 |
| `org-ietf-x25519` | the KEM's Diffie-Hellman |
| `org-ietf-chacha20-poly1305` | the AEAD |

**Not `kotoba-lang/crypto`**: its `hkdf` hardcodes a **zero salt**, and RFC
9180's key schedule passes a real one (`LabeledExtract(shared_secret,
"secret", psk)`), so a fixed-salt Extract computes a different function. Its
default digest is also a JVM `MessageDigest`.

**Not `kotoba-lang/noise`**: its AEAD is host-injected through
`provider/{jvm.clj, noble.cljs, node.cljs}` — on ClojureScript, through
`@noble` itself. Both were listed in this workspace's dependency ledger as
first-party replacements for `@noble/ciphers`, and both were seams. That
error is what this library's dependency list exists to correct.

## Verify

```sh
clojure -M:test                                                        # JVM
nbb --classpath "$(clojure -A:cljs -Spath)" scripts/verify-cljs.cljs   # ClojureScript
clojure -M:oracle                                                      # + differential vs BouncyCastle
```

**Where the vectors come from, precisely.** `ikmE` is RFC 9180 **Appendix
A.2's** and `ikmR` is **A.1's**. Both derive to the public keys those sections
publish, and the suite asserts exactly that — real RFC anchoring for
`DeriveKeyPair`, the one function where a wrong answer is silent. The
*pairing* is not a published combination, so the ciphertexts and exports are
**BouncyCastle 1.78.1's**.

That mixture is stated rather than smoothed over. An earlier draft claimed
the whole set was A.2 verbatim and it was not: the recalled `ikmR` turned out
to be A.1's, which the `pkRm` assertion caught before anything shipped.

**Differential**: 50 `DeriveKeyPair` comparisons, 12 base-mode setups each
checked across six sequential messages and three exports, and — the strongest
statement available — **eight cases where BouncyCastle decrypts what this
implementation sealed**, rather than two implementations agreeing on bytes
they both computed the same wrong way.

Dropping the mode byte from the key schedule context turns **122 assertions**
red; swapping `enc` and `pkRm` in `kem_context` turns **131** red. Both
measured.

**Both runtimes.** Everything underneath is per-runtime somewhere. HPKE adds
one of its own: the RFC's sequence limit is 2^96, which a JVM long cannot
hold and a ClojureScript number cannot represent exactly, so `compute-nonce`
builds its big-endian counter by division rather than against powers of 256 —
the obvious form throws at namespace load, before any nonce is computed.

## Not here

**Key generation.** `derive-key-pair` is deterministic in its input, which is
what makes a test vector possible. Producing the 32 random bytes is a
capability, and a leaf does not have one.

**A registry of suites.** See above: the identifiers here are the ones this
can run.
