# kotoba-lang/org-ietf-hpke

**[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE — Hybrid Public Key
Encryption — in portable `.cljc`.**

**DHKEM(X25519, HKDF-SHA256)** and **HKDF-SHA256**, with any of RFC 9180's
three AEADs, in **all four modes**: base, PSK, Auth and AuthPSK.

| suite | id | Nk |
|---|---|---|
| `hpke/aes-128-gcm` | `0x0020 / 0x0001 / 0x0001` | 16 |
| `hpke/aes-256-gcm` | `0x0020 / 0x0001 / 0x0002` | 32 |
| `hpke/chacha20-poly1305` *(default)* | `0x0020 / 0x0001 / 0x0003` | 32 |

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

The AEAD is an optional leading argument. Omitted, it is
`chacha20-poly1305` — what this library had before it was a parameter, so an
existing call site means what it used to:

```clojure
(hpke/setup-base-sender hpke/aes-128-gcm (:public kp) info eph)
```

The other three modes are the same shape with the inputs they add:

```clojure
(hpke/setup-psk-sender       pk-r info psk psk-id eph)
(hpke/setup-auth-sender      pk-r info eph kp-s)
(hpke/setup-auth-psk-sender  pk-r info psk psk-id eph kp-s)

(hpke/setup-psk-recipient      enc kp-r info psk psk-id)
(hpke/setup-auth-recipient     enc kp-r info pk-s)
(hpke/setup-auth-psk-recipient enc kp-r info psk psk-id pk-s)
```

`seal` and `open` return a **new context** alongside the bytes. A context is
a value; a mutable counter shared by two callers is how a nonce gets reused,
and the AEAD underneath is a stream cipher.

`hpke/export` derives an independent secret and does **not** advance the
sequence number — exporting is not sending.

## What each mode authenticates

| mode | the recipient learns | the sender learns |
|---|---|---|
| **base** | nothing about who sent it | nothing |
| **PSK** | the sender holds the pre-shared key | the opener holds it too |
| **Auth** | the sender holds `skS` | nothing |
| **AuthPSK** | both | the opener holds the PSK |

Auth mode's guarantee is **deniable**: both parties compute the same secret,
so a transcript proves nothing to a third party. That is a property of the
mode, not a shortfall — a signature is the thing to reach for when
transferability is wanted.

Auth mode also does not fail loudly on a wrong sender key. `auth-decap` has
nothing to compare against, so it derives a *different* shared secret and the
rejection surfaces as the first `open` returning `:authentication-failed`.
The tests assert exactly that sequence, because "no error from setup" reads
like success.

## The rule the construction depends on

**A fresh ephemeral key pair per setup.** Reusing one gives two
encapsulations the same key and the same base nonce. Randomness is a
capability, so this library *takes* the ephemeral rather than making one —
which also means a caller who reuses one is doing so visibly rather than by
accident.

`open` advances the sequence number **only on success**: a rejected message
must not consume a nonce, or an attacker can desynchronise the two sides by
injecting garbage.

**PSK inputs are checked, not coerced** (`psk-inputs-error`, RFC 9180
`VerifyPSKInputs`). A PSK without an id, an id without a PSK, a PSK handed to
a mode that ignores it, and a mode that needs one and did not get it are four
distinct refusals. The third matters most: a silently dropped secret is worse
than an absent one, because the caller believes it is in force.

## What is a parameter, and what is still not

**The AEAD is.** `kotoba-lang/org-nist-aes` exists now, and its `seal`/`open`
have the same signature and result shape as `chacha20.aead`'s, so the suite
carries the two functions themselves rather than a keyword dispatched
somewhere else. There is nothing left for a dispatch layer to do except be a
place for the two to drift apart.

**The KEM and the KDF are not**, and the reason is evidence rather than
effort:

- `HKDF-SHA384` and `HKDF-SHA512` would *run* — `org-nist-sha2` has both
  hashes and, since `hmac-sha384`, both MACs. But RFC 9180 publishes no
  vector for **this KEM** with either, so they would run against nothing.
- **P-256 / P-384 / P-521** and **X448** have no portable implementation in
  this workspace. Measured, not assumed: `btc-crypto`'s curve arithmetic is
  `#?(:clj)`-only over `java.math.BigInteger` and its `:cljs` branch throws.

`hpke/suites` therefore lists three. A suite table listing identifiers
nothing can execute is the kind of completeness that reads as capability.

*(SHA-384 and SHA-512 themselves are in `sha2.sha512`. An earlier version of
this file listed them among the missing primitives — true when written, and
it stopped being true without the sentence changing, which is the ordinary
way a "why not" section becomes wrong.)*

**The modes are four** because A.1 and A.2 both publish all of them. The
earlier argument for shipping base alone — that the others would be three
untested code paths — was an argument about evidence, and the evidence was in
the specification the whole time.

There is no branch on `mode` in the key schedule. A mode is a value that
leads `key_schedule_context`, so the three added modes cannot drift from the
one that was already tested.

## Dependencies — four, all first-party, all implementations

| | |
|---|---|
| `org-nist-sha2` | SHA-256 and HMAC-SHA256 |
| `org-ietf-x25519` | the KEM's Diffie-Hellman |
| `org-ietf-chacha20-poly1305` | one AEAD |
| `org-nist-aes` | the other two |

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

**1,034 assertions, both runtimes, 0 failures. 1,221 with the oracle.**

### Where the vectors come from

`test/hpke/rfc9180_a2.cljc` is **generated** by
`scripts/extract_rfc9180.cljs` from RFC 9180's plain text, pinned by sha256
(`f45a8b7c…f1f8f6`). It carries Appendices **A.1 and A.2** verbatim — the
same KEM and KDF with AES-128-GCM and with ChaCha20Poly1305 — and for each of
the four modes of each: every `ikm` and the key pair it derives to, `enc`,
`shared_secret`, `key_schedule_context`, `secret`, `key`, `base_nonce`,
`exporter_secret`, six encryptions and three exports.

**Transcription is mechanical because transcription is the step that failed
here.** An earlier suite claimed its vectors were A.2 verbatim and they were
not — the recalled `ikmR` was A.1's. The pairing was internally consistent,
so nothing caught it except an assertion on `pkRm`. The generator refuses
rather than regenerating if the source hash ever moves: a fixture rebuilt
from a different document is a different claim.

The sequence numbers asserted are the RFC's — 0, 1, 2, 4, **255 and 256**.
The last two are the point: they are where a byte-at-a-time nonce counter
carries, and `compute-nonce` builds its bytes by division so that it can.

### What the suite discriminates

Measured by breaking one thing at a time and running it:

| break | failures | which tests go red |
|---|---|---|
| drop the mode byte from `key_schedule_context` | **245** | all four modes, and `modes-do-not-collide` |
| swap `pkRm`/`pkSm` in the auth `kem_context` | **64** | auth and auth-psk **only** |
| drop the second DH from `auth-encap` | **64** | auth and auth-psk **only** |
| ignore the context's suite in `seal` | **97** | both appendices, and AES-256-GCM |
| drop `aead_id` from `suite_id` | **718** | everything |
| salt `LabeledExtract(…"secret"…)` with the psk instead of the shared secret | **235** | all four modes |
| *(restored)* | **0** | none |

The two 64s are the ones worth reading. Base and PSK stay **green** while
auth breaks, which is what makes them evidence about the added code rather
than about something shared underneath it.

### The BouncyCastle oracle covers base mode only

`clojure -M:oracle` runs 50 `DeriveKeyPair` comparisons and 12 base-mode
setups against BouncyCastle 1.78.1, including **eight cases where
BouncyCastle decrypts what this implementation sealed**. It has not been
extended to the three added modes, and that is stated rather than implied: a
second opinion on base mode is not a second opinion on auth mode. For A.2 the
RFC is now the primary evidence and the oracle is corroboration.

### Both runtimes

Everything underneath is per-runtime somewhere. HPKE adds one of its own: the
RFC's sequence limit is 2^96, which a JVM long cannot hold and a
ClojureScript number cannot represent exactly, so `compute-nonce` builds its
big-endian counter by division rather than against powers of 256 — the
obvious form throws at namespace load, before any nonce is computed.

## Not here

**Key generation.** `derive-key-pair` is deterministic in its input, which is
what makes a test vector possible. Producing the 32 random bytes is a
capability, and a leaf does not have one.

**A registry of suites beyond three.** See above: the identifiers here are
the ones this can run.

**AES-256-GCM as a known-answer test.** RFC 9180 has no X25519 +
AES-256-GCM section, so that suite is covered by a round-trip and a
suite-separation check and is labelled as such in the test that does it. A
reader should not have to work out which of two adjacent tests is anchored
to a specification and which is not.

**The consumers.** TLS-ECH, ODoH and MLS are what RFC 9180 was written for,
and none of them exist in this workspace yet. This is the primitive they
would each sit on.
