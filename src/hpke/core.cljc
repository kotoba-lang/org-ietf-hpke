(ns hpke.core
  "[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE — Hybrid Public Key
  Encryption — in portable `.cljc`.

  One cipher suite: **DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20Poly1305** — `0x0020 / 0x0001 / 0x0003`. One mode: **base**.

  ## Why only that

  Every other suite needs a primitive this workspace does not have. AES-GCM,
  P-256, P-384, P-521, X448, SHA-384 and SHA-512-as-a-KDF are each an
  implementation, not a parameter, and a suite table listing identifiers
  nothing can execute is the kind of completeness that reads as capability.
  The identifiers below are the ones this can actually run.

  The PSK, Auth and AuthPSK modes are the same key schedule with two more
  inputs, and adding them without a consumer would ship three untested code
  paths. `mode-base` is a def rather than a literal so the day one is needed
  the shape is already there.

  ## Use

      (def kp (dhkem/derive-key-pair ikm))          ; recipient
      (def s (setup-base-sender (:public kp) info eph))
      (seal (:context s) aad plaintext)             ; -> ciphertext
      (def r (setup-base-recipient (:enc s) kp info))
      (open (:context r) aad ciphertext)

  A context is a value and `seal`/`open` return a NEW one alongside the
  bytes, because the sequence number advances and a mutable counter shared by
  two callers is how a nonce gets reused.

  ## The rule the construction depends on

  **A fresh ephemeral key pair per `setup-base-sender`.** Reusing one gives
  two encapsulations the same key and base nonce, and the AEAD underneath is
  a stream cipher. Randomness is a capability, so this library takes the
  ephemeral rather than making it — which also means a caller who reuses one
  is doing so visibly."
  (:require [chacha20.aead :as aead]
            [hpke.dhkem :as dhkem]
            [hpke.kdf :as kdf]))

(def mode-base 0x00)
(def kdf-id 0x0001)
(def aead-id 0x0003)

(def nk 32)   ; ChaCha20Poly1305 key
(def nn 12)   ; nonce
(def nt 16)   ; tag
(def nh 32)   ; HKDF-SHA256 output

(def suite-id
  "\"HPKE\" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2).
  Distinct from the KEM's own suite id, which is `hpke.dhkem/suite-id`."
  (vec (concat (kdf/ascii "HPKE")
               [(quot dhkem/kem-id 256) (mod dhkem/kem-id 256)]
               [(quot kdf-id 256) (mod kdf-id 256)]
               [(quot aead-id 256) (mod aead-id 256)])))

(defn key-schedule
  "RFC 9180 §5.1, base mode.

  `psk` and `psk_id` are empty here. They are still hashed in, and the mode
  byte still leads the context, so a base-mode context can never collide with
  a PSK-mode one even when both have an empty psk."
  [shared-secret info]
  (let [psk-id-hash (kdf/labeled-extract suite-id [] "psk_id_hash" [])
        info-hash (kdf/labeled-extract suite-id [] "info_hash" info)
        ks-context (vec (concat [mode-base] psk-id-hash info-hash))
        secret (kdf/labeled-extract suite-id shared-secret "secret" [])]
    {:key (kdf/labeled-expand suite-id secret "key" ks-context nk)
     :base-nonce (kdf/labeled-expand suite-id secret "base_nonce" ks-context nn)
     :exporter-secret (kdf/labeled-expand suite-id secret "exp" ks-context nh)
     :seq 0}))

(defn- compute-nonce
  "RFC 9180 §5.2: `base_nonce XOR I2OSP(seq, Nn)`.

  The big-endian bytes are produced by repeated division rather than by
  multiplying `seq` against powers of 256. `256^11` is 2^88, which overflows
  a JVM long the moment it is formed and is not an exact integer under
  ClojureScript — so writing the obvious `(* seq (expt 256 k))` throws at
  namespace load, before any nonce is computed."
  [base-nonce n]
  (let [be (loop [v n out () k 0]
             (if (= k nn)
               (vec out)
               (recur (quot v 256) (conj out (bit-and v 0xFF)) (inc k))))]
    (mapv bit-xor base-nonce be)))

(def ^:private max-seq
  "The largest sequence number this can count to.

  RFC 9180 §5.2 puts the limit at 2^(8*Nn) - 1, which for Nn = 12 is 2^96 -
  and neither runtime can hold that: a JVM long stops at 2^63 and a
  ClojureScript number stops being an exact integer at 2^53. So the real
  limit is the smaller of those, and it is stated as such rather than as a
  constant that cannot be formed.

  This is not a shortcut. At one message per nanosecond, 2^53 takes over two
  hundred years; the RFC's bound was never the binding one."
  9007199254740990)

(defn seal
  "Encrypt with `ctx`. Returns `{:status :ok :bytes ct :context ctx'}` — the
  new context carries the advanced sequence number."
  [ctx aad pt]
  (if (>= (:seq ctx) max-seq)
    {:status :error :reason :message-limit-reached :seq (:seq ctx)}
    (let [r (aead/seal (:key ctx) (compute-nonce (:base-nonce ctx) (:seq ctx)) aad pt)]
      (if (= :ok (:status r))
        {:status :ok :bytes (:bytes r) :context (update ctx :seq inc)}
        r))))

(defn open
  "Decrypt with `ctx`. Returns `{:status :ok :bytes pt :context ctx'}`.

  The sequence number advances **only on success**: a rejected message must
  not consume a nonce, or an attacker could desynchronise the two sides by
  injecting garbage."
  [ctx aad ct]
  (if (>= (:seq ctx) max-seq)
    {:status :error :reason :message-limit-reached :seq (:seq ctx)}
    (let [r (aead/open (:key ctx) (compute-nonce (:base-nonce ctx) (:seq ctx)) aad ct)]
      (if (= :ok (:status r))
        {:status :ok :bytes (:bytes r) :context (update ctx :seq inc)}
        r))))

(defn export
  "RFC 9180 §5.3 — derive an independent secret from the context.

  Does not touch the sequence number: exporting is not sending, and a caller
  that exports between messages must not shift the nonce."
  [ctx exporter-context length]
  (kdf/labeled-expand suite-id (:exporter-secret ctx) "sec" exporter-context length))

;; ── setup ────────────────────────────────────────────────────────────────────

(defn setup-base-sender
  "RFC 9180 §5.1.1. `eph` is the ephemeral key pair — see this namespace's
  docstring on why it is a parameter."
  [pk-r info eph]
  (let [r (dhkem/encap pk-r eph)]
    (if (not= :ok (:status r))
      r
      {:status :ok :enc (:enc r) :context (key-schedule (:shared-secret r) info)})))

(defn setup-base-recipient
  "RFC 9180 §5.1.1, the receiving half."
  [enc kp-r info]
  (let [r (dhkem/decap enc kp-r)]
    (if (not= :ok (:status r))
      r
      {:status :ok :context (key-schedule (:shared-secret r) info)})))

;; ── single-shot ──────────────────────────────────────────────────────────────

(defn seal-base
  "Set up and seal one message. Returns `{:status :ok :enc … :bytes …}`."
  [pk-r info aad pt eph]
  (let [s (setup-base-sender pk-r info eph)]
    (if (not= :ok (:status s))
      s
      (let [r (seal (:context s) aad pt)]
        (if (= :ok (:status r))
          {:status :ok :enc (:enc s) :bytes (:bytes r)}
          r)))))

(defn open-base
  "Set up and open one message."
  [enc kp-r info aad ct]
  (let [s (setup-base-recipient enc kp-r info)]
    (if (not= :ok (:status s))
      s
      (open (:context s) aad ct))))

(defn hex [bs] (aead/hex bs))
(defn unhex [s] (aead/unhex s))
