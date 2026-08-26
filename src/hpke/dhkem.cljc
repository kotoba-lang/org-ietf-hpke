(ns hpke.dhkem
  "DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1 and §7.1.3.

  A KEM built from a Diffie-Hellman: the sender makes an ephemeral key,
  multiplies it with the recipient's public key, and derives a shared secret
  from that product **together with both public keys**. Binding the context
  is what stops a sender's encapsulation being replayed toward a different
  recipient."
  (:require [hpke.kdf :as kdf]
            [x25519.core :as x]))

(def kem-id
  "0x0020. Goes into `suite_id`, so two suites that differ only here derive
  unrelated secrets from the same DH output."
  0x0020)

(def nsecret 32)
(def nsk 32)
(def npk 32)

(def suite-id
  "\"KEM\" || I2OSP(kem_id, 2). The KEM has its OWN suite id, distinct from
  the one the key schedule uses — RFC 9180 §4."
  (vec (concat (kdf/ascii "KEM") [(quot kem-id 256) (mod kem-id 256)])))

(defn derive-key-pair
  "RFC 9180 §7.1.3. Deterministic in `ikm`, which is what makes a test vector
  possible at all.

  There is no rejection sampling here: X25519 clamps, so every 32-byte string
  is a valid scalar. The NIST curves in the same section do need it, which is
  why the specification's text looks more complicated than this."
  [ikm]
  (let [dkp-prk (kdf/labeled-extract suite-id [] "dkp_prk" ikm)
        sk (kdf/labeled-expand suite-id dkp-prk "sk" [] nsk)]
    {:private sk :public (x/public-key sk)}))

(defn- extract-and-expand
  "RFC 9180 §4.1. `kem_context` is `enc || pkRm` — the two public keys, in
  that order."
  [dh kem-context]
  (let [eae-prk (kdf/labeled-extract suite-id [] "eae_prk" dh)]
    (kdf/labeled-expand suite-id eae-prk "shared_secret" kem-context nsecret)))

(defn encap
  "Encapsulate to `pk-r`. `eph` is the ephemeral key pair; it is a parameter
  rather than generated here because randomness is a capability and this is a
  leaf — and because a caller who cannot supply it cannot test.

  **A fresh ephemeral per encapsulation is mandatory.** Reusing one makes two
  encapsulations to the same recipient share a key and a base nonce, and the
  AEAD underneath is a stream cipher."
  [pk-r eph]
  (let [dh (x/x25519 (:private eph) pk-r)]
    (if (not= :ok (:status dh))
      {:status :error :reason :bad-recipient-key :detail (:reason dh)}
      (let [dh (:bytes dh)]
        ;; RFC 9180 §7.1.4: an all-zero DH output means a low-order point and
        ;; the shared secret would carry none of the recipient's key.
        (if-not (x/contributory? dh)
          {:status :error :reason :non-contributory-dh}
          (let [enc (:public eph)]
            {:status :ok
             :enc enc
             :shared-secret (extract-and-expand dh (vec (concat enc pk-r)))}))))))

(defn decap
  "Decapsulate `enc` with the recipient's key pair."
  [enc kp-r]
  (if (not= npk (count enc))
    {:status :error :reason :bad-encapsulation-length :length (count enc)}
    (let [dh (x/x25519 (:private kp-r) enc)]
      (if (not= :ok (:status dh))
        {:status :error :reason :bad-encapsulation :detail (:reason dh)}
        (let [dh (:bytes dh)]
          (if-not (x/contributory? dh)
            {:status :error :reason :non-contributory-dh}
            {:status :ok
             :shared-secret (extract-and-expand
                             dh (vec (concat enc (:public kp-r))))}))))))
