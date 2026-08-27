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

(defn- dh
  "One X25519, with the check RFC 9180 §7.1.4 requires on its output.

  An all-zero product means a low-order point: the result carries none of the
  other party's key, so every peer would derive the same shared secret. It is
  checked here, once, rather than at each of the four call sites below --
  `auth-encap` and `auth-decap` each do two of these, and a check written
  twice per function is a check that gets written once."
  [sk pk on-error]
  (let [r (x/x25519 sk pk)]
    (cond
      (not= :ok (:status r)) {:status :error :reason on-error :detail (:reason r)}
      (not (x/contributory? (:bytes r))) {:status :error :reason :non-contributory-dh}
      :else {:status :ok :bytes (:bytes r)})))

(defn encap
  "Encapsulate to `pk-r`. `eph` is the ephemeral key pair; it is a parameter
  rather than generated here because randomness is a capability and this is a
  leaf -- and because a caller who cannot supply it cannot test.

  **A fresh ephemeral per encapsulation is mandatory.** Reusing one makes two
  encapsulations to the same recipient share a key and a base nonce, and the
  AEAD underneath is a stream cipher."
  [pk-r eph]
  (let [d (dh (:private eph) pk-r :bad-recipient-key)]
    (if (not= :ok (:status d))
      d
      (let [enc (:public eph)]
        {:status :ok
         :enc enc
         :shared-secret (extract-and-expand (:bytes d) (vec (concat enc pk-r)))}))))

(defn decap
  "Decapsulate `enc` with the recipient's key pair."
  [enc kp-r]
  (if (not= npk (count enc))
    {:status :error :reason :bad-encapsulation-length :length (count enc)}
    (let [d (dh (:private kp-r) enc :bad-encapsulation)]
      (if (not= :ok (:status d))
        d
        {:status :ok
         :shared-secret (extract-and-expand
                         (:bytes d) (vec (concat enc (:public kp-r))))}))))

;; -- authenticated KEM, RFC 9180 s4.1 ----------------------------------------
;;
;; The same construction with the sender's static key mixed in. Two things
;; change and both matter:
;;
;;   the DH input      DH(skE, pkR) || DH(skS, pkR)   -- two products, not one
;;   the KEM context   enc || pkRm || pkSm            -- three keys, not two
;;
;; The second is what makes the authentication mean anything. Without pkSm in
;; the context, a recipient who also holds a valid encapsulation from someone
;; else could not tell the two apart; the shared secret is bound to *which*
;; sender, not merely to the fact that some static key was used.

(defn auth-encap
  "RFC 9180 §4.1 AuthEncap. `kp-s` is the sender's static key pair.

  The recipient learns that whoever sent this holds `skS`. It does not learn
  it in a way it can show to anyone else -- both parties can compute the same
  secret, so a transcript proves nothing to a third party. That deniability
  is the property that distinguishes this from a signature, and it is a
  feature of the mode rather than a shortfall of it."
  [pk-r eph kp-s]
  (let [de (dh (:private eph) pk-r :bad-recipient-key)]
    (if (not= :ok (:status de))
      de
      (let [ds (dh (:private kp-s) pk-r :bad-recipient-key)]
        (if (not= :ok (:status ds))
          ds
          (let [enc (:public eph)]
            {:status :ok
             :enc enc
             :shared-secret (extract-and-expand
                             (vec (concat (:bytes de) (:bytes ds)))
                             (vec (concat enc pk-r (:public kp-s))))}))))))

(defn auth-decap
  "RFC 9180 §4.1 AuthDecap. `pk-s` is the sender's static public key.

  A wrong `pk-s` does not fail here -- it derives a different shared secret,
  and the failure surfaces as the AEAD rejecting the first message. That is
  the specified behaviour: the KEM has nothing to compare against, so
  authentication is enforced by decryption rather than by a check with its
  own error."
  [enc kp-r pk-s]
  (cond
    (not= npk (count enc))
    {:status :error :reason :bad-encapsulation-length :length (count enc)}

    (not= npk (count pk-s))
    {:status :error :reason :bad-sender-key-length :length (count pk-s)}

    :else
    (let [de (dh (:private kp-r) enc :bad-encapsulation)]
      (if (not= :ok (:status de))
        de
        (let [ds (dh (:private kp-r) pk-s :bad-sender-key)]
          (if (not= :ok (:status ds))
            ds
            {:status :ok
             :shared-secret (extract-and-expand
                             (vec (concat (:bytes de) (:bytes ds)))
                             (vec (concat enc (:public kp-r) pk-s)))}))))))
