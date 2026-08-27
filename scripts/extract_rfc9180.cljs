(ns extract-rfc9180
  "Extract RFC 9180 Appendix A.2 — DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20Poly1305 — into `test/hpke/rfc9180_a2.cljc`.

  A.2 is this library's suite exactly, and it publishes all four modes. So the
  vectors are the RFC's rather than another implementation's, for every mode.

  ## Why this is a script and not a hand-transcription

  An earlier draft of this repository's test suite claimed its vectors were
  A.2 verbatim and they were not: the recalled `ikmR` was A.1's. The pairing
  happened to be internally consistent, so nothing caught it except an
  assertion on `pkRm`. Transcription is the step that failed, so it is the
  step that is now mechanical.

  Both A.1 and A.2 are extracted: they are the same KEM and KDF, and differ
  only in the AEAD, which makes them the cheapest possible check that the
  suite is a parameter rather than a constant.

  ## Why the input is pinned by hash

  A vector file regenerated from a different document is a different claim.
  If rfc-editor.org ever serves something else under this URL, this refuses
  rather than quietly rewriting the fixtures.

      curl -sSo rfc9180.txt https://www.rfc-editor.org/rfc/rfc9180.txt
      nbb scripts/extract_rfc9180.cljs rfc9180.txt

  The download is a separate step on purpose: a generator that reaches the
  network is a generator whose output depends on when it ran."
  (:require ["fs" :as fs]
            ["crypto" :as crypto]
            [clojure.string :as str]))

(def source-url "https://www.rfc-editor.org/rfc/rfc9180.txt")

(def source-sha256
  "sha256 of RFC 9180's plain-text rendering, measured 2026-08-27."
  "f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6")

(defn- sha256-hex [s]
  (-> (crypto/createHash "sha256") (.update s "utf8") (.digest "hex")))

;; ── the shape of the document ────────────────────────────────────────────────
;;
;; Every value is `name: hex`, where the hex may be empty on that line and
;; continue, indented, on the ones after it. A line that itself matches
;; `name:` ends the previous value — which is why continuation is detected by
;; "does not look like a key" rather than by indentation, since the keys are
;; indented too.

(def ^:private key-line #"^\s{2,}([A-Za-z_][A-Za-z0-9_ ]*):\s*(.*)$")
(def ^:private hex-line #"^\s*([0-9a-f]+)\s*$")

(defn- parse-fields
  "Fold a block of lines into an ordered vector of [key value] pairs.

  A vector rather than a map: the Encryptions blocks repeat `sequence number`
  and the Exported Values blocks repeat `exporter_context`, and a map would
  silently keep only the last of each."
  [lines]
  (loop [[l & more] lines out [] cur nil]
    (cond
      (nil? l) (if cur (conj out cur) out)
      :else
      (if-let [[_ k v] (re-matches key-line l)]
        (recur more (if cur (conj out cur) out) [(str/trim k) (str/trim v)])
        (if-let [[_ hx] (and cur (re-matches hex-line l))]
          (recur more out (update cur 1 str hx))
          (recur more (if cur (conj out cur) out) nil))))))

(defn- section-lines
  "The lines of `heading` up to the next heading at any level."
  [lines heading]
  (let [start (first (keep-indexed #(when (str/starts-with? %2 heading) %1) lines))]
    (when-not start
      (throw (ex-info (str "section not found: " heading) {:heading heading})))
    (->> (drop (inc start) lines)
         (take-while #(not (re-matches #"^A\.\d+(\.\d+)*\.\s.*$" %))))))

(defn- pairs->map [pairs] (into {} pairs))

(defn- encryptions
  "Split the repeated `sequence number` groups apart."
  [pairs]
  (->> pairs
       (partition-by #(= "sequence number" (first %)))
       (partition 2)
       (map (fn [[[[_ n]] rest]] (assoc (pairs->map rest) "sequence number" n)))))

(defn- exports [pairs]
  (->> pairs
       (partition-by #(= "exporter_context" (first %)))
       (partition 2)
       (map (fn [[[[_ c]] rest]] (assoc (pairs->map rest) "exporter_context" c)))))

(defn- mode-section [lines app n]
  (let [setup (pairs->map (parse-fields (section-lines lines (str "A." app "." n ".  "))))
        encs (encryptions (parse-fields (section-lines lines (str "A." app "." n ".1.  "))))
        exps (exports (parse-fields (section-lines lines (str "A." app "." n ".2.  "))))]
    (assoc setup
           "encryptions" (vec encs)
           "exports" (vec exps))))

(defn- kw [s] (keyword (str/replace (str/lower-case s) #"[ _]" "-")))

(defn- emit-value [v]
  (cond (vector? v) (str "[" (str/join "\n     " (map emit-value v)) "]")
        (map? v) (str "{" (str/join " " (mapcat (fn [[k x]] [(pr-str (kw k)) (emit-value x)]) v)) "}")
        :else (pr-str v)))

(defn -main [& args]
  (let [path (first args)
        _ (when-not path
            (println "usage: nbb scripts/extract_rfc9180.cljs <rfc9180.txt>")
            (println "  curl -sSo rfc9180.txt" source-url)
            (js/process.exit 2))
        text (str (fs/readFileSync path "utf8"))
        got (sha256-hex text)]
    (when (not= got source-sha256)
      (println "REFUSING: RFC 9180 text sha256 mismatch")
      (println "  expected" source-sha256)
      (println "  got     " got)
      (js/process.exit 2))
    (let [lines (str/split-lines text)
          section (fn [app] (into {} (map (fn [[k n]] [k (mode-section lines app n)])
                                          {:base 1 :psk 2 :auth 3 :auth-psk 4})))
          modes {:a1 (section 1) :a2 (section 2)}
          _ (doseq [[app ms] modes
                    [m data] ms]
              (println (name app) (name m)
                       "fields=" (count data)
                       "encryptions=" (count (get data "encryptions"))
                       "exports=" (count (get data "exports"))))
          out (str ";; GENERATED by scripts/extract_rfc9180.cljs — do not edit.\n"
                   ";;\n"
                   ";; RFC 9180 Appendices A.1 and A.2 — DHKEM(X25519, HKDF-SHA256),\n"
                   ";; HKDF-SHA256, with AES-128-GCM (:a1) and ChaCha20Poly1305 (:a2).\n"
                   ";; All four modes of each, verbatim.\n"
                   ";;\n"
                   ";; Source:  " source-url "\n"
                   ";; sha256:  " source-sha256 "\n"
                   "(ns hpke.rfc9180-a2)\n\n"
                   ";; :a2 is kept at the top level as `vectors` for the suite that was\n"
                   ";; here first; `by-appendix` carries both.\n"
                   "(def by-appendix\n  "
                   (str "{" (str/join "\n\n   "
                                      (map (fn [[app ms]]
                                             (str (pr-str app) "\n   "
                                                  (str "{" (str/join "\n\n    "
                                                                     (map (fn [[m data]]
                                                                            (str (pr-str m) "\n    " (emit-value data)))
                                                                          ms)) "}")))
                                           modes)) "})")
                   "\n\n(def vectors (:a2 by-appendix))\n")]
      (fs/mkdirSync "test/hpke" #js {:recursive true})
      (fs/writeFileSync "test/hpke/rfc9180_a2.cljc" out)
      (println "wrote test/hpke/rfc9180_a2.cljc" (count out) "bytes"))))

(apply -main *command-line-args*)
