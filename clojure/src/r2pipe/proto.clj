(ns r2pipe.proto
    (:require [clojure.string :as string]
              [cheshire.core :refer :all]))

(def deny-inquiry true)

(defn set-deny-inquiry
  [deny]
  (def deny-inquiry deny))

(defprotocol R2Proto
  (r2-read [this])
  (r2-write [this input]) ; will specific serialization be required?
  (close [this]))

(defn cmd [this & cmds]
  "Generic function to send to an R2 pipe a command"
  (let [cmd (first (string/split (first cmds) #"\s+"))
        msg (string/join " " cmds)]
    (if (and deny-inquiry (string/includes? cmd "?"))
      (throw (ex-info "inquiry command" {:cmd cmd :cmds cmds})))
    (.r2-write this msg)
    (.r2-read this)))

(defn cmdj [this & cmds]
  "Generic function to send to an R2 pipe a command and receive a JSON"
  (let [cmd (first (string/split (first cmds) #"\s+"))
        msg (string/join " " cmds)]
    (if (and deny-inquiry (string/includes? cmd "?"))
      (throw (ex-info "inquiry command" {:cmd cmd :cmds cmds})))
    (if (not (string/ends-with? cmd "j"))
      (throw (ex-info "not a json command" {:cmd cmd :cmds cmds})))
    (.r2-write this msg)
    (parse-string (.r2-read this) true)))
