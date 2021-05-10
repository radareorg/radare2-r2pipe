(ns r2pipe.tcp
  (:refer-clojure :exclude [read-string])
  (:require [r2pipe.proto :as r2p])
  (:import [java.net Socket]))

(def cmd-delim -1)

(defrecord TCPClient [host port socket])

(defn- is-connected? [^TCPClient client] (-> client :socket nil? not))

;; this would be nice to async ;) todo: create a pool
(defn- connect [^TCPClient client]
  "Connect the client to a new TCP stream"
  (if (is-connected? client)
    (do
      (ex-info "connection already in progress" {:client client})
      client)
    (assoc client :socket (Socket. (:host client) (:port client)))))

(defn- disconnect [^TCPClient client]
  "Disconnect the client from the TCP stream"
  (if (-> client :socket nil? not)
    (do
      (-> client :socket .close)
      (assoc client :socket nil))
    client))

(deftype R2TCP [^TCPClient ^:volatile-mutable client]
  r2p/R2Proto
  (r2-read [this]
    "Read from the r2 TCP stream"
    (if (is-connected? client)
      (let [s-out (-> client :socket .getInputStream)
            output
            (apply
             str
             (map (fn [c] (char c))
                  (take-while
                   (fn [c] (not (= c cmd-delim)))
                   (repeatedly
                    #(-> s-out .read)))))]
        (.close this)
        output)
      nil))
  
  (r2-write [this input]
    "Write to the r2 TCP stream"
    (set! client (connect client))
    (let [s-in (-> client :socket .getOutputStream)]
      (.write s-in (.getBytes (str input "\n")))
      (.flush s-in)))
  
  (close [this]
    "Close r2 TCP connection, if possible"
    (set! client (disconnect client))))

(defn r2open
  "Creates the TCP connection client"
  [host port]
  (R2TCP. (->TCPClient host port nil)))
