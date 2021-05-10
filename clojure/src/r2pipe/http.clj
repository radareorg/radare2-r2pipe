(ns r2pipe.http
  (:refer-clojure :exclude [read-string])
  (:require [r2pipe.proto :as r2p]
            [clojure.string :as string]
            [clj-http.client :as client]))

(defrecord HTTPClientData [scheme server port base-uri last-response])

(deftype R2HTTP [^HTTPClientData ^:volatile-mutable client-data]
  r2p/R2Proto
  (r2-read [this]
    "Read last response of r2 HTTP server"
    (let [response (:last-response client-data)]
      (.close this)
      response))
  
  (r2-write [this input]
    "Write request r2 HTTP server"
    (let [full-uri
          (string/join `(~(:base-uri client-data)
                         ~(if (string/ends-with? (:base-uri client-data) "/") "" "/")
                         ~(client/url-encode-illegal-characters input)))
          full-url (client/unparse-url
                    {:scheme (:scheme client-data)
                     :server-name (:server client-data)
                     :server-port (:port client-data)
                     :uri full-uri})
          response (client/get full-url)]
      (if (not (= 200 (:status response)))
        (ex-info "request in error"
                 {:status (:status response)
                  :input input :url full-url
                  :response response}))
      (set! client-data (assoc client-data :last-response (:body response)))
      nil))
  
  (close [this]
    "Closes r2 HTTP client (does nothing really)"
    (set! client-data (assoc client-data :last-response nil))))

(defn r2open
  "Creates the HTTP connection client"
  [url]
  (let [parsed-url (client/parse-url url)]
    (R2HTTP. (->HTTPClientData
              (:scheme parsed-url)
              (:server-name parsed-url)
              (:server-port parsed-url)
              (:uri parsed-url)
              nil))))
