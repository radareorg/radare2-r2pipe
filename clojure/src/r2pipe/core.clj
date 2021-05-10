(ns r2pipe.core
  (:require [r2pipe.proto :as proto]
            [r2pipe.spawn :as spawn]
            [r2pipe.tcp :as tcp]
            [r2pipe.http :as http]

            [clojure.string :as string])
  (:import [java.net URI]))

;; Define the default path for r2 to load.
(def r2-path "/usr/bin/r2")

;; Define core instance
(def r2-instance nil)

(defn configure-path
  "Configure the r2 path."
  [path]
  (def r2-path path))

(defn parse-r2pipe-url
  "Parse r2pipe URL"
  [url]
  (let [url-parsed (URI. url)]
    {:url url
     :scheme (keyword (.getScheme url-parsed))
     :server-name (.getHost url-parsed)
     :server-port (.getPort url-parsed)
     :uri (.getPath url-parsed)
     :user-info (.getUserInfo url-parsed)
     :query-string (.getRawQuery url-parsed)}))

(defn r2open
  "Open instance, according to url.

  Example urls:
  spawn:///./program.bin
  tcp://127.0.0.1:9090
  http://127.0.0.1:9090/cmd
  "
  [url]
  (let [parsed-url (parse-r2pipe-url url)]
    (def r2-instance
      (case (:scheme parsed-url)
        :spawn
        (spawn/r2open (string/replace-first (:uri parsed-url) "/" "") r2-path)
        :tcp
        (tcp/r2open (:server-name parsed-url) (:server-port parsed-url))
        :http
        (http/r2open (:url parsed-url))
        ;; default
        (ex-info "unsupported url" {:url url})))))

(defn cmd
  "Send command to the default r2 instance"
  [& cmds]
  (apply proto/cmd r2-instance cmds))

(defn cmdj
  "Send JSON command to the default r2 instance"
  [& cmds]
  (apply proto/cmdj r2-instance cmds))

(defn close
  "Closes default r2 pipe instance"
  []
  (.close r2-instance)
  (def r2-instance nil))
