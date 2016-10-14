(ns r2pipe.core
    (:refer-clojure :exclude [read-string])
    (:require [me.raynes.conch.low-level :as sh]
              [clojure.java.io :as io]))

;; Define the default path for r2 to load.
(def r2path "/usr/bin/r2")

(defn configure-path
  "Confgiure the r2 path."
  [path]
  (def r2path path))

(defn r2open
  "Opens a file in r2 and starts a process instance"
  [input_file]
  (def pipe (sh/proc r2path "-q0" (str input_file))))

(defn r2print
  "Read from the r2 process(pipe) and print."
  []
  (dotimes [i (.available (get pipe :out))] (print (str (char (.read (get pipe :out)))))))

(defn r2write
  "Write to the r2 process"
  [input]
  (.write (get pipe :in) (.getBytes (str input "\n")))
  (.flush (get pipe :in)))

(defn r2string
  "Returns a string representation of the output shown by radare2"
  []
  (apply str (repeatedly (.available (get pipe :out)) #(str (char (.read (get pipe :out)))))))

(defn r2cmd
  "Runs an r2 command and returns the result as a string"
  [input]
  (do
      (r2write input)
      ;; 1337 hax! This is to offset the latency created due to stream buffering.
      (Thread/sleep 1)
      (r2string)))
