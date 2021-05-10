(ns r2pipe.spawn
  (:require [r2pipe.proto :as r2p]
            
            [me.raynes.conch.low-level :as sh]))

(def cmd-delim (char 0))

(deftype R2Spawn [proc]
  r2p/R2Proto
  (r2-read [this]
    "Read from the r2 process"
    (apply str
           (take-while
            (fn [c] (not (= c (str cmd-delim))))
            (repeatedly
             #(-> proc :out .read char str)))))
  
  (r2-write [this input]
    "Write to the r2 process"
    (.write (:in proc) (.getBytes (str input "\n")))
    (.flush (:in proc)))
  
  (close [this]
    "Close r2 process"
    (-> proc :process .destroy)
    (:process proc)))

(defn r2open
  "Opens a file in r2 and starts a process instance"
  [filename r2-path]
  (let [proc (sh/proc r2-path
                      "-q0" "-e" "scr.utf8=false"
                      (str filename))
        p (R2Spawn. proc)]
    (.r2-read p) ;; first prompt must go
    p))
