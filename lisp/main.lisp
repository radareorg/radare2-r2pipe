;;; -*- encoding:utf-8 Mode: LISP; Syntax: COMMON-LISP; Base: 10  -*- ---
;; 
;; Filename: main.lisp
;; Description: 
;; Author: Jingtao Xu <jingtaozf@gmail.com>
;; Created: 2015.09.29 17:43:05(+0800)
;; Last-Updated: 2015.09.30 16:33:26(+0800)
;;     Update #: 6
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 
;;; Commentary: 
;; 
;; 
;;(load "r2pipe.lisp")
(setf pipe (r2pipe "/bin/bash"))
(format t "~s~%" (r2-cmd pipe "pi 5"))
(format t "~s~%" (r2-json (r2-cmd pipe "pij 1")))
(format t "~s~%" (r2-cmd pipe "px 64"))
(r2-quit pipe)
