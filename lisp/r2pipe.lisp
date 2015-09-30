;;; -*- encoding:utf-8 Mode: LISP; Syntax: COMMON-LISP; Base: 10  -*- ---
;; 
;; Filename: r2pipe.lisp
;; Description: 
;; Author: Jingtao Xu <jingtaozf@gmail.com>
;; Created: 2015.09.29 17:42:43(+0800)
;; Last-Updated: 2015.09.30 16:30:25(+0800)
;;     Update #: 38
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 
;;; Commentary: 
;; 
;; 
(in-package :cl-user)

(asdf:oos 'asdf:load-op :cl-json)

(defvar *r2-bin-path* "/usr/bin/r2")
(defun r2-read-pipe (pipe)
  (with-output-to-string (stream)
    (loop for c = (read-char pipe)
          until (= 0 (char-code c))
          do (write-char c stream))))

(defun r2pipe (file)
  (let ((pipe #-lispworks(error "r2pipe is not implemented for current lisp platform.")
              #+lispworks(sys:open-pipe `(,*r2-bin-path* "-q" "-0" ,file) :direction :io)))
    (values pipe (r2-read-pipe pipe))))

(defun r2-cmd (pipe cmd)
  (write-line (format nil "~a" cmd) pipe)
  (finish-output pipe)
  (r2-read-pipe pipe))

(defun r2-quit (pipe)
  (r2-cmd pipe "q!"))

(defun r2-json (str)
  (json:decode-json-from-string
   (with-output-to-string (*standard-output*)
     (with-input-from-string (*standard-input* str)
       (loop for c = (read-char *standard-input* nil nil) then (read-char *standard-input* nil nil)
             until (null c)
             unless (find c '(#\Newline #\Return))
               do (write-char c))))))
