(in-package :cl-user)

;(ql:quickload '("drakma"
;		"yason"
;		"flexi-streams"
;		"cl-base64"
;		"ironclad"))

(defpackage #:cl-163-music-asd
  (:use :cl :asdf))

(in-package #:cl-163-music-asd)

(defsystem :cl-163-music
  :version "0.0.1"
  :description "163 music"
  :author "tskshy<tanshuaitskshy@gmail.com>"
  :license "MIT"
  :serial t
  :depends-on (#:cl-ansi-term
	       #:drakma
	       #:yason
	       #:flexi-streams
	       #:cl-base64
	       #:ironclad)
  :components ((:file "package")
	       (:file "api")))
