(in-package :cl-163-music)

;;;;网易云登录

;;;固定参数配置
(defvar *login-url* "http://music.163.com/weapi/login/")
(defvar *modulus* "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7")
(defvar *nonce* "0CoJUm6Qyw8W8jud")
(defvar *pub-key* "010001")

;;;;登录整体思路
;    text = {
;        username: xx,
;        password: md5(xx),
;        rememberLogin: true
;    }
;    
;    sec-key = random-secret-key (16)
;    
;    enc-text = aes(aes(text, nonce), sec-key)
;    enc-sec-key = rsa(sec-key, pub-key, modulus)
;
;    http request
;    post parameters:
;        params = enc-text
;        encSecKey = enc-sec-key

(defun string+ (&rest s)
  (apply #'concatenate 'string s))

(defun md5 (str)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence
    :md5    
    (ironclad:ascii-string-to-byte-array str))))

(defun create-secret-key (&optional (length 16))
  (cond ((or (< length 0) (> length 32)) (error "Illegal length. Need [0 - 32]"))
	(t (let ((string "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
	   (labels ((random-string ()
		      (string (char string (random (length string)))))
		    (create (depth)
		      (if (= 0 depth)
			  (random-string)
			  (string+ (random-string) (create (- depth 1))))))
	     (create (- length 1)))))))

(defun aes-padding (text)
  (let* ((pad-num (- 16 (mod (length text) 16)))
	(str (string (code-char pad-num))))
    (labels ((fn (depth)
	       (if (= 0 depth)
		   str
		   (string+ str (fn (- depth 1))))))
      (string+ text (fn (- pad-num 1))))))

(defun add-padding (enc-text modulus)
  (let ((ml (length modulus)))
    (labels ((calc-num (num i)
	       (if (and (> num 0) (char= #\0 (aref modulus i)))
		   (calc-num (- num 1) (+ i 1))
		   (- num (length enc-text))))
	     (res-str (i)
	       (if (= i 0)
		   enc-text
		   (string+ "0" (res-str (- i 1))))))
      (res-str (calc-num ml 0)))))
