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
    ;(ironclad:ascii-string-to-byte-array str)
    (flexi-streams:string-to-octets str :external-format :utf8))))

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

(defun convert-utf8-to-hex (str)
  (let* ((arr (flexi-streams:string-to-octets str :external-format :utf8))
	 (len (length arr))
	 (radix 16))
    (labels ((convert (arr index str-hex)
	       (if (= index (- len 1))
		   (concatenate 'string
				str-hex
				(write-to-string (aref arr index) :base radix))
		   (convert arr
			    (+ 1 index)
			    (concatenate 'string
					 str-hex
					 (write-to-string (aref arr index)
							  :base radix))))))
      (convert arr 0 nil))))

(defun aes-cbc-encrypt (plaintext key &optional (iv "0102030405060708"))
  "
AES具体算法: AES-128-CBC, 输出格式: base64
默认初始化向量 0102030405060708
明文需要padding
"
  (let* ((cipher (ironclad:make-cipher 'ironclad:aes
				       :key (flexi-streams:string-to-octets key)
				       :mode 'ironclad:cbc
				       :initialization-vector (flexi-streams:string-to-octets iv)))
	 (ptp (aes-padding plaintext))
	 (ptp-byte-arr (flexi-streams:string-to-octets ptp :external-format :utf8))
	 (cipher-byte-arr (make-array (length ptp-byte-arr)
				      :initial-element 0
				      :element-type '(unsigned-byte 8))))
    (ironclad:encrypt cipher ptp-byte-arr cipher-byte-arr)
    (cl-base64:usb8-array-to-base64-string cipher-byte-arr)))

(defun rsa-encrypt (text pubkey modulus)
  "
RSA加密采用非常规填充方式(非PKCS1 / PKCS1_OAEP)
此处是向前补0
这样加密出来的密文有个特点：加密过程没有随机因素，明文多次加密后得到的密文是相同的
然而，我们常用的 RSA 加密模块均不支持此种加密，所以需要手写一段简单的 RSA 加密
加密过程 convertUtf8toHex(reversedText) ^ e % N
输入过程中需要对加密字符串进行 hex 格式转码
"
  (let ((n-text (parse-integer (convert-utf8-to-hex (reverse text)) :radix 16))
	(n-pubkey (parse-integer pubkey :radix 16))
	(n-modulus (parse-integer modulus :radix 16)))
    (add-padding (write-to-string (mod (expt n-text n-pubkey) n-modulus) :base 16) modulus)))

(defun encrypt-user-account (username password &optional (remember "true"))
  (let ((table (make-hash-table))
	(sec-key (create-secret-key)))
    (setf (gethash "username" table) username)
    (setf (gethash "password" table) (md5 password))
    (setf (gethash "rememberLogin" table) remember)
    (let* ((text (with-output-to-string (stream) (yason:encode table stream)))
	   (enc-text (aes-cbc-encrypt (aes-cbc-encrypt text *nonce*) sec-key))
	   (enc-sec-key (rsa-encrypt sec-key *pub-key* *modulus*)))
      (list (cons "params" enc-text)
	    (cons "encSecKey" (string-downcase enc-sec-key))))))

#+test
(defun encrypt-request (username password)
  "
SIMPLE TEST FUNCTION
"
  (let ((stream (drakma:http-request "http://music.163.com/weapi/login/"
				     :method :post
				     :user-agent " Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:46.0) Gecko/20100101 Firefox/46.0"
				     :accept "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
				     :content-type "application/x-www-form-urlencoded"
				     :additional-headers '(("Host" . "music.163.com")
							   ("Referer" . "http://music.163.com")
							   ("Accept-Language" . "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3")
							   ("Accep:at-Encoding" . "gzip, deflate"))
				     :parameters (encrypt-user-account username password)
				     :external-format-in :utf8
				     :external-format-out :utf8
				     :want-stream t)))
	(setf (flexi-streams:flexi-stream-external-format stream) :utf-8)
	(yason:parse stream :object-as :plist)))