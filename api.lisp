(in-package :cl-163-music)

(defun square (x)
  (* x x))

(defun fast-expt (base exponent)
  "base ^ power"
  (labels ((expt-iter (b e a)
	     (cond ((= e 0) a)
		   ((evenp e) (expt-iter (square b) (/ e 2) a))
		   (t (expt-iter b (- e 1) (* b a))))))
    (expt-iter base exponent 1)))

(defun expt-mod (base exponent modulus)
  "As (mod (expt base exponent) modulus), but more efficient.
^表示幂运算  %表示取余 
1. (x * y) % m = (x * (y % m)) % m = ((x % m) * (y % m)) % m
2. (x ^ y) % m = ((x % m) ^ y) % m

e.g.
(evenp n) => t
x^n % m ==> (x^(n / 2))^2 % m ==> (x^(n / 2) % m)^2 % m
(evenp n) => nil
x^n % m ==> (x * x^(n - 1)) % m ==> (x * (x^(n - 1) % m)) % m
"
  (if (= exponent 0)
      1
      (if (evenp exponent)
	  (mod (square (expt-mod base (/ exponent 2) modulus)) modulus)
	  (mod (* base (expt-mod base (- exponent 1) modulus)) modulus))))


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
    (add-padding (write-to-string (expt-mod n-text n-pubkey n-modulus) :base 16) modulus)))

(defun encrypt-info (&rest lst)
  (let ((table (make-hash-table :size (length lst)))
	(sec-key (create-secret-key))
	(nonce "0CoJUm6Qyw8W8jud")
	(pubkey "010001")
	(modulus "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"))
    (dotimes (i (length lst))
      (let ((e (nth i lst)))
	(setf (gethash (car e) table) (cdr e))))
    (let* ((text (with-output-to-string (stream) (yason:encode table stream)))
	   (enc-text (aes-cbc-encrypt (aes-cbc-encrypt text nonce) sec-key))
	   (enc-sec-key (rsa-encrypt sec-key pubkey modulus)))
      (list (cons "params" enc-text)
	    (cons "encSecKey" (string-downcase enc-sec-key))))))

(defun encrypt-user-account (username password &optional (remember "true"))
  (encrypt-info `("username" . ,username)
		`("password" . ,(md5 password))
		`("rememberLogin" . ,remember)))


;;;;网易云登录

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

(defun mail-login (username password)
  "
项目最终目的就是想实现自动签到
目前只需要cookie就够了
捕捉: 返回信息(目前暂时将json转为plist)/http状态码/和cookie集合
"
  (let ((cookie-jar (make-instance 'drakma:cookie-jar)))
    (multiple-value-bind (stream http-code)
	(drakma:http-request "http://music.163.com/weapi/login/"
			     :method :post
			     :user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:46.0) Gecko/20100101 Firefox/46.0"
			     :accept "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
			     :content-type "application/x-www-form-urlencoded"
			     ;对于请求头 如果已有关键字选项 就不能放入additional-headers
			     :additional-headers '(("Host" . "music.163.com")
						   ("Referer" . "http://music.163.com")
						   ("Accept-Language" . "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3")
						   ("Accep:at-Encoding" . "gzip, deflate"))
			     :parameters (encrypt-user-account username password)
			     :external-format-in :utf8
			     :external-format-out :utf8
			     :want-stream t
			     :cookie-jar cookie-jar)
      ;(setf (flexi-streams:flexi-stream-external-format stream) :utf8)
      ;(values (yason:parse stream :object-as :plist) http-code cookie-jar)
      (values stream http-code cookie-jar))))


;;;; 每日签到
(defun daily-sign-with-cookie (cookie-jar &optional (type 0))
  (multiple-value-bind (stream http-code)
      (drakma:http-request "http://music.163.com/weapi/point/dailyTask"
			   :method :post
			   :user-agent " Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:46.0) Gecko/20100101 Firefox/46.0"
			   :accept "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
			   :content-type "application/x-www-form-urlencoded"
			   :additional-headers '(("Host" . "music.163.com")
						 ("Referer" . "http://music.163.com/discover")
						 ("Accept-Language" . "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3")
						 ("Accep:at-Encoding" . "gzip, deflate"))
			   :parameters (encrypt-info `("type" . ,type))
			   :external-format-in :utf8
			   :external-format-out :utf8
			   :want-stream t
			   :cookie-jar cookie-jar)
    ;(setf (flexi-streams:flexi-stream-external-format stream) :utf8)
    ;(values (yason:parse stream :object-as :plist) http-code)
    (values stream http-code)))

(defun daily-sign (username password)
  (multiple-value-bind (stream http-code cookie-jar)
      (mail-login username password)
    (if (= http-code 200)
	(let ((m (daily-sign-with-cookie cookie-jar 0))
	      (w (daily-sign-with-cookie cookie-jar 1)))
	  (setf (flexi-streams:flexi-stream-external-format m) :utf8)
	  (setf (flexi-streams:flexi-stream-external-format w) :utf8)
	  (values (format nil "mobile daily sign: ~a" (yason:parse m :object-as :plist))
		  (format nil "web daily sign: ~a" (yason:parse w :object-as :plist)))))))
