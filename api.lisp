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

(defun mail-login (username password))


;;;; 每日签到
; curl 'http://music.163.com/weapi/point/dailyTask?csrf_token=b6ca3d80323560a81fb83c3509bb3a17' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Encoding: gzip, deflate' -H 'Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3' -H 'Connection: keep-alive' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: visited=true; __utma=94650624.1753221833.1463477851.1463728608.1464154273.13; __utmz=94650624.1463477851.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); __csrf=b6ca3d80323560a81fb83c3509bb3a17; usertrack=c+5+hlc8SDZD1jXDA1ZiAg==; _ntes_nnid=2fbef6f21a72307144f271b21a0076c4,1463568440526; Province=0; City=0; _ntes_nuid=2fbef6f21a72307144f271b21a0076c4; _ga=GA1.2.1955364583.1463568441; NETEASE_WDA_UID=32388043#|#1407163666227; JSESSIONID-WYYY=199c27ab9c554dd66913328de7a10d1df124cea8587657a9e6e03c297de01b0fe275562ee64b9c0fe75d48e4f70b90bc94df59a83555c95c98a0ee0bb2a27ff64d988a7f8ff0aba37b14d46c09ad5110b178f4ba5593520c6a0d16a1ffa3f3672798be4f3d6fd311a3ee94b7b69740f77f6bb65b06bf48a5748db25ad95b6c76129fcf68%3A1464156070551; _iuqxldmzr_=25; __utmb=94650624.3.10.1464154273; __utmc=94650624; __remember_me=true; MUSIC_U=6b470c1bc434f60e99dcb9d14e06692f1002c49c1ed319e878c7fe98cbb7825a07323d6b500f9f0858b91e9df94b352c5d6875572a075826c3061cd18d77b7a0' -H 'Host: music.163.com' -H 'Referer: http://music.163.com/discover' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:46.0) Gecko/20100101 Firefox/46.0' --data 'params=QJ1tTizoKR%2BJcPXpde%2B9UWzY4XnJrKEZSkXxRZviwGK0Bp7BoJdQ41q1iDYDWpgEjVM%2BWB2di6TzB2HWLMC%2F5QODSyauHKEjpdR%2B7iDN4vl%2BBB6bfBMl3yZv6OCodNZU&encSecKey=bc162b620d7e07b918c1c680f8a38dca08893c007918ad597c1d850f70c32472440525a76824a40bbdcb9e498ba74b13ffaba5f887870983e42928ddd39016042c684cb0f7ebc0531a51769388dc8908dba3c3b2e09e0e045ba5593986b0e59a885a8cb3c245b272c4f2d736ec0713f3334be05e9a5242cc2e78a059a640342b'
