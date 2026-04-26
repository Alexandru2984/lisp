(in-package :cl-user)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (ql:quickload :hunchentoot))

(defpackage :safe-sandbox
  (:use) ; Do not use CL! We will import only safe symbols.
  (:import-from :cl
                :+ :- :* :/ := :< :> :<= :>= :/=
                :1+ :1- :abs :max :min :mod :rem
                :sin :cos :tan :exp :log :sqrt
                :car :cdr :cons :list :append :length
                :mapcar :mapc :reduce :remove :remove-if :remove-if-not
                :format :print :princ :prin1 :terpri
                :defun :let :let* :if :cond :when :unless :case
                :lambda :funcall :apply :progn :loop :dotimes :dolist
                :t :nil
                :string :string= :string-equal :concatenate
                :make-array :aref
                :math-error :type-error)
  (:export :safe-eval :redefine-function :get-functions))

(in-package :cl-user)

;; Safe Evaluator Setup
(defvar *sandbox-package* (find-package :safe-sandbox))

(defun safe-sandbox::safe-eval (expr)
  (let ((*package* *sandbox-package*)
        (*read-eval* nil))
    (eval expr)))

;; Application State
(defvar *custom-functions* (make-hash-table :test 'equal))

(defun safe-sandbox::redefine-function (name body)
  (let ((*package* *sandbox-package*)
        (*read-eval* nil))
    (eval `(defun ,(intern (string-upcase name) *sandbox-package*) () ,body))
    (setf (gethash name *custom-functions*) body)
    name))

(defun safe-sandbox::get-functions ()
  (let ((funcs nil))
    (maphash (lambda (k v)
               (push (cons k v) funcs))
             *custom-functions*)
    funcs))

;; Web Server Setup
(defvar *acceptor* nil)
(defvar *port* 8093)

(defun start-server ()
  (when *acceptor*
    (hunchentoot:stop *acceptor*))
  (setf *acceptor* (make-instance 'hunchentoot:easy-acceptor
                                  :port *port*
                                  :access-log-destination "/home/micu/commonLisp/lisp-app/logs/access.log"
                                  :message-log-destination "/home/micu/commonLisp/lisp-app/logs/message.log"))
  (hunchentoot:start *acceptor*)
  (format t "Server started on port ~a~%" *port*))

;; Basic Auth logic
(defun check-auth ()
  (multiple-value-bind (user pass)
      (hunchentoot:authorization)
    (unless (and (equal user "admin") (equal pass "admin"))
      (hunchentoot:require-authorization "Lisp App"))))

;; Handlers
(hunchentoot:define-easy-handler (home-page :uri "/") ()
  (check-auth)
  (setf (hunchentoot:content-type*) "text/html")
  (format nil "<html>
<head><title>Self-Modifying Lisp App</title>
<style>
body { font-family: sans-serif; margin: 40px; }
textarea { width: 100%; height: 100px; font-family: monospace; }
.container { max-width: 800px; margin: auto; }
</style>
</head>
<body>
<div class='container'>
  <h1>Lisp REPL (Safe Sandbox)</h1>
  <form action='/eval' method='POST'>
    <h3>Evaluate Expression</h3>
    <textarea name='expr'></textarea><br>
    <button type='submit'>Evaluate</button>
  </form>

  <form action='/redefine' method='POST'>
    <h3>Redefine Function</h3>
    Function Name: <input type='text' name='name'><br>
    Function Body: <textarea name='body'></textarea><br>
    <button type='submit'>Redefine</button>
  </form>

  <h3>Current Functions</h3>
  <ul>
    ~{<li><b>~a</b>: <code>~a</code></li>~}
  </ul>
</div>
</body></html>"
          (loop for (k . v) in (safe-sandbox:get-functions)
                append (list k v))))

(hunchentoot:define-easy-handler (eval-handler :uri "/eval") (expr)
  (check-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (let* ((*package* *sandbox-package*)
             (*read-eval* nil)
             (form (read-from-string expr))
             (result (safe-sandbox:safe-eval form)))
        (format nil "Result: ~a" result))
    (error (c)
      (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (redefine-handler :uri "/redefine") (name body)
  (check-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (let* ((*package* *sandbox-package*)
             (*read-eval* nil)
             (body-form (read-from-string body)))
        (safe-sandbox:redefine-function name body-form)
        (format nil "Successfully redefined ~a" name))
    (error (c)
      (format nil "Error: ~a" c))))

;; Wait forever for systemd
(start-server)
(loop (sleep 3600))
