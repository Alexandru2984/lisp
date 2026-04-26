(in-package :cl-user)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (ql:quickload '(:hunchentoot :alexandria :cl-json)))

(load "/home/micu/lisp/lisp-app/config/config.lisp")

(defpackage :safe-sandbox
  (:use)
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
                :arithmetic-error :type-error :error :condition)
  (:export :safe-eval :redefine-function :get-functions :restore-functions))

(in-package :cl-user)

(defvar *sandbox-package* (find-package :safe-sandbox))
(defvar *custom-functions* (make-hash-table :test 'equal))

(defun save-functions ()
  (with-open-file (out *data-file*
                       :direction :output
                       :if-exists :supersede
                       :if-does-not-exist :create)
    (let ((data nil))
      (maphash (lambda (k v) (push (list k v) data)) *custom-functions*)
      (format out "~S" data))))

(defun safe-sandbox:redefine-function (name body &optional (skip-save nil))
  (let ((*package* *sandbox-package*)
        (*read-eval* nil))
    (eval `(defun ,(intern (string-upcase name) *sandbox-package*) () ,body))
    (setf (gethash name *custom-functions*) body)
    (unless skip-save (save-functions))
    name))

(defun safe-sandbox:restore-functions ()
  (when (probe-file *data-file*)
    (with-open-file (in *data-file*)
      (let ((data (read in nil)))
        (dolist (item data)
          (destructuring-bind (name body) item
            (safe-sandbox:redefine-function name body t)))))))

(defun safe-sandbox:get-functions ()
  (let ((funcs nil))
    (maphash (lambda (k v) 
               (push (cl-json:make-object (list (cons "name" k) (cons "body" (format nil "~S" v))) nil) funcs))
             *custom-functions*)
    funcs))

(defun safe-sandbox:safe-eval (expr)
  (let ((*package* *sandbox-package*)
        (*read-eval* nil))
    (sb-ext:with-timeout *eval-timeout*
      (eval expr))))

(defvar *acceptor* nil)
(defvar *port* 8093)

(defun check-auth ()
  (multiple-value-bind (user pass) (hunchentoot:authorization)
    (unless (and (equal user *auth-user*) (equal pass *auth-pass*))
      (hunchentoot:require-authorization "Lisp Sandbox"))))

(hunchentoot:define-easy-handler (home-page :uri "/") ()
  (check-auth)
  (setf (hunchentoot:content-type*) "text/html")
  (format nil "<!DOCTYPE html>
<html lang='en' data-theme='dark'>
<head>
    <meta charset='UTF-8'>
    <title>Lisp Control Center</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css'>
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css'>
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/monokai.min.css'>
    <style>
        .CodeMirror { height: 150px; border-radius: 4px; margin-bottom: 1rem; border: 1px solid #333; }
        pre#result { background: #1a1a1a; padding: 1rem; border-radius: 4px; min-height: 50px; border: 1px solid #333; white-space: pre-wrap; word-break: break-all; }
        .func-item { border-bottom: 1px solid #333; padding: 0.5rem 0; }
        .container { margin-top: 2rem; }
    </style>
</head>
<body>
    <main class='container'>
        <h1>λ Lisp Self-Modifying Service</h1>
        <div class='grid'>
            <section>
                <h3>Safe REPL</h3>
                <textarea id='eval-editor'>(+ 1 2 3)</textarea>
                <button onclick='doEval()'>Run Expression</button>
                <label>Output:</label>
                <pre id='result'>Ready.</pre>
            </section>
            <section>
                <h3>Redefine Function</h3>
                <input type='text' id='func-name' placeholder='function-name'>
                <textarea id='func-editor'>(format nil \"Hello from ~~a\" \"Lisp\")</textarea>
                <button class='secondary' onclick='doRedefine()'>Save & Define</button>
            </section>
        </div>
        <hr>
        <section id='functions-list'>
            <h3>Runtime Functions</h3>
            <div id='functions-container'>Loading...</div>
        </section>
    </main>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js'></script>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/commonlisp/commonlisp.min.js'></script>
    <script>
        const evalEditor = CodeMirror.fromTextArea(document.getElementById('eval-editor'), { mode: 'commonlisp', theme: 'monokai', lineNumbers: true });
        const funcEditor = CodeMirror.fromTextArea(document.getElementById('func-editor'), { mode: 'commonlisp', theme: 'monokai', lineNumbers: true });
        async function doEval() {
            const res = await fetch('/api/eval', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({expr: evalEditor.getValue()})
            });
            document.getElementById('result').innerText = await res.text();
        }
        async function doRedefine() {
            const name = document.getElementById('func-name').value;
            if (!name) { alert('Name required!'); return; }
            const res = await fetch('/api/redefine', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({name: name, body: funcEditor.getValue()})
            });
            alert(await res.text());
            loadFunctions();
        }
        async function loadFunctions() {
            const res = await fetch('/api/functions');
            const data = await res.json();
            const container = document.getElementById('functions-container');
            container.innerHTML = data.map(f => \"<div class='func-item'><strong>\"+f.name+\"</strong>: <code>\"+f.body+\"</code></div>\").join('') || 'No custom functions defined.';
        }
        loadFunctions();
    </script>
</body>
</html>"))

(hunchentoot:define-easy-handler (api-eval :uri "/api/eval") (expr)
  (check-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (let* ((*package* *sandbox-package*)
             (*read-eval* nil)
             (form (read-from-string expr))
             (result (safe-sandbox:safe-eval form)))
        (with-open-file (log "/home/micu/lisp/lisp-app/logs/evaluations.log" :direction :output :if-exists :append :if-does-not-exist :create) (format log "[~a] EVAL: ~S => ~S~%" (get-universal-time) expr result))
        (format nil "~S" result))
    (sb-ext:timeout () "Error: Evaluation timed out!")
    (error (c) (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (api-redefine :uri "/api/redefine") (name body)
  (check-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (let* ((*package* *sandbox-package*)
             (*read-eval* nil)
             (body-form (read-from-string body)))
        (safe-sandbox:redefine-function name body-form)
        (format nil "Function '~a' defined successfully." name))
    (error (c) (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (api-functions :uri "/api/functions") ()
  (check-auth)
  (setf (hunchentoot:content-type*) "application/json")
  (cl-json:encode-json-to-string (safe-sandbox:get-functions)))

(defun start-server ()
  (safe-sandbox:restore-functions)
  (setf *acceptor* (make-instance 'hunchentoot:easy-acceptor
                                  :port *port*
                                  :access-log-destination "/home/micu/lisp/lisp-app/logs/access.log"
                                  :message-log-destination "/home/micu/lisp/lisp-app/logs/message.log"))
  (hunchentoot:start *acceptor*)
  (format t "Server started on port ~a~%" *port*))

(start-server)
(loop (sleep 3600))
