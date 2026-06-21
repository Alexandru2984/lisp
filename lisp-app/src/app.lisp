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
                :print :princ :prin1 :terpri
                :defun :let :let* :if :cond :when :unless :case :quote
                :lambda :funcall :apply :progn :loop :dotimes :dolist
                :t :nil
                :string :string= :string-equal :concatenate
                :arithmetic-error :type-error :error :condition)
  (:export :safe-eval :redefine-function :get-functions :restore-functions))

(in-package :cl-user)

(defvar *sandbox-package* (find-package :safe-sandbox))
(defvar *custom-functions* (make-hash-table :test 'equal))

;; --- SECURITY LAYER ---

;; Validate that every symbol in the AST belongs strictly to the sandbox or keywords.
;; This PREVENTS package-prefix attacks like (uiop:run-program "ls").
(defun safe-symbol-p (sym)
  (cond
    ((null (symbol-package sym)) t) ; uninterned symbols
    ((eq (symbol-package sym) (find-package :keyword)) t)
    ((typep sym 'boolean) t)
    (t (multiple-value-bind (found status) (find-symbol (symbol-name sym) *sandbox-package*)
         (and found (eq found sym))))))

;; AST Walker that deeply validates all forms before evaluation.
(defun safe-form-p (form &optional visited)
  (cond
    ((member form visited) (error "Security violation: Circular structures not allowed!"))
    ((symbolp form) (safe-symbol-p form))
    ((consp form)
     (and (safe-form-p (car form) (cons form visited))
          (safe-form-p (cdr form) (cons form visited))))
    (t t))) ; strings, numbers are natively safe

;; --- Safe FORMAT -------------------------------------------------------
;; cl:format's ~/name/ directive calls an arbitrary function whose name comes
;; from the *control string* (not from a symbol the AST walker can see), and
;; ~? recursively formats with a control string taken from the arguments.
;; Both bypass the symbol whitelist, so the sandbox exposes this wrapper
;; instead of cl:format and refuses those two directives.
(defun format-directive-chars (control)
  "List the dispatch character of every ~ directive in CONTROL, skipping
prefix parameters and the : @ modifiers."
  (let ((chars '()) (i 0) (n (length control)))
    (loop while (< i n) do
      (cond
        ((char= (char control i) #\~)
         (incf i)
         (loop while (< i n) do
           (let ((c (char control i)))
             (cond
               ((char= c #\') (incf i 2))   ; 'x quoted-char parameter
               ((or (digit-char-p c)
                    (member c '(#\, #\: #\@ #\- #\+ #\# #\v #\V)))
                (incf i))
               (t (return)))))
         (when (< i n)
           (push (char-downcase (char control i)) chars)
           (incf i)))
        (t (incf i))))
    (nreverse chars)))

(defun format-control-safe-p (control)
  (notany (lambda (d) (member d '(#\/ #\?))) (format-directive-chars control)))

(defun safe-sandbox::format (destination control &rest args)
  (unless (stringp control)
    (error "Sandbox: format control must be a string."))
  (unless (format-control-safe-p control)
    (error "Security violation: format ~~/ and ~~? directives are not allowed."))
  (apply #'cl:format destination control args))

(defun truncate-output (string)
  (if (> (length string) *max-output-bytes*)
      (concatenate 'string (subseq string 0 *max-output-bytes*) " ...[truncated]")
      string))

(defun render-result (result)
  "Print RESULT to a size-bounded string; guards against huge/deep/circular
output that could exhaust memory while printing."
  (let ((*print-circle* t)
        (*print-length* 10000)
        (*print-level* 100)
        (*package* *sandbox-package*)
        (*read-eval* nil))
    (truncate-output (prin1-to-string result))))

(defun save-functions ()
  (with-open-file (out *data-file*
                       :direction :output
                       :if-exists :supersede
                       :if-does-not-exist :create)
    (let ((data nil))
      (maphash (lambda (k v) (push (list k v) data)) *custom-functions*)
      (format out "~S" data))))

(defun safe-sandbox:redefine-function (name body &optional (skip-save nil))
  ;; Cap the name length before interning so we cannot be made to intern a
  ;; multi-megabyte symbol name.
  (when (or (null name) (> (length name) *max-name-length*))
    (error "Security violation: invalid or over-long function name!"))
  (let* ((*package* *sandbox-package*)
         (*read-eval* nil)
         (sym (intern (string-upcase name) *sandbox-package*)))
    ;; 1. Prevent redefining core Common Lisp features
    (when (eq (symbol-package sym) (find-package :cl))
      (error "Security violation: Cannot redefine standard Common Lisp symbols!"))
    ;; 2. Cap the number of stored functions (unbounded growth = DoS).
    (when (and (null (nth-value 1 (gethash name *custom-functions*)))
               (>= (hash-table-count *custom-functions*) *max-functions*))
      (error "Limit reached: too many stored functions!"))
    ;; 3. Prevent malicious code injection inside the function
    (unless (safe-form-p body)
      (error "Security violation: Unauthorized external symbols in function body!"))

    (eval `(defun ,sym () ,body))
    (setf (gethash name *custom-functions*) body)
    (unless skip-save (save-functions))
    name))

(defun safe-sandbox:restore-functions ()
  (when (probe-file *data-file*)
    (with-open-file (in *data-file*)
      ;; Never honour #. (read-eval) when loading persisted data.
      (let* ((*read-eval* nil)
             (data (read in nil)))
        (dolist (item data)
          (destructuring-bind (name body) item
            (handler-case
                (safe-sandbox:redefine-function name body t)
              (error (c) (format t "Failed to restore ~a: ~a~%" name c)))))))))

(defun safe-sandbox:get-functions ()
  (let ((funcs nil))
    (maphash (lambda (k v) 
               (push (cl-json:make-object (list (cons "name" k) (cons "body" (format nil "~S" v))) nil) funcs))
             *custom-functions*)
    funcs))

(defun safe-sandbox:safe-eval (expr)
  ;; Ensure we parse the string securely without #. macro support
  (unless (safe-form-p expr)
    (error "Security violation: Unauthorized external symbols detected!"))
  (let ((*package* *sandbox-package*)
        (*read-eval* nil))
    (sb-ext:with-timeout *eval-timeout*
      (eval expr))))


;; --- WEB SERVER LAYER ---

(defvar *acceptor* nil)
(defvar *port* 8093)

;; Compare two strings without an early-exit so the time taken does not
;; reveal how many leading characters matched (mitigates timing oracles
;; against the credentials).
(defun constant-time-equal (a b)
  (let* ((a (string (or a ""))) (b (string (or b "")))
         (la (length a)) (lb (length b))
         (acc (logxor la lb)))
    (dotimes (i (max la lb))
      (setf acc (logior acc
                        (logxor (if (< i la) (char-code (char a i)) 0)
                                (if (< i lb) (char-code (char b i)) 0)))))
    (zerop acc)))

;; Hunchentoot only marks the session cookie HttpOnly by default. Re-emit it
;; with Secure (HTTPS-only) and SameSite=Strict (blocks cross-site sends, a
;; baseline CSRF defence) once the user is authenticated.
(defun harden-session-cookie (session)
  (hunchentoot:set-cookie (hunchentoot:session-cookie-name hunchentoot:*acceptor*)
                          :value (hunchentoot:session-cookie-value session)
                          :path "/"
                          :http-only t
                          :secure t
                          :same-site "Strict"))

;; HTML Form Auth Handlers
(defun check-auth ()
  (unless (hunchentoot:session-value 'authenticated)
    (hunchentoot:redirect "/login" :add-session-id nil)))

(defun check-api-auth ()
  (unless (hunchentoot:session-value 'authenticated)
    (setf (hunchentoot:return-code*) 401)
    (hunchentoot:abort-request-handler "Unauthorized")))

(hunchentoot:define-easy-handler (login-page :uri "/login") (error)
  (setf (hunchentoot:content-type*) "text/html")
  (format nil "<!DOCTYPE html>
<html lang='en' data-theme='dark'>
<head>
    <meta charset='UTF-8'>
    <meta name='robots' content='noindex, nofollow'>
    <title>Login - Lisp Control Center</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css'>
    <style>
        body { display: flex; align-items: center; justify-content: center; height: 100vh; }
        .login-card { padding: 2rem; width: 100%; max-width: 400px; border: 1px solid #333; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.5); }
        .error { color: #ff6b6b; margin-bottom: 1rem; font-weight: bold; }
    </style>
</head>
<body>
    <div class='login-card'>
        <h2 style='text-align: center'>λ System Login</h2>
        ~a
        <form action='/do-login' method='POST'>
            <label>Username
                <input type='text' name='username' required>
            </label>
            <label>Password
                <input type='password' name='password' required>
            </label>
            <button type='submit'>Authenticate</button>
        </form>
    </div>
</body>
</html>" (if error "<div class='error'>Invalid credentials!</div>" "")))

(hunchentoot:define-easy-handler (do-login :uri "/do-login") (username password)
  ;; Evaluate both checks unconditionally so a wrong username and a wrong
  ;; password are indistinguishable by timing.
  (let ((user-ok (constant-time-equal username *auth-user*))
        (pass-ok (constant-time-equal password *auth-pass*)))
    (if (and user-ok pass-ok)
        (let ((session (hunchentoot:start-session)))
          ;; Rotate the session id on login to defeat session fixation.
          (hunchentoot:regenerate-session-cookie-value session)
          (setf (hunchentoot:session-value 'authenticated) t)
          (harden-session-cookie session)
          (hunchentoot:redirect "/" :add-session-id nil))
        (hunchentoot:redirect "/login?error=1" :add-session-id nil))))

(hunchentoot:define-easy-handler (do-logout :uri "/logout") ()
  ;; Fully invalidate the session server-side, not just the flag.
  (let ((session (hunchentoot:session hunchentoot:*request*)))
    (when session
      (hunchentoot:remove-session session)))
  (hunchentoot:redirect "/login" :add-session-id nil))

;; Main App UI
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
        pre#result { background: #1a1a1a; padding: 1rem; border-radius: 4px; min-height: 50px; border: 1px solid #333; white-space: pre-wrap; word-break: break-all; color: #a6e22e; }
        .func-item { border-bottom: 1px solid #333; padding: 0.5rem 0; }
        .container { margin-top: 2rem; }
        .nav-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #444; padding-bottom: 1rem; margin-bottom: 2rem; }
    </style>
</head>
<body>
    <main class='container'>
        <div class='nav-header'>
            <h1 style='margin:0'>λ Lisp Self-Modifying Service</h1>
            <a href='/logout' role='button' class='secondary outline'>Logout</a>
        </div>
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
            if (res.status === 401) { window.location.href = '/login'; return; }
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
            if (res.status === 401) { window.location.href = '/login'; return; }
            alert(await res.text());
            loadFunctions();
        }
        
        function escapeHtml(unsafe) {
            return unsafe
                 .replace(/&/g, '&amp;')
                 .replace(/</g, '&lt;')
                 .replace(/>/g, '&gt;')
                 .replace(/\"/g, '&quot;')
                 .replace(/'/g, '&#039;');
        }

        async function loadFunctions() {
            const res = await fetch('/api/functions');
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            const container = document.getElementById('functions-container');
            container.innerHTML = data.map(f => \"<div class='func-item'><strong>\"+escapeHtml(f.name)+\"</strong>: <code>\"+escapeHtml(f.body)+\"</code></div>\").join('') || 'No custom functions defined.';
        }
        loadFunctions();
    </script>
</body>
</html>"))

;; API Handlers
(hunchentoot:define-easy-handler (api-eval :uri "/api/eval") (expr)
  (check-api-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (progn
        (when (or (null expr) (> (length expr) *max-input-bytes*))
          (error "Input exceeds the ~a byte limit." *max-input-bytes*))
        (let* ((*package* *sandbox-package*)
               (*read-eval* nil)
               (form (read-from-string expr))
               (result (safe-sandbox:safe-eval form))
               (out (render-result result)))
          (with-open-file (log "/home/micu/lisp/lisp-app/logs/evaluations.log" :direction :output :if-exists :append :if-does-not-exist :create)
            (format log "[~a] EVAL: ~S => ~a~%" (get-universal-time) expr out))
          out))
    (sb-ext:timeout () "Error: Evaluation timed out!")
    (storage-condition () "Error: Resource limit exceeded!")
    (serious-condition (c) (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (api-redefine :uri "/api/redefine") (name body)
  (check-api-auth)
  (setf (hunchentoot:content-type*) "text/plain")
  (handler-case
      (progn
        (when (or (null name) (null body)
                  (> (length name) *max-name-length*)
                  (> (length body) *max-input-bytes*))
          (error "Invalid or oversized input."))
        (let* ((*package* *sandbox-package*)
               (*read-eval* nil)
               (body-form (read-from-string body)))
          (safe-sandbox:redefine-function name body-form)
          (format nil "Function '~a' defined successfully." name)))
    (storage-condition () "Error: Resource limit exceeded!")
    (serious-condition (c) (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (api-functions :uri "/api/functions") ()
  (check-api-auth)
  (setf (hunchentoot:content-type*) "application/json")
  (cl-json:encode-json-to-string (safe-sandbox:get-functions)))

;; App Entry Point
(defun start-server ()
  (safe-sandbox:restore-functions)
  (setf hunchentoot:*session-secret* *session-secret*)
  ;; Never put the session id in URLs (it would leak via Referer/logs/history).
  (setf hunchentoot:*rewrite-for-session-urls* nil)
  (setf *acceptor* (make-instance 'hunchentoot:easy-acceptor
                                  :address *bind-address*
                                  :port *port*
                                  :access-log-destination "/home/micu/lisp/lisp-app/logs/access.log"
                                  :message-log-destination "/home/micu/lisp/lisp-app/logs/message.log"))
  (hunchentoot:start *acceptor*)
  (format t "Server started on ~a:~a~%" *bind-address* *port*))

(defun main ()
  (start-server)
  (loop (sleep 3600)))

;; Loading the file for tests/inspection must not start the listener.
;; Set LISP_APP_NO_AUTOSTART=1 to load definitions only.
(unless (config-env "LISP_APP_NO_AUTOSTART")
  (main))