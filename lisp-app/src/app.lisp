(in-package :cl-user)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (ql:quickload '(:hunchentoot :alexandria :cl-json)))

;; Load config relative to this file so the project is portable (CI, clones).
(load (merge-pathnames "../config/config.lisp"
                       (or *load-pathname* *default-pathname-defaults*)))

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

;; --- DEFENSE-IN-DEPTH LAYER --------------------------------------------

;; Cryptographically strong random hex token (CSPRNG via /dev/urandom),
;; used for CSP nonces and CSRF tokens. cl:random is NOT suitable here.
(defun random-token (&optional (bytes 16))
  (with-open-file (u "/dev/urandom" :element-type '(unsigned-byte 8))
    (let ((buf (make-array bytes :element-type '(unsigned-byte 8))))
      (read-sequence buf u)
      (with-output-to-string (s)
        (loop for b across buf do (cl:format s "~(~2,'0x~)" b))))))

;; --- Logging (sanitized, ISO 8601, never breaks a request) ---
(defun iso-timestamp (&optional (ut (get-universal-time)))
  (multiple-value-bind (s m h d mon y) (decode-universal-time ut 0)
    (cl:format nil "~4,'0d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0dZ" y mon d h m s)))

(defun sanitize-log (value &optional (max 500))
  "Drop control characters (prevents log injection) and bound the length."
  (let ((s (remove-if (lambda (c) (< (char-code c) 32)) (string value))))
    (if (> (length s) max) (subseq s 0 max) s)))

(defun log-path (name)
  (concatenate 'string (string-right-trim "/" *log-dir*) "/" name))

(defun log-event (filename fmt &rest args)
  (handler-case
      (with-open-file (log (log-path filename)
                           :direction :output :if-exists :append :if-does-not-exist :create)
        (cl:format log "[~a] ~a~%" (iso-timestamp) (apply #'cl:format nil fmt args)))
    (error () nil)))

;; --- Real client IP (behind Cloudflare + Nginx) ---
(defun client-ip ()
  (or (hunchentoot:header-in* :cf-connecting-ip)
      (hunchentoot:header-in* :x-real-ip)
      (ignore-errors (hunchentoot:real-remote-addr))
      "unknown"))

;; --- Per-IP login throttling (thread-safe) ---
(defvar *login-attempts* (make-hash-table :test 'equal))
(defvar *login-lock* (sb-thread:make-mutex :name "login-attempts"))

(defun login-locked-p (ip)
  (sb-thread:with-mutex (*login-lock*)
    (let ((entry (gethash ip *login-attempts*)))
      (and entry
           (>= (car entry) *login-max-attempts*)
           (< (get-universal-time) (cdr entry))))))

(defun register-login-failure (ip)
  (sb-thread:with-mutex (*login-lock*)
    (let* ((now (get-universal-time))
           (entry (gethash ip *login-attempts*))
           (count (if (and entry (< now (cdr entry))) (1+ (car entry)) 1)))
      (setf (gethash ip *login-attempts*) (cons count (+ now *login-lockout-secs*))))))

(defun clear-login-failures (ip)
  (sb-thread:with-mutex (*login-lock*)
    (remhash ip *login-attempts*)))

;; --- CSRF tokens (synchronizer pattern; SameSite=Strict is the first line) ---
(defun ensure-csrf-token ()
  (or (hunchentoot:session-value 'csrf-token)
      (setf (hunchentoot:session-value 'csrf-token) (random-token 32))))

(defun check-csrf ()
  (let ((sent (hunchentoot:header-in* :x-csrf-token))
        (expected (hunchentoot:session-value 'csrf-token)))
    (unless (and expected sent (constant-time-equal sent expected))
      (setf (hunchentoot:return-code*) 403)
      (hunchentoot:abort-request-handler "CSRF token invalid"))))

;; --- Security headers on every response (set before the handler runs) ---
(defvar *csp-nonce* nil)

(defun set-security-headers (nonce)
  (flet ((h (name val) (setf (hunchentoot:header-out name) val)))
    (h :x-content-type-options "nosniff")
    (h :x-frame-options "DENY")
    (h :referrer-policy "no-referrer")
    (h :permissions-policy "geolocation=(), microphone=(), camera=()")
    (h :strict-transport-security "max-age=63072000; includeSubDomains")
    (h :content-security-policy
       (cl:format nil "default-src 'none'; ~
                       script-src 'nonce-~a' https://cdnjs.cloudflare.com; ~
                       style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; ~
                       font-src 'self'; img-src 'self' data:; connect-src 'self'; ~
                       base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                  nonce))))

(defclass lisp-acceptor (hunchentoot:easy-acceptor) ())

(defmethod hunchentoot:acceptor-dispatch-request :around ((acceptor lisp-acceptor) request)
  (declare (ignore request))
  (let ((*csp-nonce* (random-token 16)))
    (set-security-headers *csp-nonce*)
    (call-next-method)))

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
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@picocss/pico@1.5.13/css/pico.min.css' integrity='sha384-Igjx5rLo1oJuDlq1Ls6uECey1nXahm4j4GoF8ixTon9zxdse6QkdsFelFYk8j7rI' crossorigin='anonymous'>
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
  (let ((ip (client-ip)))
    (cond
      ;; Throttle brute-force attempts per IP.
      ((login-locked-p ip)
       (log-event "security.log" "LOGIN locked-out ip=~a" (sanitize-log ip))
       (setf (hunchentoot:return-code*) 429
             (hunchentoot:content-type*) "text/plain")
       "Too many failed attempts. Please try again later.")
      (t
       ;; Evaluate both checks unconditionally so a wrong username and a wrong
       ;; password are indistinguishable by timing.
       (let ((user-ok (constant-time-equal username *auth-user*))
             (pass-ok (constant-time-equal password *auth-pass*)))
         (cond
           ((and user-ok pass-ok)
            (clear-login-failures ip)
            (let ((session (hunchentoot:start-session)))
              ;; Rotate the session id on login to defeat session fixation.
              (hunchentoot:regenerate-session-cookie-value session)
              (setf (hunchentoot:session-value 'authenticated) t)
              (ensure-csrf-token)
              (harden-session-cookie session)
              (log-event "security.log" "LOGIN success ip=~a" (sanitize-log ip))
              (hunchentoot:redirect "/" :add-session-id nil)))
           (t
            (register-login-failure ip)
            (log-event "security.log" "LOGIN failure ip=~a user=~a"
                       (sanitize-log ip) (sanitize-log (or username "")))
            (hunchentoot:redirect "/login?error=1" :add-session-id nil))))))))

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
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@picocss/pico@1.5.13/css/pico.min.css' integrity='sha384-Igjx5rLo1oJuDlq1Ls6uECey1nXahm4j4GoF8ixTon9zxdse6QkdsFelFYk8j7rI' crossorigin='anonymous'>
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css' integrity='sha384-zaeBlB/vwYsDRSlFajnDd7OydJ0cWk+c2OWybl3eSUf6hW2EbhlCsQPqKr3gkznT' crossorigin='anonymous'>
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/monokai.min.css' integrity='sha384-05WuhgjXiqmZzcQ3vQRQ39HN356Yqb+SnhvELzFtpwS5b2IlqE8QsOO5LCSJ2znj' crossorigin='anonymous'>
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
                <button id='run-btn'>Run Expression</button>
                <label>Output:</label>
                <pre id='result'>Ready.</pre>
            </section>
            <section>
                <h3>Redefine Function</h3>
                <input type='text' id='func-name' placeholder='function-name'>
                <textarea id='func-editor'>(format nil \"Hello from ~~a\" \"Lisp\")</textarea>
                <button class='secondary' id='define-btn'>Save & Define</button>
            </section>
        </div>
        <hr>
        <section id='functions-list'>
            <h3>Runtime Functions</h3>
            <div id='functions-container'>Loading...</div>
        </section>
    </main>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js' integrity='sha384-oG4CsOtmTEhYO9bKzsYPGRJyqcREeEElY9hokeI8NndemZlK5k6d+0LX0xY5HObE' crossorigin='anonymous'></script>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/commonlisp/commonlisp.min.js' integrity='sha384-ye4RbMVxAnFR5m3bDEHC/aMjpHeLXp0sfDBS/nlkE/GnpnAngBz7b5ufKgCuadrF' crossorigin='anonymous'></script>
    <script nonce='~a'>
        const CSRF = '~a';
        const evalEditor = CodeMirror.fromTextArea(document.getElementById('eval-editor'), { mode: 'commonlisp', theme: 'monokai', lineNumbers: true });
        const funcEditor = CodeMirror.fromTextArea(document.getElementById('func-editor'), { mode: 'commonlisp', theme: 'monokai', lineNumbers: true });

        async function doEval() {
            const res = await fetch('/api/eval', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': CSRF },
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
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': CSRF },
                body: new URLSearchParams({name: name, body: funcEditor.getValue()})
            });
            if (res.status === 401) { window.location.href = '/login'; return; }
            alert(await res.text());
            loadFunctions();
        }

        document.getElementById('run-btn').addEventListener('click', doEval);
        document.getElementById('define-btn').addEventListener('click', doRedefine);

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
</html>" *csp-nonce* (ensure-csrf-token)))

;; API Handlers
(hunchentoot:define-easy-handler (api-eval :uri "/api/eval") (expr)
  (check-api-auth)
  (check-csrf)
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
          (log-event "evaluations.log" "EVAL ip=~a expr=~s => ~a"
                     (sanitize-log (client-ip) 64) (sanitize-log expr) (sanitize-log out))
          out))
    (sb-ext:timeout () "Error: Evaluation timed out!")
    (storage-condition () "Error: Resource limit exceeded!")
    (serious-condition (c) (format nil "Error: ~a" c))))

(hunchentoot:define-easy-handler (api-redefine :uri "/api/redefine") (name body)
  (check-api-auth)
  (check-csrf)
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
          (log-event "evaluations.log" "REDEFINE ip=~a name=~a"
                     (sanitize-log (client-ip) 64) (sanitize-log name 64))
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
  ;; Never echo Lisp errors/backtraces to clients (information disclosure).
  (setf hunchentoot:*show-lisp-errors-p* nil
        hunchentoot:*show-lisp-backtraces-p* nil)
  (setf *acceptor* (make-instance 'lisp-acceptor
                                  :address *bind-address*
                                  :port *port*
                                  :access-log-destination (log-path "access.log")
                                  :message-log-destination (log-path "message.log")))
  (hunchentoot:start *acceptor*)
  (format t "Server started on ~a:~a~%" *bind-address* *port*))

(defun main ()
  (start-server)
  (loop (sleep 3600)))

;; Loading the file for tests/inspection must not start the listener.
;; Set LISP_APP_NO_AUTOSTART=1 to load definitions only.
(unless (config-env "LISP_APP_NO_AUTOSTART")
  (main))