(in-package :cl-user)

;;;; Runtime configuration.
;;;;
;;;; NO secrets live in this file or anywhere in version control. Every
;;;; sensitive value is read from the process environment at start-up
;;;; (see deploy/lisp-app.env.example for the full list). The service
;;;; FAILS CLOSED: if a required secret is missing or obviously weak it
;;;; refuses to start instead of silently falling back to a guessable
;;;; default.

(defun config-env (name &optional default)
  "Return environment variable NAME, or DEFAULT when unset/empty."
  (let ((val (sb-ext:posix-getenv name)))
    (if (or (null val) (string= val "")) default val)))

(defun config-require-env (name &key (min-length 1))
  "Return required environment variable NAME or signal an error.
Enforces a minimum length so weak/empty secrets cannot be used."
  (let ((val (config-env name)))
    (cond
      ((null val)
       (error "Refusing to start: required environment variable ~a is not set." name))
      ((< (length val) min-length)
       (error "Refusing to start: ~a must be at least ~a characters." name min-length))
      (t val))))

;;; --- Secrets (must be provided via the environment) ---
(defparameter *auth-user*      (config-require-env "LISP_AUTH_USER"))
(defparameter *auth-pass*      (config-require-env "LISP_AUTH_PASS" :min-length 12))
;; The session secret signs session cookies; if it leaks or is guessable an
;; attacker can forge an authenticated session. Demand real entropy.
(defparameter *session-secret* (config-require-env "LISP_SESSION_SECRET" :min-length 32))

;;; --- Non-secret tunables (safe, conservative defaults) ---
(defparameter *eval-timeout*   (parse-integer (config-env "LISP_EVAL_TIMEOUT" "3")))
;; Bind to loopback by default: the public surface must go through the reverse
;; proxy (Nginx/Cloudflare), never straight to the application port.
(defparameter *bind-address*   (config-env "LISP_BIND_ADDRESS" "127.0.0.1"))
(defparameter *port*           (parse-integer (config-env "LISP_PORT" "8093")))
(defparameter *data-file*      (config-env "LISP_DATA_FILE" "/home/micu/lisp/lisp-app/data/functions.lisp"))
(defparameter *log-dir*        (config-env "LISP_LOG_DIR"   "/home/micu/lisp/lisp-app/logs"))

;;; --- Sandbox resource limits ---
(defparameter *max-input-bytes*    10000)   ; reject oversized expressions before reading
(defparameter *max-output-bytes*   100000)  ; truncate huge results before returning
(defparameter *max-functions*      200)     ; cap stored user functions
(defparameter *max-name-length*    64)      ; cap user function name length
(defparameter *login-max-attempts* 10)      ; per-IP failures before lockout
(defparameter *login-lockout-secs* 300)     ; lockout window in seconds
