;;;; Regression tests for the safe-sandbox security boundary.
;;;;
;;;; Run standalone (no server is started):
;;;;
;;;;   LISP_APP_NO_AUTOSTART=1 LISP_AUTH_USER=test \
;;;;   LISP_AUTH_PASS=test-password LISP_SESSION_SECRET=0123456789abcdef0123456789abcdef \
;;;;   sbcl --non-interactive --load tests/sandbox-tests.lisp
;;;;
;;;; Exits 0 if every test passes, 1 otherwise (CI-friendly).

(in-package :cl-user)

;; Make sure we never start the listener while testing.
(require :sb-posix)
(unless (sb-ext:posix-getenv "LISP_APP_NO_AUTOSTART")
  (sb-posix:setenv "LISP_APP_NO_AUTOSTART" "1" 1))

(load (merge-pathnames "../lisp-app/src/app.lisp"
                       (or *load-pathname* *default-pathname-defaults*)))

(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (name form &optional (expected t))
  `(handler-case
       (let ((got ,form))
         (if (equal got ,expected)
             (progn (incf *pass*) (format t "  ok   ~a~%" ,name))
             (progn (incf *fail*) (format t "  FAIL ~a => ~s (expected ~s)~%" ,name got ,expected))))
     (serious-condition (c)
       (incf *fail*) (format t "  FAIL ~a => signalled ~a~%" ,name (type-of c)))))

(defmacro check-blocked (name &body body)
  "The body MUST signal a serious-condition (operation rejected / aborted)."
  `(handler-case
       (progn ,@body
              (incf *fail*) (format t "  FAIL ~a => NOT blocked~%" ,name))
     (serious-condition ()
       (incf *pass*) (format t "  ok   ~a (blocked)~%" ,name))))

(defun run (string)
  "Evaluate STRING through the exact same pipeline the API uses."
  (let ((*package* *sandbox-package*) (*read-eval* nil))
    (safe-sandbox:safe-eval (read-from-string string))))

;; A bait function in CL-USER that must never be reachable from the sandbox.
(defparameter *pwned* nil)
(defun cl-user::pwned-probe (s a c at &rest p)
  (declare (ignore s a c at p)) (setf *pwned* t))

(format t "~%==== safe-sandbox regression tests ====~%")

(format t "-- core evaluation --~%")
(check "arithmetic"        (run "(+ 1 2 3)") 6)
(check "mapcar + lambda"   (run "(mapcar (lambda (x) (* x x)) (list 1 2 3))") '(1 4 9))
(check "let / cond"        (run "(let ((x 5)) (cond ((> x 3) :big) (t :small)))") :big)
(check "legit format"      (run "(format nil \"~a-~d\" \"x\" 5)") "x-5")

(format t "-- sandbox escapes must be blocked --~%")
(setf *pwned* nil)
(check-blocked "format ~/ function-call directive" (run "(format nil \"~/cl-user::pwned-probe/\" 1)"))
(check "format ~/ did not execute probe" *pwned* nil)
(check-blocked "format ~? recursive directive"     (run "(format nil \"~?\" \"~a\" (list 1))"))
(check-blocked "package-prefix call (run-program)" (run "(sb-ext::run-program \"/bin/true\" nil)"))
(check-blocked "file access (open)"                (run "(open \"/etc/passwd\")"))
(check-blocked "eval is not exposed"               (run "(eval (list 'print 1))"))
(check-blocked "read-eval #. is disabled"          (run "#.(+ 1 2)"))

(format t "-- format control-string analysis --~%")
(check "fcs accepts ~a"     (format-control-safe-p "Hi ~a") t)
(check "fcs accepts ~5,'0d" (format-control-safe-p "~5,'0d") t)
(check "fcs accepts ~{~}"   (format-control-safe-p "~{~a~}") t)
(check "fcs rejects ~/"     (format-control-safe-p "~/x/") nil)
(check "fcs rejects ~2/x/"  (format-control-safe-p "~2/x/") nil)
(check "fcs rejects ~?"     (format-control-safe-p "~?") nil)

(format t "-- auth / crypto helpers --~%")
(check "ct-equal match"     (constant-time-equal "correct horse" "correct horse") t)
(check "ct-equal mismatch"  (constant-time-equal "correct horse" "correct house") nil)
(check "ct-equal length"    (constant-time-equal "abc" "abcd") nil)
(check "random-token len"   (length (random-token 32)) 64)
(check "random-token uniq"  (not (string= (random-token 16) (random-token 16))) t)

(format t "-- resource / abuse limits --~%")
(check "output truncation"
       (let ((s (truncate-output (make-string 200000 :initial-element #\a))))
         (and (<= (length s) (+ *max-output-bytes* 32)) (search "truncated" s) t)) t)
(check-blocked "over-long function name"
  (safe-sandbox:redefine-function (make-string 100 :initial-element #\a) 1 t))
(check-blocked "cannot redefine a standard CL symbol"
  (safe-sandbox:redefine-function "car" 1 t))
(check-blocked "function-count cap"
  (let ((*max-functions* 3)
        (*custom-functions* (make-hash-table :test 'equal)))
    (dotimes (i 5)
      (safe-sandbox:redefine-function (format nil "f~d" i) 1 t))))
(let ((*eval-timeout* 1))
  (check-blocked "CPU timeout on infinite loop" (run "(loop)")))

(format t "~%==== ~d passed, ~d failed ====~%" *pass* *fail*)
(sb-ext:exit :code (if (zerop *fail*) 0 1))
