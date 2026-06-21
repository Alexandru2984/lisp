# λ Lisp Control Center

A self-modifying **Common Lisp web service**: a browser REPL that evaluates
user-submitted Lisp and lets you define and persist functions at runtime —
running inside a hand-built security sandbox.

The interesting part is not the REPL; it is **safely evaluating untrusted code
in a live image**. The whole project is organised around that constraint. See
[`SECURITY.md`](SECURITY.md) for the threat model and controls.

> ⚠️ Evaluating untrusted code is inherently dangerous. The sandbox is defense
> in depth (symbol whitelist + AST walker + disabled read-eval + wrapped
> `format` + resource limits) backed by OS-level containment (systemd
> sandboxing, cgroup memory/CPU caps). Read `SECURITY.md` before exposing it.

## Architecture

```
            Cloudflare ──► Nginx (TLS, real-IP) ──► 127.0.0.1:8093 (Hunchentoot)
                                                          │
                                  ┌───────────────────────┴───────────────────────┐
                                  │  app.lisp                                       │
                                  │   • auth (env secrets, throttling, CSRF)        │
                                  │   • safe-sandbox package (symbol whitelist)     │
                                  │   • AST walker + wrapped format + read-eval off │
                                  │   • resource limits + sanitized audit logging   │
                                  └─────────────────────────────────────────────────┘
```

| Path | What |
|------|------|
| `lisp-app/src/app.lisp`   | Web server, sandbox, and security layer |
| `lisp-app/config/config.lisp` | Env-driven config; **fails closed** if secrets are missing |
| `lisp-app.service`        | Hardened systemd unit |
| `lisp.micutu.com`         | Nginx site (Cloudflare real-IP + TLS template) |
| `tests/sandbox-tests.lisp`| Regression tests — known escapes must stay blocked |
| `deploy/lisp-app.env.example` | Template for the secrets (never commit a filled copy) |

## Configuration

No secret lives in the repository. All are read from the environment and the
service refuses to start without them:

| Variable | Required | Notes |
|----------|----------|-------|
| `LISP_AUTH_USER`      | yes | admin username |
| `LISP_AUTH_PASS`      | yes | min 12 chars |
| `LISP_SESSION_SECRET` | yes | min 32 chars; signs session cookies |
| `LISP_BIND_ADDRESS`   | no  | default `127.0.0.1` |
| `LISP_PORT`           | no  | default `8093` |
| `LISP_EVAL_TIMEOUT`   | no  | seconds, default `3` |
| `LISP_DATA_FILE` / `LISP_LOG_DIR` | no | persistence + log locations |

Generate strong secrets:

```bash
openssl rand -base64 24   # LISP_AUTH_PASS
openssl rand -hex 32      # LISP_SESSION_SECRET
```

## Running locally

```bash
# Requires SBCL + Quicklisp (hunchentoot, alexandria, cl-json)
LISP_AUTH_USER=admin \
LISP_AUTH_PASS=$(openssl rand -base64 24) \
LISP_SESSION_SECRET=$(openssl rand -hex 32) \
sbcl --non-interactive --load lisp-app/src/app.lisp
# -> http://127.0.0.1:8093
```

## Tests

The regression suite asserts that every known sandbox escape stays blocked and
that core features work. It starts no server.

```bash
LISP_APP_NO_AUTOSTART=1 \
LISP_AUTH_USER=test LISP_AUTH_PASS=test-password-123 \
LISP_SESSION_SECRET=0123456789abcdef0123456789abcdef \
sbcl --non-interactive --load tests/sandbox-tests.lisp
```

CI runs this on every push (see `.github/workflows/ci.yml`).

## Deployment

```bash
# 1. Secrets (root-owned, outside the repo)
sudo install -d -m 750 /etc/lisp-app
sudo cp deploy/lisp-app.env.example /etc/lisp-app/lisp-app.env
sudoedit /etc/lisp-app/lisp-app.env        # fill in real values
sudo chmod 600 /etc/lisp-app/lisp-app.env

# 2. Service
sudo cp lisp-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lisp-app

# 3. Reverse proxy
sudo cp lisp.micutu.com /etc/nginx/sites-available/lisp.micutu.com
sudo ln -s /etc/nginx/sites-available/lisp.micutu.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Operate:

```bash
sudo journalctl -u lisp-app -f          # service logs
tail -f <LISP_LOG_DIR>/security.log     # auth audit trail
tail -f <LISP_LOG_DIR>/evaluations.log  # REPL audit trail
```
