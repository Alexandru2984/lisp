# Security Model

This service evaluates **untrusted Common Lisp** submitted over HTTP. That is a
hostile feature by design, so security is treated as the primary requirement,
not an afterthought. This document describes the threat model, the controls in
place, and the limitations that remain.

## Threat model

| Actor | Capability | Goal |
|-------|-----------|------|
| Anonymous internet user | Reach the public endpoint | Bypass auth, RCE, read host files, DoS |
| Authenticated admin | Submit arbitrary Lisp to the REPL | Escape the sandbox, run shell commands, read/write the filesystem |
| Compromised CDN | Serve modified JS/CSS | Inject script into the admin's browser |

**Trust boundary:** everything inside the SBCL image is privileged. The job of
the sandbox is to ensure that text arriving from the network can never reach
that privilege.

## Controls

### Authentication & sessions
- Credentials and the session-signing secret are read from the environment and
  never committed. The service **fails closed** if they are missing or weak.
- Constant-time credential comparison; both username and password are always
  checked (no timing oracle).
- Per-IP login throttling (real client IP via Cloudflare/Nginx headers).
- Session cookie is `HttpOnly; Secure; SameSite=Strict`; the session id is
  rotated on login (anti-fixation) and never placed in URLs.

### The sandbox (defense in depth)
1. **Symbol whitelist** — user code is read into a package that imports only a
   small, audited set of safe `CL` symbols. No `eval`, no file/stream/process
   primitives, no `make-array`.
2. **AST walker** — every symbol in the parsed form is verified to resolve to
   the sandbox package or to keywords; this blocks package-prefix attacks such
   as `(sb-ext:run-program ...)`.
3. **`*read-eval*` is disabled** everywhere code is read, so `#.` cannot run at
   read time (including when restoring persisted functions).
4. **`format` is wrapped** — `cl:format` is *not* exposed. The wrapper rejects
   the `~/name/` (arbitrary function call by name from the control string) and
   `~?` (recursive) directives, which otherwise bypass the symbol whitelist.
   This was a real, confirmed escape and is covered by a regression test.
5. **Resource limits** — input size cap, CPU timeout, bounded result rendering
   (`*print-length*`/`*print-level*`/`*print-circle*` + byte cap), a cap on the
   number and name-length of stored functions.

### Transport & browser
- Strict `Content-Security-Policy` with a per-request nonce for the single
  inline script; CDN origins are explicitly allowlisted.
- Subresource Integrity (`sha384`) on every CDN asset, pinned to exact versions.
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, and HSTS.
- CSRF synchronizer token required on state-changing API calls.
- App binds to `127.0.0.1` only — the public surface must traverse the reverse
  proxy / Cloudflare; the origin port cannot be hit directly.

### Host containment (systemd)
- Runs under `NoNewPrivileges`, `ProtectSystem=strict` (only `logs/` and
  `data/` writable), `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`,
  `SystemCallFilter=@system-service`, and friends.
- `--dynamic-space-size` is bounded below the cgroup `MemoryMax`, with
  `CPUQuota` and `TasksMax` caps.

## Known limitations

- **Heap-allocation DoS.** A tight allocation loop (e.g. `(loop ... collect x)`)
  can exhaust the bounded Lisp heap faster than SBCL can run a recovery handler,
  causing the process to exit. This is only reachable by an authenticated admin,
  is bounded by `--dynamic-space-size` (it cannot consume the host), and the
  service auto-restarts within ~2s. **Recommended hardening:** run each
  evaluation in a short-lived child process with its own `RLIMIT_AS`/`RLIMIT_CPU`
  so a crash never touches the listener. Tracked as future work.
- The in-process symbol whitelist is necessarily an allowlist; new escapes are
  possible if the import list grows carelessly. Keep the list minimal and add a
  regression test for every capability added.

## Reporting

Found something? Open a private security advisory on the GitHub repository, or
email the maintainer. Please do not file public issues for exploitable bugs.
