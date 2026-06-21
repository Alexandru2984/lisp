# Nginx site for lisp.micutu.com
#
# This origin sits behind Cloudflare. Two things matter for security here:
#   1. Restore the real visitor IP (Cloudflare hides it behind its proxy IPs).
#   2. Optionally refuse any connection that did NOT come through Cloudflare,
#      so the origin cannot be hit directly (defence in depth on top of the
#      app binding to 127.0.0.1).
#
# The application itself listens only on 127.0.0.1:8093 and sets its own
# security headers (CSP, X-Frame-Options, ...), so this file stays focused
# on transport + real-IP.

# --- Cloudflare real client IP --------------------------------------------
# Refresh the ranges from https://www.cloudflare.com/ips/ periodically.
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;

server {
    listen 80;
    listen [::]:80;
    server_name lisp.micutu.com;

    # Keep request bodies small: the REPL only ever submits short snippets.
    client_max_body_size 64k;

    # OPTIONAL but recommended: only accept traffic proxied by Cloudflare.
    # Uncomment once you have verified all `set_real_ip_from` ranges above
    # cover your Cloudflare edge, otherwise you may lock yourself out.
    #   if ($http_cf_connecting_ip = "") { return 403; }

    location / {
        proxy_pass http://127.0.0.1:8093;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }
}

# --- TLS at the origin (recommended: Cloudflare SSL mode = Full (strict)) ---
# Generate a Cloudflare Origin Certificate (15-year, free) and reference it
# here, then switch the :80 server above to a permanent redirect.
#
# server {
#     listen 443 ssl http2;
#     listen [::]:443 ssl http2;
#     server_name lisp.micutu.com;
#
#     ssl_certificate     /etc/ssl/cloudflare/lisp.micutu.com.pem;
#     ssl_certificate_key /etc/ssl/cloudflare/lisp.micutu.com.key;
#     ssl_protocols       TLSv1.2 TLSv1.3;
#     ssl_ciphers         HIGH:!aNULL:!MD5;
#     client_max_body_size 64k;
#
#     location / {
#         proxy_pass http://127.0.0.1:8093;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#         proxy_read_timeout 15s;
#     }
# }
