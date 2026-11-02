# nginx snippets for the stand

`report-routes.conf`: the `/r/` report links (`url`, `pdf_url`, `manage_url` of review_report).

Deploy on both vhosts (`mcp.soken.dev` and `soken.dev`):

1. Delete the old `location ~ ^/r/(?<rid>[a-z0-9]+)\.pdf$ { alias ... }` block from both
   server blocks. It ignored the signature and expiry, kept serving deleted reports and always
   served render 1.
2. Delete any other `location` that matches `/r/` (the generic proxy for `/r/` is replaced by
   this snippet).
3. Copy `report-routes.conf` to `/etc/nginx/snippets/`, set the `limit_req` zone name to the
   existing zone, and add `include snippets/report-routes.conf;` to both server blocks.
4. `nginx -t && systemctl reload nginx`.
5. Check: `curl -sI 'https://soken.dev/r/<id>.pdf?e=1&s=x'` answers 403;
   a fresh `pdf_url` from review_report answers 200 `application/pdf`; `url` answers 200
   `text/html`; `manage_url` (without the fragment) answers 200.

The app serves `/r/` before the MCP transport, so `SOKEN_ALLOWED_HOSTS` (the DNS-rebinding
allowlist of `/mcp`) does not need `soken.dev` for these routes.
