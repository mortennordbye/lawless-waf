# Security Policy

## Security model

lawless-waf is a single-operator tool. It runs on your laptop in Docker, reads WAF logs from your
own Azure storage account, and answers questions about them. The posture below follows from that,
and the choices are deliberate rather than omissions.

**Where it runs.** Both containers publish to `127.0.0.1` only (the `ports:` entries in
`compose.yaml`). Uvicorn and Vite bind `0.0.0.0` *inside* their containers, so that prefix is the
enforcement point: drop it and you put an unauthenticated API on your LAN.

**No app-level auth, by design.** There is no login. The gate is your Azure access. The app holds
no credentials of its own; it reuses your ambient `az login` session (`~/.azure` is mounted
read-write because the CLI refreshes tokens there). Whatever stands in front of Azure for you
(PIM, Conditional Access, VPN) stands in front of this data too. No Azure secrets live in the
repo, the image, or `.env`, which holds only a target: subscription, storage account, container.

**Browser-side exposure.** With no auth, any page you visit is a potential client of your
localhost. CORS is empty by default, but CORS only hides responses; it does not stop the request
from running. The compensating control is a Host-header allowlist (`localhost`, `127.0.0.1`, and
`api` for the Vite dev proxy), which rejects DNS-rebinding attempts that aim an attacker-controlled
hostname at 127.0.0.1. The expensive endpoints are rate-limited on top of that.

**Data handling.** Match values are truncated everywhere they are returned, because WAF logs carry
tokens, cookies, and other personal data. Clients get generic errors; detail goes to the server log
only. Nothing leaves the laptop except `az` calls to your own storage account, with one opt-in
exception: `GEOIP_ENABLED=true` turns on country flags by sending the client IPs from your logs to
the third party ip-api.com over plain HTTP. It is off by default.

**Out of scope.** Multi-user or multi-tenant use, running on a shared or internet-facing host, and
defending against someone who already holds your laptop or your Azure session.

## Supported Versions

Only the latest release is actively supported with security updates.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.
Use the "Report a vulnerability" button under this repository's **Security** tab
(private vulnerability reporting is enabled). You will receive an acknowledgement
within 48 hours.
