# Troubleshooting

The failure modes people actually hit, and what each one means. Messages quoted here are the
ones the app really emits, so you can match on them.

## Getting it running

### Ports are taken

`make up` needs **5173** (UI) and **8000** (API) free on localhost; the single-container
`docker run` needs **8000**. If something else owns them, stop it — the compose ports are pinned
on purpose so the URLs in the docs are always right.

A common self-inflicted version: a leftover `make up` still holding 8000 while you try to
`docker run` the image. `docker run` fails to bind, and if you missed the error you end up
talking to the *old* container and wondering why your changes did nothing. `make down` first, and
check with `docker ps`.

`make up` stays in the foreground tailing logs. Give it its own terminal; `Ctrl+C` there, or
`make down` from another, stops it.

### `docker run` gives me the app but no data

Add `-e SEED_SAMPLE=true` for the synthetic demo days, or download a real one from the Download
tab. Without a `-v ...:/data` volume the datasets live in an anonymous volume and vanish when the
container is removed — that's fine for a demo, less fine once you've downloaded a real day.

### My downloaded datasets disappeared

`--rm` plus no `-v` means the data lived in an anonymous volume that went with the container. Use
a named volume (`-v lawless-waf-data:/data`) and they persist across runs *and* upgrades. There's
no recovering the old ones; download the day again.

### A fix or feature in the README isn't in my app

You're running a stale image. `docker run` uses the `latest` you already pulled and never checks
for a newer one, so "I ran it last month" means you're on last month's build:

```bash
docker pull ghcr.io/mortennordbye/lawless-waf:latest
```

or add `--pull=always` to the run. Your datasets are in the volume, not the image, so upgrading
loses nothing. `docker image ls ghcr.io/mortennordbye/lawless-waf` shows what you actually have
and when it was created.

### Nothing to look at after `make up`

You need a dataset. Offline: `make seed` writes two synthetic days. Otherwise download a real
one from the **Download** tab. An empty Analyze tab with no datasets says so and points at
Download.

### Changes to the frontend do not show up

The UI hot-reloads from a bind mount, but on macOS Docker occasionally misses a file event and
Vite serves a stale transform — the symptom is an edit that provably saved but does not reach
the browser, even after a hard reload. `docker compose restart ui` clears it.

Note the compose services are `api` and `ui`. `docker compose restart web` fails with
*"service web is not running"*, which reads like something worse than a typo.

## Azure

### `az: not signed in` in the header

> `not signed in — run az login on the host`

Run `az login` **on your laptop, not inside the container**. The app has no credentials of its
own: `compose.yaml` mounts `${HOME}/.azure` and reuses whatever session is there. If you are
signed in on the host and the app still says otherwise, the mount is the thing to check — a
non-Unix `$HOME` (plain Windows rather than WSL) will not resolve.

### `az CLI not found`

The `az` binary is not on the host, or not on the PATH the container sees through the mount.
Install the Azure CLI on the host.

### `az timed out — check the VPN connection`

Usually exactly what it says: the storage account is network-restricted and your VPN is not up.
It is also what a not-yet-activated PIM role looks like from here.

### The download 403s or returns nothing

Three things to check, in order:

1. **PIM** — is the role granting *Storage Blob Data Reader* actually activated right now, not
   just assigned?
2. **VPN** — is the storage account behind a network restriction?
3. **Role** — *Reader* on the subscription is not enough. You need **Storage Blob Data Reader**
   on the storage account; the data plane and the control plane are different permissions, and
   this is the single most common cause.

### `no blobs found in the container`

The container is right but empty for what you asked for, or it is the wrong container. Check:

- **The container.** The default is `insights-logs-frontdoorwebapplicationfirewalllog`. If your
  diagnostic setting writes somewhere else, pick it on the Settings tab.
- **The day.** Nothing was archived for that date/hour. WAF blobs land a few minutes late, so
  "this hour" can legitimately be empty for a while.
- **The export exists at all.** This tool reads an archive; it does not create one. If nothing
  is streaming WAF diagnostic logs to a storage account, there is nothing here to read. Set that
  up in Azure first.

### Downloading does nothing / refuses

> `OFFLINE=true: refusing to download; seed the dataset instead.`

`OFFLINE=true` is still set in `.env`. That is the default, deliberately — the offline demo must
never touch Azure. Set `OFFLINE=false` and restart (`make down && make up`).

### Settings dropdowns are empty

They are populated from your `az` session, so an empty subscription list means the session is
not visible to the container — same cause as *not signed in* above. You can always type the
target manually with **Enter manually**.

## Analysis

### The dataset downloaded but the analysis is empty

- **A policy filter is set** in the scope bar. Set it back to *All policies*.
- **Wrong day.** Blobs are partitioned by **UTC**, not your local time. The Download tab prints
  the current UTC time next to the hour field for exactly this reason.

### Rules are firing but "blocks by cause" is empty

The policy is in **Detection** mode, so nothing blocks by definition. The Overview says so with
a badge. Read firing rules instead — they are what would block in Prevention mode. See
[WAF concepts](waf-concepts.md#detection-vs-prevention-mode).

### Rule 949110 is my top "firing rule"

That is the scoreboard, not a rule to tune. `949110` / `BLOCKING-EVALUATION` is the row Azure
writes when a request's anomaly score crosses the threshold. The rules that *caused* it are the
`AnomalyScoring` rows. See [WAF concepts](waf-concepts.md#actions-why-a-rule-can-fire-without-blocking).

### I excluded it and the rule still fires

Usually one of:

- **The rule genuinely still fires for another reason.** One rule can match several match
  variables; you fixed one. The rule diff shows `reduced`, not `resolved`, and per-match-variable
  it will show exactly which one went to zero. That is the [walkthrough](walkthrough.md#5-verify-with-a-diff)
  case, and it is usually correct behaviour — a scanner tripping the same rule *should* stay blocked.
- **Name vs value.** The exclusion targets the cookie/param **name**
  (`RequestCookieNames`), not the value the log reported (`CookieValue:...`). See
  [the mapping table](waf-concepts.md#exclusions-the-mapping-that-catches-everyone).
- **Still blocked at score.** Removing one scoring rule may not drop the request under the
  threshold. The request inspector shows every rule it tripped and the total.

### The request inspector shows no anomaly score

The score is parsed out of the `949110` blocking-evaluation message. If the request was never
blocked there is no such row, and so no score — that is expected, not a bug.

## Still stuck

Open an issue with what you ran, what you expected, and what happened. Do **not** paste real WAF
log rows: they carry tokens, cookies, and personal data. The sample dataset (`make seed`) is
synthetic and safe to quote from.
