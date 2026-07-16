# Backlog

Known gaps deliberately left for later. WIP belongs on a branch, not here.

## An MCP-initiated download can still have its lock stolen after 15 minutes
- **What:** `_lock_is_stale` no longer reclaims a lock whose owner is this process, and
  `stream_dataset` (the web UI's path) refreshes its lock's mtime while downloading. Neither
  covers the *other* process: `make mcp` runs the MCP server via `docker compose exec` in the
  same container, so an `mcp_server.download()` running longer than `stale_after` (900s) can
  still have its lock reclaimed by the API, starting a second concurrent `az` download into the
  same `raw/` dir.
- **Why deferred:** `ensure_dataset` is a blocking call with no poll loop to heartbeat from, so
  fixing it means a watchdog thread — more machinery than the case earns. It needs a >15-minute
  MCP download racing a UI download of the same day, on one operator's laptop.
- **Unblock:** have `ensure_dataset` touch the lock from a small background thread for the
  duration of the download (or move the heartbeat into `downloader.download`'s `on_event`), then
  drop the age check for live foreign PIDs. Related: `clear_stale_locks()` at API startup wipes
  locks unconditionally on the "single-process app" assumption, which the in-container MCP
  process also breaks.
- **Where:** `src/lawless_waf/cache.py` (`_lock_is_stale`, `clear_stale_locks`),
  `src/lawless_waf/service.py` (`ensure_dataset`, `stream_dataset`).

## Multi-resource download estimate
- **What:** `POST /datasets/estimate` discovers a single WAF resourceId prefix and
  sums blob `contentLength` under it. If one container holds blobs for *multiple* WAF
  resources, the estimate only covers the first prefix; the actual download (a `*/` glob)
  fetches them all, so the real size can exceed the estimate.
- **Why deferred:** uncommon layout; a single-resource estimate is enough to gauge cost.
- **Unblock:** enumerate all top-level resourceId prefixes and sum across them.
- **Where:** `src/lawless_waf/azure/estimate.py` (`discover_base_prefix`/`day_bytes`).

## `http://[::1]:8000` is rejected by the Host allowlist
- **What:** Browsing the app on the IPv6 loopback literal returns `400 Invalid host header`.
  `localhost` and `127.0.0.1` both work, so this only bites someone who types `[::1]` directly.
- **Why deferred:** not fixable by configuration. Starlette's `TrustedHostMiddleware` parses the
  header as `host.split(":")[0]`, which reduces `[::1]` to `[` — so an `"[::1]"` entry in
  `allowed_hosts` can never match. The only allowlist entry that would match is `"["`, which
  would also match any other host starting with `[`. Not worth weakening the check that stops
  DNS rebinding, for a URL nobody types (browsers send `localhost`).
- **Unblock:** upstream fix in Starlette to parse IPv6 literals, or replace the middleware with a
  small custom Host check that strips brackets properly. Re-verify with
  `curl -H 'Host: [::1]' http://localhost:8000/api/healthz`.
- **Where:** `src/lawless_waf/main.py` (the `TrustedHostMiddleware` registration).

## Community health files and a first release tag
- **What:** No CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue/PR templates, or releases/tags, and
  the README has no closing Contributing/License sections (the license is badge-only, though
  `LICENSE` itself is present). From the pre-launch audit (P3 item 20).
- **Why deferred:** repo-governance calls rather than code polish, and the shape depends on
  whether the project expects outside contributors at all. Tagging `v0.1.0` is also a call the
  maintainer should make, not one to slip into a polish branch.
- **Unblock:** decide whether to invite contributions. If yes: a minimal CONTRIBUTING.md (dev
  setup `make up`, checks `make test && make lint`, Conventional Commits per AGENTS.md), a PR
  template, one bug-report issue form, README "## Contributing" and "## License — Apache-2.0"
  sections, then tag `v0.1.0`.
- **Where:** `.github/` (templates), repo root (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`),
  `README.md` (closing sections).

## Personal Claude Code skill committed in-repo
- **What:** `.claude/skills/setup-github-repo/` is generic personal repo-setup tooling
  unrelated to WAF tuning. Harmless, but noise for a visitor browsing `.claude/`. From the
  pre-launch audit (P3 item 21).
- **Why deferred:** it is the maintainer's own tooling; whether it stays is a preference, not
  a defect. Left in place rather than deleted someone else's working setup unasked.
- **Unblock:** decide to either move it to `~/.claude/skills/` and
  `git rm -r .claude/skills/setup-github-repo`, or keep it deliberately.
- **Where:** `.claude/skills/setup-github-repo/SKILL.md`.

## Scanner-heuristic tuning
- **What:** Thresholds in `src/lawless_waf/analysis/scanner.py` (min_blocks=20, min_groups=3,
  min_uris=15) are first-pass defaults. They correctly classify the sample day but have not
  been validated across a wider range of real days.
- **Why deferred:** needs more real datasets to calibrate.
- **Unblock:** run against several production days and tune; consider making thresholds
  configurable via `.env`.
- **Where:** `src/lawless_waf/analysis/scanner.py`.
