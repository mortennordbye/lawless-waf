# Backlog

Known gaps deliberately left for later. WIP belongs on a branch, not here.

## Application Gateway log-schema normalization
- **What:** Only Azure Front Door WAF logs are parsed. Application Gateway firewall logs use
  a different schema (`clientIp`, `transactionId`, `ruleId`/`ruleSetType`, actions
  `Blocked`/`Detected`/`Matched`, a flat `details` object), so pointing the app at
  `insights-logs-applicationgatewayfirewalllog` downloads fine but every query then errors
  or returns empty.
- **Why deferred:** Front Door is what I run and can validate against real traffic; shipping
  an AppGw mapping I can't test on a real day would be a guess. README and `.env.example`
  now state the Front Door-only scope rather than implying AppGw works.
- **Unblock:** add a normalization layer over the logs view mapping `clientIp→clientIP`,
  `transactionId→trackingReference`, `Blocked→Block` / `Detected→Log`, `details→matches`,
  and synthesizing `ruleName` from `ruleSetType`+`ruleId`; cover it with a test using an
  AppGw-shaped sample record.
- **Where:** `src/lawless_waf/duck/engine.py` (logs view) and `src/lawless_waf/duck/queries.py`.

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

## Scanner-heuristic tuning
- **What:** Thresholds in `src/lawless_waf/analysis/scanner.py` (min_blocks=20, min_groups=3,
  min_uris=15) are first-pass defaults. They correctly classify the sample day but have not
  been validated across a wider range of real days.
- **Why deferred:** needs more real datasets to calibrate.
- **Unblock:** run against several production days and tune; consider making thresholds
  configurable via `.env`.
- **Where:** `src/lawless_waf/analysis/scanner.py`.
