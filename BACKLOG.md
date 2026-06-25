# Backlog

Known gaps deliberately left for later. WIP belongs on a branch, not here.

## MCP stdio adapter
- **What:** Expose the same analysis as native MCP tools (download, scanner-report,
  rule-drill, exclusion-context, exclusions-count) so Claude Code can connect directly
  instead of via HTTP/curl.
- **Why deferred:** REST was chosen as the primary, fastest-to-ship interface; the service
  layer was kept framework-agnostic specifically so this is a thin adapter, not a rewrite.
- **Unblock:** add an `mcp` entrypoint that maps each tool to the matching function in
  `src/lawless_waf/service.py` (no analysis logic should be duplicated).
- **Where:** `src/lawless_waf/service.py` (the core to reuse); new `src/lawless_waf/mcp_server.py`.

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
