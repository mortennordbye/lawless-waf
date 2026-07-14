/** Free-text search across the whole dataset, plus the fullscreen results view.
 *
 * Owns its own query/results/filter state: nothing outside this panel reads it. Remount it with
 * `key={selected}` to reset when the dataset changes. */
import { Loader2, Maximize2, Minimize2, Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, type GeoInfo, type ScopeParams, type SearchEvent } from "@/lib/api";

import { SearchResultsTable } from "./SearchResultsTable";

export function SearchPanel({
  selected,
  scope,
  onOpenRequest,
}: {
  selected: string;
  scope: ScopeParams;
  onOpenRequest: (ref: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchEvent[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [action, setAction] = useState<string>("");
  const [limit, setLimit] = useState<number>(200);
  const [ipGeo, setIpGeo] = useState<Record<string, GeoInfo>>({});

  const [fullscreen, setFullscreen] = useState(false);
  const [excludedIps, setExcludedIps] = useState<Set<string>>(new Set());

  function runSearch() {
    const q = query.trim();
    if (!q || !selected) return;
    setSearching(true);
    setError(null);
    api
      .searchEvents(selected, q, limit, scope, action || undefined)
      .then((r) => {
        setResults(r.events);
        const uniqueIps = [...new Set(r.events.map((e) => e.client_ip).filter(Boolean))];
        if (uniqueIps.length > 0) {
          api
            .geoipBatch(uniqueIps)
            .then((g) => setIpGeo((prev) => ({ ...prev, ...g.results })))
            .catch(() => {/* geo is best-effort */});
        }
      })
      .catch((e) => {
        setResults(null);
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setSearching(false));
  }

  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fullscreen]);

  // Reset exclusions whenever new results arrive
  useEffect(() => { setExcludedIps(new Set()); }, [results]);

  function excludeIp(ip: string) {
    setExcludedIps((prev) => new Set([...prev, ip]));
  }
  function unexcludeIp(ip: string) {
    setExcludedIps((prev) => { const n = new Set(prev); n.delete(ip); return n; });
  }

  const visible = results?.filter((e) => !excludedIps.has(e.client_ip)) ?? null;

  const resultsSection = results !== null && (
    results.length === 0 ? (
      <p className="text-sm text-muted-foreground">No events match that term.</p>
    ) : (
      <>
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {visible!.length}{results.length !== visible!.length && `/${results.length}`} event{visible!.length === 1 ? "" : "s"}
            {results.length >= limit && " (capped — narrow the term or increase the limit to see more)"}
          </p>
          <button
            onClick={() => setFullscreen((f) => !f)}
            title={fullscreen ? "Exit fullscreen" : "Expand to fullscreen"}
            className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            {fullscreen ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
            {fullscreen ? "Exit" : "Fullscreen"}
          </button>
        </div>
        {excludedIps.size > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Excluded:</span>
            {[...excludedIps].map((ip) => (
              <span
                key={ip}
                className="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 font-mono text-[11px]"
              >
                {ip}
                <button
                  onClick={() => unexcludeIp(ip)}
                  title="Remove exclusion"
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
            <button
              onClick={() => setExcludedIps(new Set())}
              className="text-[11px] text-muted-foreground underline hover:text-foreground"
            >
              Clear all
            </button>
          </div>
        )}
        <SearchResultsTable events={visible!} onOpenRequest={onOpenRequest} fullscreen={fullscreen} ipGeo={ipGeo} onExclude={excludeIp} />
      </>
    )
  );

  return (
    <>
      {fullscreen && (
        <div className="fixed inset-0 z-50 flex flex-col bg-background p-4 overflow-hidden">
          <div className="flex items-center justify-between mb-3 shrink-0">
            <div>
              <h2 className="text-base font-semibold">Search events</h2>
              {visible && visible.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  {visible.length}{results && results.length !== visible.length && `/${results.length}`} event{visible.length === 1 ? "" : "s"}
                  {results && results.length >= limit && " (capped)"}
                </p>
              )}
            </div>
            <button
              onClick={() => setFullscreen(false)}
              title="Exit fullscreen (Esc)"
              className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" /> Close
            </button>
          </div>
          {excludedIps.size > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 mb-2 shrink-0">
              <span className="text-xs text-muted-foreground">Excluded:</span>
              {[...excludedIps].map((ip) => (
                <span
                  key={ip}
                  className="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 font-mono text-[11px]"
                >
                  {ip}
                  <button onClick={() => unexcludeIp(ip)} className="text-muted-foreground hover:text-foreground">
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
              <button onClick={() => setExcludedIps(new Set())} className="text-[11px] text-muted-foreground underline hover:text-foreground">
                Clear all
              </button>
            </div>
          )}
          {visible && visible.length > 0 && (
            <SearchResultsTable events={visible} onOpenRequest={onOpenRequest} fullscreen={true} ipGeo={ipGeo} onExclude={excludeIp} />
          )}
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Search events</CardTitle>
          <CardDescription>
            Find every event touching an IP, URL, or host — across all rules and actions. The free-text replacement for
            ad-hoc KQL when you're chasing one specific request.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="e.g. /api/health, 203.0.113.10, or www.example.com"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runSearch()}
              className="font-mono"
            />
            <Button onClick={runSearch} disabled={searching || !query.trim()}>
              {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Search
            </Button>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <label className="text-xs text-muted-foreground whitespace-nowrap">Action</label>
              <select
                className="h-7 rounded-md border border-input bg-background px-2 text-xs"
                value={action}
                onChange={(e) => setAction(e.target.value)}
              >
                <option value="">All</option>
                <option value="Block">Block</option>
                <option value="Log">Log</option>
                <option value="AnomalyScoring">AnomalyScoring</option>
              </select>
            </div>
            <div className="flex items-center gap-1.5">
              <label className="text-xs text-muted-foreground whitespace-nowrap">Limit</label>
              <select
                className="h-7 rounded-md border border-input bg-background px-2 text-xs"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
              >
                <option value={200}>200</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
              </select>
            </div>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          {resultsSection}
        </CardContent>
      </Card>
    </>
  );
}
