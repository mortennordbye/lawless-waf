/** Free-text search across the whole dataset, plus the fullscreen results view.
 *
 * Owns its own query/results/filter state: nothing outside this panel reads it. Remount it with
 * `key={selected}` to reset when the dataset changes. */
import { Loader2, Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, type GeoInfo, type ScopeParams, type SearchEvent } from "@/lib/api";

import { FullscreenPanel, FullscreenToggle } from "./Fullscreen";
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

  // Reset exclusions whenever new results arrive
  useEffect(() => { setExcludedIps(new Set()); }, [results]);

  function excludeIp(ip: string) {
    setExcludedIps((prev) => new Set([...prev, ip]));
  }
  function unexcludeIp(ip: string) {
    setExcludedIps((prev) => { const n = new Set(prev); n.delete(ip); return n; });
  }

  const visible = results?.filter((e) => !excludedIps.has(e.client_ip)) ?? null;
  const capped = results !== null && results.length >= limit;

  const excludedChips = excludedIps.size > 0 && (
    <div className="flex shrink-0 flex-wrap items-center gap-1.5">
      <span className="text-xs text-muted-foreground">Excluded:</span>
      {[...excludedIps].map((ip) => (
        <span key={ip} className="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 font-mono text-[11px]">
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
  );

  const resultsSection = results !== null && (
    results.length === 0 ? (
      <p className="text-sm text-muted-foreground">No events match that term.</p>
    ) : (
      <FullscreenPanel
        on={fullscreen}
        onExit={() => setFullscreen(false)}
        title="Search events"
        meta={capped && `capped at ${limit} — narrow the term or raise the limit to see more`}
      >
        <div className={fullscreen ? "flex min-h-0 flex-1 flex-col gap-2" : "space-y-2"}>
          {!fullscreen && capped && (
            <p className="text-xs text-muted-foreground">
              capped at {limit} — narrow the term or raise the limit to see more
            </p>
          )}
          {excludedChips}
          <SearchResultsTable
            events={visible!}
            onOpenRequest={onOpenRequest}
            fullscreen={fullscreen}
            ipGeo={ipGeo}
            onExclude={excludeIp}
            toolbar={<FullscreenToggle on={fullscreen} onToggle={() => setFullscreen((f) => !f)} />}
          />
        </div>
      </FullscreenPanel>
    )
  );

  return (
    <>
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
            <label className="flex items-center gap-1.5 whitespace-nowrap text-xs text-muted-foreground">
              Action
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
            </label>
            <label className="flex items-center gap-1.5 whitespace-nowrap text-xs text-muted-foreground">
              Limit
              <select
                className="h-7 rounded-md border border-input bg-background px-2 text-xs"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
              >
                <option value={200}>200</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
              </select>
            </label>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          {resultsSection}
        </CardContent>
      </Card>
    </>
  );
}
