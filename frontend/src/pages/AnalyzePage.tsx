import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  Bot,
  Check,
  ChevronsUpDown,
  Copy,
  GitCompare,
  Layers,
  Loader2,
  Radio,
  Search,
  ShieldCheck,
  Square,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { HBarChart, StatTile, Timeline } from "@/components/charts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  api,
  type CauseRule,
  type Coverage,
  type DatasetMeta,
  type DatasetSummary,
  type ExclusionContext,
  type ExclusionContextItem,
  type FiringDiff,
  type FiringRule,
  type IpVerdict,
  type RequestDetail,
  type RuleDiff,
  type RuleEvent,
  type ScannerReport,
  type ScopeParams,
  type SearchEvent,
} from "@/lib/api";

// The API container is bound to localhost:8000 (the UI proxies /api to it). An AI coding agent
// runs on the host, so it queries the API directly here.
const API_BASE = "http://localhost:8000/api";

// Live tailing targets the current UTC hour — Azure partitions the blobs by UTC.
const ymd = (d: Date) => d.toISOString().slice(0, 10);
const LIVE_INTERVALS = [15, 30, 60];

function aiBriefing(id: string): string {
  return `You are helping me tune Azure WAF false positives.

A local analysis API is running at ${API_BASE} (no auth — it's localhost-only; the real gate
is Azure). Use \`curl\` + \`jq\` to query it. It serves pre-downloaded WAF logs and classifies
blocks. It does NOT generate Terraform — you write the exclusions in waf-exclusions.tf yourself
from the structured facts it returns.

Dataset to analyze: ${id}

Do this, in order:

1. Scanner segmentation — READ THIS FIRST. Never write an exclusion for a scanner IP.
   curl -s ${API_BASE}/datasets/${id}/scanner-report | jq

2. What blocks real (non-scanner) traffic:
   curl -s "${API_BASE}/datasets/${id}/blocks-by-cause?exclude_scanners=true" | jq
   (If there are 0 blocks, check policy_modes in the summary — a Detection-mode policy only
    scores/logs and never blocks, so look at firing rules instead:
    curl -s ${API_BASE}/datasets/${id}/summary | jq '{actions, policy_modes, policies, top_ips}'
    curl -s ${API_BASE}/datasets/${id}/firing-rules | jq )

   Free-text drill — everything touching one IP / URL / host, across all rules (replaces KQL):
   curl -s "${API_BASE}/datasets/${id}/search?q=<IP_OR_URL>&limit=200" | jq

3. For each rule id that blocks legitimate traffic, get exclusion context:
   curl -s ${API_BASE}/datasets/${id}/rules/<RULE_ID>/exclusion-context | jq
   Per match variable it returns a "classification":
     - false_positive  -> good candidate for an exclusion
     - not_excludable   -> do NOT exclude (it tells you why)
     - attack / scanner_noise -> leave it blocked
   Drill to the actual requests (URI / IP / host / matched value) to confirm a false positive:
   curl -s "${API_BASE}/datasets/${id}/rules/<RULE_ID>/events?match_variable=<NAME>&limit=50" | jq
   Inspect ONE whole request (all rules it tripped + the parsed anomaly score):
   curl -s ${API_BASE}/datasets/${id}/requests/<TRACKING_REFERENCE> | jq

   Scope (append to any analysis call): &policy=<NAME> restricts to one WAF policy;
   repeat &dataset=<OTHER_ID> to analyze several days together (catches intermittent FPs).

4. Don't redo work — check what's already excluded against what's firing now:
   jq -Rs '{tf_content: .}' waf-exclusions.tf | curl -s -X POST \\
     ${API_BASE}/datasets/${id}/exclusions/coverage -H 'Content-Type: application/json' -d @- | jq
   It returns covered rules, uncovered_candidates (the real work), and duplicate/conflict/stale entries.

5. Write the exclusion in waf-exclusions.tf using the returned
   terraform.match_variable + terraform.selector + suggested_operator.

6. Guard the 100-exclusion limit (run before and after editing):
   jq -Rs '{tf_content: .}' waf-exclusions.tf | curl -s -X POST ${API_BASE}/exclusions/count \\
     -H 'Content-Type: application/json' -d @- | jq
   To stay under 100, prefer (in order): a) policy-level exclusions for globally-safe fields,
   b) StartsWith/EndsWith/Contains to merge selectors sharing a prefix/suffix/substring,
   c) rule-level exclusions only when the field is too broad to exclude globally.

7. After applying the Terraform, verify the fix — diff a fresh window against the old one:
   curl -s "${API_BASE}/datasets/<NEW_ID>/rules/<RULE_ID>/diff?against=${id}" | jq
   "resolved": true means the rule stopped firing.

Start with step 1 and walk me through what you find.`;
}

const CLASS_VARIANT: Record<string, "success" | "destructive" | "secondary" | "warning" | "outline"> = {
  false_positive: "success",
  attack: "destructive",
  scanner_noise: "secondary",
  not_excludable: "warning",
  mixed: "warning",
  unknown: "outline",
};

export function AnalyzePage({ active }: { active: boolean }) {
  const [datasets, setDatasets] = useState<DatasetMeta[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [summary, setSummary] = useState<DatasetSummary | null>(null);
  const [firing, setFiring] = useState<FiringRule[]>([]);
  const [scanner, setScanner] = useState<ScannerReport | null>(null);
  const [causes, setCauses] = useState<CauseRule[]>([]);
  const [ctx, setCtx] = useState<ExclusionContext | null>(null);
  const [ctxLoading, setCtxLoading] = useState<string | null>(null);
  const [ctxError, setCtxError] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showAi, setShowAi] = useState(false);
  const [inspect, setInspect] = useState<string | null>(null);
  const [events, setEvents] = useState<RuleEvent[] | null>(null);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [offline, setOffline] = useState<boolean | null>(null);

  // Live tailing of the current UTC hour.
  const [live, setLive] = useState(false);
  const [liveSeconds, setLiveSeconds] = useState(30);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [liveErr, setLiveErr] = useState<string | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);

  // Free-text search across the whole dataset.
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchEvent[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState<string | null>(null);

  // Scope: filter to one WAF policy, and/or span extra cached datasets (multi-day).
  const [policy, setPolicy] = useState("");
  const [policies, setPolicies] = useState<string[]>([]);
  const [spanDatasets, setSpanDatasets] = useState<string[]>([]);

  // Before/after diff against another dataset.
  const [against, setAgainst] = useState("");
  const [firingDiff, setFiringDiff] = useState<FiringDiff | null>(null);
  const [ruleDiff, setRuleDiff] = useState<RuleDiff | null>(null);

  // Full-request inspector (all rules + anomaly score for one tracking reference).
  const [reqRef, setReqRef] = useState<string | null>(null);
  const [reqDetail, setReqDetail] = useState<RequestDetail | null>(null);
  const [reqLoading, setReqLoading] = useState(false);

  // Overview stat-tile drill: which action tile is open ("all" = Total events), and its events.
  const [actionFilter, setActionFilter] = useState<string | null>(null);
  const [actionEvents, setActionEvents] = useState<SearchEvent[] | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  // Existing-exclusions coverage.
  const [coverageTf, setCoverageTf] = useState("");
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [coverageErr, setCoverageErr] = useState<string | null>(null);

  const scope: ScopeParams = { datasets: spanDatasets, policy: policy || null };

  useEffect(() => {
    if (!active) return;
    api.listDatasets().then((r) => setDatasets(r.datasets)).catch(() => undefined);
    api.health().then((h) => setOffline(h.offline)).catch(() => setOffline(null));
  }, [active]);

  // Reset the row-level drill whenever a different rule is investigated.
  useEffect(() => {
    setInspect(null);
    setEvents(null);
  }, [ctx]);

  const loadAnalysis = useCallback(
    async (id: string) => {
      const s: ScopeParams = { datasets: spanDatasets, policy: policy || null };
      const [sum, f, sc, c] = await Promise.all([
        api.summary(id, s),
        api.firingRules(id, s),
        api.scannerReport(id, s),
        api.blocksByCause(id, true, s),
      ]);
      setSummary(sum);
      setFiring(f.rules);
      setScanner(sc);
      setCauses(c.rules);
    },
    [policy, spanDatasets],
  );

  // Clear per-dataset view state when switching to a different dataset (not on live ticks).
  useEffect(() => {
    setCtx(null);
    setCtxError(null);
    setSummary(null);
    setFiring([]);
    setScanner(null);
    setCauses([]);
    setSearchResults(null);
    setSearchErr(null);
    setQuery("");
    setPolicy("");
    setSpanDatasets([]);
    setAgainst("");
    setFiringDiff(null);
    setReqRef(null);
    setReqDetail(null);
    setCoverage(null);
    setActionFilter(null);
    setActionEvents(null);
    setActionErr(null);
  }, [selected]);

  // Load / refresh the selected dataset. refreshNonce bumps on each live tick so the same
  // hour reloads in place without a full reset (no flicker). Re-runs when the scope changes.
  useEffect(() => {
    if (!selected) return;
    setErr(null);
    loadAnalysis(selected).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [selected, refreshNonce, loadAnalysis]);

  // Available policies for the scope selector (unfiltered list, independent of the chosen policy).
  useEffect(() => {
    if (!selected) {
      setPolicies([]);
      return;
    }
    api.policies(selected).then((r) => setPolicies(r.policies)).catch(() => setPolicies([]));
  }, [selected]);

  // Firing-rule diff whenever an "against" dataset is chosen.
  useEffect(() => {
    if (!selected || !against) {
      setFiringDiff(null);
      return;
    }
    api
      .diffFiring(selected, against, { datasets: spanDatasets, policy: policy || null })
      .then(setFiringDiff)
      .catch(() => setFiringDiff(null));
  }, [selected, against, policy, spanDatasets, refreshNonce]);

  // Per-rule diff for the rule under investigation, when comparing against another dataset.
  useEffect(() => {
    if (!ctx || !against) {
      setRuleDiff(null);
      return;
    }
    api
      .ruleDiff(selected, ctx.rule_id, against, null, { datasets: spanDatasets, policy: policy || null })
      .then(setRuleDiff)
      .catch(() => setRuleDiff(null));
  }, [ctx, against, selected, policy, spanDatasets]);

  function runSearch() {
    const q = query.trim();
    if (!q || !selected) return;
    setSearching(true);
    setSearchErr(null);
    api
      .searchEvents(selected, q, 200, scope)
      .then((r) => setSearchResults(r.events))
      .catch((e) => {
        setSearchResults(null);
        setSearchErr(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setSearching(false));
  }

  function investigate(ruleId: string) {
    setCtx(null);
    setCtxError(null);
    setCtxLoading(ruleId);
    api
      .exclusionContext(selected, ruleId, scope)
      .then((c) => setCtx(c))
      .catch((e) => setCtxError(e instanceof Error ? e.message : String(e)))
      .finally(() => setCtxLoading(null));
  }

  function showRequests(matchVariable: string) {
    if (!ctx) return;
    if (inspect === matchVariable) {
      setInspect(null);
      setEvents(null);
      return;
    }
    setInspect(matchVariable);
    setEvents(null);
    setLoadingEvents(true);
    api
      .ruleEvents(selected, ctx.rule_id, matchVariable, 200, scope)
      .then((r) => setEvents(r.events))
      .catch(() => setEvents([]))
      .finally(() => setLoadingEvents(false));
  }

  // Toggle the Overview drill for a stat tile. `filter` is "all" (Total events) or an action
  // name; the API takes null for "all". Clicking the open tile again closes the panel.
  function showActionEvents(filter: string) {
    if (actionFilter === filter) {
      setActionFilter(null);
      setActionEvents(null);
      return;
    }
    setActionFilter(filter);
    setActionEvents(null);
    setActionErr(null);
    setActionLoading(true);
    api
      .actionEvents(selected, filter === "all" ? null : filter, 200, scope)
      .then((r) => setActionEvents(r.events))
      .catch((e) => setActionErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setActionLoading(false));
  }

  function openRequest(ref: string) {
    setReqRef(ref);
    setReqDetail(null);
    setReqLoading(true);
    api
      .requestDetail(selected, ref, scope)
      .then(setReqDetail)
      .catch(() => setReqDetail(null))
      .finally(() => setReqLoading(false));
  }

  function runCoverage() {
    if (!selected) return;
    setCoverageLoading(true);
    setCoverageErr(null);
    api
      .exclusionCoverage(selected, coverageTf, scope)
      .then(setCoverage)
      .catch((e) => {
        setCoverage(null);
        setCoverageErr(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setCoverageLoading(false));
  }

  // Live loop: re-download the current UTC hour, then reload analysis. Chained (not an
  // interval) so ticks never overlap an in-flight download. Pauses when the tab is inactive.
  useEffect(() => {
    if (!live || !active) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function tick() {
      if (cancelled) return;
      try {
        const now = new Date();
        let meta = await api.createDataset(ymd(now), now.getUTCHours(), true);
        if (meta.line_count === 0) {
          // WAF logs lag a few minutes — early in the hour fall back to the previous one.
          const prev = new Date(now.getTime() - 3_600_000);
          meta = await api.createDataset(ymd(prev), prev.getUTCHours(), true);
        }
        if (cancelled) return;
        setSelected(meta.dataset_id);
        setRefreshNonce((n) => n + 1);
        setLiveErr(null);
        setLiveStatus(`updated ${new Date().toISOString().slice(11, 19)} UTC · ${meta.dataset_id} · ${meta.line_count} lines`);
      } catch (e) {
        if (!cancelled) setLiveErr(e instanceof Error ? e.message : String(e));
      }
      if (!cancelled) timer = setTimeout(tick, liveSeconds * 1000);
    }
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [live, liveSeconds, active]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-muted-foreground">Dataset:</span>
        <select
          className="h-9 rounded-md border border-input bg-transparent px-3 text-sm disabled:opacity-50"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          disabled={live}
        >
          <option value="">Select…</option>
          {datasets.map((d) => (
            <option key={d.dataset_id} value={d.dataset_id}>
              {d.dataset_id} ({d.line_count} lines)
            </option>
          ))}
        </select>

        <LiveControls
          live={live}
          offline={offline}
          seconds={liveSeconds}
          onToggle={() => setLive((v) => !v)}
          onSeconds={setLiveSeconds}
        />

        {selected && (
          <Button variant="outline" size="sm" className="ml-auto" onClick={() => setShowAi((v) => !v)}>
            <Bot className="h-4 w-4" /> Show your AI this data
          </Button>
        )}
        {err && <span className="w-full text-sm text-destructive">{err}</span>}
      </div>

      {selected && (
        <ScopeBar
          datasets={datasets}
          selected={selected}
          policies={policies}
          policy={policy}
          onPolicy={setPolicy}
          span={spanDatasets}
          onSpan={setSpanDatasets}
          against={against}
          onAgainst={setAgainst}
          disabled={live}
        />
      )}

      {live && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {liveErr ? (
            <span className="text-destructive">Live refresh failed: {liveErr} (retrying every {liveSeconds}s)</span>
          ) : (
            <span>{liveStatus ?? "Starting live tail of the current UTC hour…"}</span>
          )}
        </div>
      )}

      {selected && showAi && <AiBriefingCard id={selected} />}

      {summary && (
        <OverviewCard
          summary={summary}
          firing={firing}
          actionFilter={actionFilter}
          actionEvents={actionEvents}
          actionLoading={actionLoading}
          actionError={actionErr}
          onAction={showActionEvents}
          onOpenRequest={openRequest}
        />
      )}

      {firingDiff && <FiringDiffCard diff={firingDiff} onInvestigate={investigate} />}

      {selected && (
        <SearchCard
          query={query}
          onQuery={setQuery}
          onSearch={runSearch}
          searching={searching}
          results={searchResults}
          error={searchErr}
          onOpenRequest={openRequest}
        />
      )}

      {scanner && <ScannerCard scanner={scanner} />}

      {firing.length > 0 && (
        <FiringRulesCard firing={firing} ctxLoading={ctxLoading} onInvestigate={investigate} />
      )}

      {causes.length > 0 && (
        <BlocksByCauseCard causes={causes} ctxLoading={ctxLoading} onInvestigate={investigate} />
      )}

      {ctxError && (
        <Card>
          <CardContent className="flex items-center gap-2 py-4 text-sm text-destructive">
            <AlertCircle className="h-4 w-4" /> Couldn't load exclusion context: {ctxError}
          </CardContent>
        </Card>
      )}

      {ctx && (
        <Card>
          <CardHeader>
            <CardTitle>
              Exclusion context · {ctx.rule_group}-{ctx.rule_id}
            </CardTitle>
            <CardDescription>
              Facts to write the exclusion. The app does not generate HCL — copy the mapping into{" "}
              <code>waf-exclusions.tf</code>.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {ruleDiff && <RuleDiffBanner diff={ruleDiff} />}
            {ctx.contexts.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No excludable match variables for this rule — it only logs/scores without extractable match data (e.g. a
                bot or protocol rule), so there's nothing to whitelist here.
              </p>
            )}
            <div className="grid gap-4 md:grid-cols-2">
              {ctx.contexts.map((item) => (
                <ContextCard
                  key={item.match_variable_name}
                  item={item}
                  ruleGroup={ctx.rule_group}
                  ruleId={ctx.rule_id}
                  active={inspect === item.match_variable_name}
                  loading={loadingEvents && inspect === item.match_variable_name}
                  onShowRequests={() => showRequests(item.match_variable_name)}
                />
              ))}
            </div>
            {inspect && (
              <div className="rounded-md border p-3">
                <div className="mb-2 text-sm font-medium">
                  Matching requests · <span className="font-mono">{inspect}</span>
                </div>
                {loadingEvents ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" /> Loading…
                  </div>
                ) : (
                  events && <EventsTable events={events} onOpenRequest={openRequest} />
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {selected && (
        <CoverageCard
          tf={coverageTf}
          onTf={setCoverageTf}
          onRun={runCoverage}
          loading={coverageLoading}
          coverage={coverage}
          error={coverageErr}
          onInvestigate={investigate}
        />
      )}

      {reqRef && (
        <RequestDetailModal
          trackingRef={reqRef}
          detail={reqDetail}
          loading={reqLoading}
          onClose={() => {
            setReqRef(null);
            setReqDetail(null);
          }}
        />
      )}
    </div>
  );
}

function OverviewCard({
  summary,
  firing,
  actionFilter,
  actionEvents,
  actionLoading,
  actionError,
  onAction,
  onOpenRequest,
}: {
  summary: DatasetSummary;
  firing: FiringRule[];
  actionFilter: string | null;
  actionEvents: SearchEvent[] | null;
  actionLoading: boolean;
  actionError: string | null;
  onAction: (filter: string) => void;
  onOpenRequest: (ref: string) => void;
}) {
  const blocks = summary.actions.Block ?? 0;
  const anomaly = summary.actions.AnomalyScoring ?? 0;
  const log = summary.actions.Log ?? 0;
  const total = blocks + anomaly + log;

  const actionColor: Record<string, string> = {
    Block: "bg-red-500",
    AnomalyScoring: "bg-amber-500",
    Log: "bg-sky-500/60",
  };
  const topRules = [...firing]
    .sort((a, b) => b.total - a.total)
    .slice(0, 8)
    .map((r) => ({
      label: r.rule_id,
      value: r.total,
      hint: `${r.action} · ${r.rule_group}-${r.rule_id}`,
      color: actionColor[r.action] ?? "bg-primary",
    }));
  const topHosts = summary.top_hosts.map((h) => ({ label: h.host, value: h.n }));
  const topIps = summary.top_ips.map((p) => ({
    label: p.client_ip,
    value: p.n,
    hint: `${p.client_ip} · ${p.n} events${p.blocks ? ` · ${p.blocks} blocks` : ""}`,
    color: p.blocks ? "bg-red-500" : "bg-primary",
  }));
  const detection = summary.policy_modes.some((m) => /detection/i.test(m.mode));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Overview</CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>Everything the WAF saw in this window, at a glance.</span>
          {summary.policy_modes.map((m) => (
            <Badge key={m.mode} variant={/detection/i.test(m.mode) ? "warning" : "secondary"}>
              {m.mode} mode · {m.n.toLocaleString()}
            </Badge>
          ))}
          {summary.policies.map((p) => (
            <Badge key={p.policy} variant="outline">
              {p.policy}
            </Badge>
          ))}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <StatTile
            label="Total events"
            value={total.toLocaleString()}
            onClick={() => onAction("all")}
            active={actionFilter === "all"}
          />
          <StatTile
            label="Blocked"
            value={blocks.toLocaleString()}
            accent={blocks ? "text-red-500" : undefined}
            onClick={() => onAction("Block")}
            active={actionFilter === "Block"}
          />
          <StatTile
            label="Anomaly-scored"
            value={anomaly.toLocaleString()}
            accent={anomaly ? "text-amber-500" : undefined}
            onClick={() => onAction("AnomalyScoring")}
            active={actionFilter === "AnomalyScoring"}
          />
          <StatTile
            label="Logged"
            value={log.toLocaleString()}
            onClick={() => onAction("Log")}
            active={actionFilter === "Log"}
          />
          <StatTile label="Client IPs" value={summary.distinct_client_ips.toLocaleString()} />
          <StatTile label="Rules fired" value={summary.distinct_rules.toLocaleString()} />
        </div>

        {actionFilter && (
          <div className="rounded-md border p-3">
            <div className="mb-2 text-sm font-medium">
              {actionFilter === "all" ? "All events" : `${actionFilter} events`}
            </div>
            {actionLoading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading…
              </div>
            ) : actionError ? (
              <p className="text-sm text-destructive">{actionError}</p>
            ) : actionEvents && actionEvents.length === 0 ? (
              <p className="text-sm text-muted-foreground">No matching events.</p>
            ) : (
              actionEvents && (
                <>
                  <p className="mb-2 text-xs text-muted-foreground">
                    {actionEvents.length} event{actionEvents.length === 1 ? "" : "s"}
                    {actionEvents.length >= 200 && " (capped at 200 — use Search to narrow)"}
                  </p>
                  <SearchResultsTable events={actionEvents} onOpenRequest={onOpenRequest} />
                </>
              )
            )}
          </div>
        )}

        {blocks === 0 && detection && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-600 dark:text-amber-400">
            No blocks because the policy is in <b>Detection</b> mode — it only scores and logs. The rules below show
            what <i>would</i> block if it were switched to Prevention.
          </p>
        )}

        {summary.timeline.length > 0 && (
          <div>
            <div className="mb-2 text-sm font-medium">Activity over time</div>
            <Timeline points={summary.timeline} />
          </div>
        )}

        <div className="grid gap-6 md:grid-cols-3">
          {topRules.length > 0 && (
            <div>
              <div className="mb-2 text-sm font-medium">Top rules by volume</div>
              <HBarChart data={topRules} />
            </div>
          )}
          {topIps.length > 0 && (
            <div>
              <div className="mb-2 text-sm font-medium">Top client IPs</div>
              <HBarChart data={topIps} />
            </div>
          )}
          {topHosts.length > 0 && (
            <div>
              <div className="mb-2 text-sm font-medium">Top hosts</div>
              <HBarChart data={topHosts} />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function AiBriefingCard({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  const text = aiBriefing(id);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Bot className="h-5 w-5" /> Hand this to your AI agent
          </span>
          <Button size="sm" variant="outline" onClick={copy}>
            {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
            {copied ? "Copied" : "Copy prompt"}
          </Button>
        </CardTitle>
        <CardDescription>
          Paste this into your AI coding agent (Claude Code, Cursor, and the like). It queries this same local
          API over <code>curl</code> and walks the scanner → blocks → exclusion-context loop, then edits{" "}
          <code>waf-exclusions.tf</code> for you.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-muted/50 p-3 text-xs">{text}</pre>
      </CardContent>
    </Card>
  );
}

function ContextCard({
  item,
  ruleGroup,
  ruleId,
  active,
  loading,
  onShowRequests,
}: {
  item: ExclusionContextItem;
  ruleGroup: string | null;
  ruleId: string;
  active: boolean;
  loading: boolean;
  onShowRequests: () => void;
}) {
  const copy = () => {
    const tf = item.terraform;
    const line = tf
      ? `rule ${ruleId} (${ruleGroup}) → match_variable=${tf.match_variable} selector=${tf.selector} operator=${item.suggested_operator}`
      : `rule ${ruleId} (${ruleGroup}) ${item.match_variable_name}: NOT excludable — ${item.not_excludable_reason}`;
    navigator.clipboard.writeText(line);
  };

  return (
    <div className="rounded-md border p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="font-mono text-sm">{item.match_variable_name}</span>
        <Badge variant={CLASS_VARIANT[item.classification] ?? "outline"}>{item.classification}</Badge>
      </div>
      {item.terraform ? (
        <div className="space-y-1 text-sm">
          <div>
            <span className="text-muted-foreground">match_variable:</span> <b>{item.terraform.match_variable}</b>
          </div>
          <div>
            <span className="text-muted-foreground">selector:</span> <b>{item.terraform.selector}</b>
          </div>
          <div>
            <span className="text-muted-foreground">operator:</span> {item.suggested_operator}
          </div>
        </div>
      ) : (
        <p className="text-sm text-amber-500">{item.not_excludable_reason}</p>
      )}
      <div className="mt-2 text-xs text-muted-foreground">
        {item.hit_count} hits · {item.distinct_ips} IP(s)
        {item.scanner_share !== null && ` · scanner share ${(item.scanner_share * 100).toFixed(0)}%`}
        {item.evidence.length > 0 && ` · ${item.evidence.join(", ")}`}
      </div>
      {item.sample_values.length > 0 && (
        <div className="mt-2">
          <div className="text-xs font-medium text-muted-foreground">Sample values</div>
          <pre className="mt-1 max-h-24 overflow-auto rounded bg-muted/50 p-2 text-xs">
            {item.sample_values.join("\n")}
          </pre>
        </div>
      )}
      {item.affected_uris.length > 0 && (
        <div className="mt-2">
          <div className="text-xs font-medium text-muted-foreground">Affected URIs</div>
          <pre className="mt-1 max-h-24 overflow-auto rounded bg-muted/50 p-2 text-xs">
            {item.affected_uris.join("\n")}
          </pre>
        </div>
      )}

      <div className="mt-3 flex items-center gap-2">
        <Button size="sm" variant="ghost" onClick={copy}>
          <Copy className="h-3 w-3" /> Copy context
        </Button>
        <Button size="sm" variant={active ? "secondary" : "ghost"} onClick={onShowRequests} disabled={loading}>
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
          {active ? "Hide requests" : "Show matching requests"}
        </Button>
      </div>
    </div>
  );
}

function LiveControls({
  live,
  offline,
  seconds,
  onToggle,
  onSeconds,
}: {
  live: boolean;
  offline: boolean | null;
  seconds: number;
  onToggle: () => void;
  onSeconds: (s: number) => void;
}) {
  // Live tailing pulls from Azure on a timer — only possible with a live session.
  if (offline !== false) {
    return (
      <span
        className="text-xs text-muted-foreground"
        title="Live tailing downloads the current hour on a timer — needs a live Azure session (OFFLINE=false)."
      >
        Live unavailable {offline === true ? "(OFFLINE=true)" : "(no Azure session)"}
      </span>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <Button size="sm" variant={live ? "destructive" : "default"} onClick={onToggle}>
        {live ? (
          <>
            <Square className="h-4 w-4" /> Stop live
          </>
        ) : (
          <>
            <Radio className="h-4 w-4" /> Go live
          </>
        )}
      </Button>
      {live && (
        <span className="flex items-center gap-1 text-xs font-medium text-red-500">
          <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-red-500" /> LIVE
        </span>
      )}
      <select
        className="h-8 rounded-md border border-input bg-transparent px-2 text-xs"
        value={seconds}
        onChange={(e) => onSeconds(Number(e.target.value))}
        title="Refresh interval"
      >
        {LIVE_INTERVALS.map((s) => (
          <option key={s} value={s}>
            every {s}s
          </option>
        ))}
      </select>
    </div>
  );
}

function SearchCard({
  query,
  onQuery,
  onSearch,
  searching,
  results,
  error,
  onOpenRequest,
}: {
  query: string;
  onQuery: (q: string) => void;
  onSearch: () => void;
  searching: boolean;
  results: SearchEvent[] | null;
  error: string | null;
  onOpenRequest: (ref: string) => void;
}) {
  return (
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
            onChange={(e) => onQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && onSearch()}
            className="font-mono"
          />
          <Button onClick={onSearch} disabled={searching || !query.trim()}>
            {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            Search
          </Button>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {results !== null &&
          (results.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events match that term.</p>
          ) : (
            <>
              <p className="text-xs text-muted-foreground">
                {results.length} event{results.length === 1 ? "" : "s"}
                {results.length >= 200 && " (capped at 200 — narrow the term to see more)"}
              </p>
              <SearchResultsTable events={results} onOpenRequest={onOpenRequest} />
            </>
          ))}
      </CardContent>
    </Card>
  );
}

function InspectButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      title="Inspect the full request (all rules + anomaly score)"
      className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground"
    >
      <Search className="h-3 w-3" /> request
    </button>
  );
}

// Shared cell styles. Short columns stay on one line (nowrap); text-heavy columns wrap inside
// a bounded width instead of truncating, so nothing clips and the full value is readable. The
// whole table scrolls horizontally as a fallback for very wide rows.
const CELL = "p-2 align-top";
const SHORT = `${CELL} whitespace-nowrap`;
const WIDE = `${CELL} min-w-[220px] max-w-[420px] whitespace-normal break-all`;
const TH = "p-2 text-left font-medium whitespace-nowrap";

function fmtTime(t: string | undefined): string {
  return t?.slice(0, 19).replace("T", " ") ?? "";
}

// Click-to-sort for the row-level tables. Accessor maps are module-level constants (stable, so
// the memo doesn't re-sort every render). Click a header to sort by it; click again to flip
// direction — e.g. sort by Action to group all "Block" (deny) rows together.
type SortDir = "asc" | "desc";
type Accessors<T> = Record<string, (row: T) => string | number>;

function useSort<T>(rows: T[], accessors: Accessors<T>, initialKey = "", initialDir: SortDir = "desc") {
  const [key, setKey] = useState(initialKey);
  const [dir, setDir] = useState<SortDir>(initialDir);
  const sorted = useMemo(() => {
    const acc = accessors[key];
    if (!acc) return rows;
    const out = [...rows].sort((a, b) => {
      const av = acc(a);
      const bv = acc(b);
      return av < bv ? -1 : av > bv ? 1 : 0;
    });
    return dir === "desc" ? out.reverse() : out;
  }, [rows, key, dir, accessors]);
  const toggle = (k: string) => {
    if (k === key) setDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setKey(k);
      setDir("asc");
    }
  };
  return { sorted, sortKey: key, dir, toggle };
}

// Generic clickable sort control. Drops into ANY header cell — the raw `<th>` event tables and
// the shadcn `<TableHead>` data tables alike — so sorting isn't bolted onto one specific table.
function SortLabel({
  label,
  col,
  sortKey,
  dir,
  onSort,
}: {
  label: string;
  col: string;
  sortKey: string;
  dir: SortDir;
  onSort: (col: string) => void;
}) {
  const active = sortKey === col;
  return (
    <button
      type="button"
      onClick={() => onSort(col)}
      aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}
      className="inline-flex select-none items-center gap-1 hover:text-foreground"
    >
      {label}
      {active ? (
        dir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
      ) : (
        <ChevronsUpDown className="h-3 w-3 text-muted-foreground/40" />
      )}
    </button>
  );
}

const SEARCH_SORT: Accessors<SearchEvent> = {
  time: (e) => e.time ?? "",
  action: (e) => e.action,
  mode: (e) => e.policy_mode ?? "",
  rule: (e) => e.rule_id,
  client_ip: (e) => e.client_ip ?? "",
  host: (e) => e.host ?? "",
  uri: (e) => e.request_uri ?? "",
  msg: (e) => e.msg ?? "",
};

const EVENT_SORT: Accessors<RuleEvent> = {
  time: (e) => e.time ?? "",
  action: (e) => e.action,
  client_ip: (e) => e.client_ip ?? "",
  host: (e) => e.host ?? "",
  uri: (e) => e.request_uri ?? "",
  value: (e) => e.match_value ?? "",
  msg: (e) => e.msg ?? "",
};

const FIRING_SORT: Accessors<FiringRule> = {
  action: (r) => r.action,
  rule: (r) => r.rule_id,
  group: (r) => r.rule_group,
  count: (r) => r.total,
};

const CAUSE_SORT: Accessors<CauseRule> = {
  rule: (r) => r.rule_id,
  group: (r) => r.rule_group,
  msg: (r) => r.msg ?? "",
  hits: (r) => r.hits,
  ips: (r) => r.distinct_ips,
};

const SCANNER_SORT: Accessors<IpVerdict> = {
  ip: (v) => v.ip,
  blocks: (v) => v.blocks,
  groups: (v) => v.distinct_rule_groups,
  rules: (v) => v.distinct_rules,
  uris: (v) => v.distinct_uris,
  verdict: (v) => v.verdict,
};

function ModeBadge({ mode }: { mode: string | null }) {
  if (!mode) return null;
  return <Badge variant={/detection/i.test(mode) ? "warning" : "secondary"}>{mode}</Badge>;
}

function SearchResultsTable({
  events,
  onOpenRequest,
}: {
  events: SearchEvent[];
  onOpenRequest: (ref: string) => void;
}) {
  const { sorted, sortKey, dir, toggle } = useSort(events, SEARCH_SORT, "time");
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <div className="max-h-[28rem] overflow-auto rounded border text-xs">
      <table className="min-w-full">
        <thead className="sticky top-0 z-10 bg-muted/90 backdrop-blur">
          <tr>
            <th className={TH}><SortLabel label="Time (UTC)" col="time" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Action" col="action" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Mode" col="mode" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Rule" col="rule" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Client IP" col="client_ip" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Host" col="host" {...sortProps} /></th>
            <th className={TH}><SortLabel label="URI" col="uri" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Message" col="msg" {...sortProps} /></th>
            <th className={TH}></th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((e, i) => (
            <tr key={`${e.tracking_reference}-${i}`} className="border-t border-border/50 hover:bg-muted/40">
              <td className={`${SHORT} font-mono text-muted-foreground`}>{fmtTime(e.time)}</td>
              <td className={SHORT}>
                <Badge variant={e.action === "Block" ? "destructive" : "secondary"}>{e.action}</Badge>
              </td>
              <td className={SHORT}>
                <ModeBadge mode={e.policy_mode} />
              </td>
              <td className={`${SHORT} font-mono`} title={`${e.rule_group}-${e.rule_id}`}>
                {e.rule_id}
              </td>
              <td className={`${SHORT} font-mono`}>{e.client_ip}</td>
              <td className={SHORT}>{e.host}</td>
              <td className={`${WIDE} font-mono`}>{e.request_uri}</td>
              <td className={`${WIDE} text-muted-foreground`}>{e.msg}</td>
              <td className={SHORT}>
                <InspectButton onClick={() => onOpenRequest(e.tracking_reference)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EventsTable({
  events,
  onOpenRequest,
}: {
  events: RuleEvent[];
  onOpenRequest: (ref: string) => void;
}) {
  const { sorted, sortKey, dir, toggle } = useSort(events, EVENT_SORT, "time");
  const sortProps = { sortKey, dir, onSort: toggle };
  if (events.length === 0) {
    return <p className="mt-3 text-xs text-muted-foreground">No request-level matches found.</p>;
  }
  return (
    <div className="max-h-[28rem] overflow-auto rounded border text-xs">
      <table className="min-w-full">
        <thead className="sticky top-0 z-10 bg-muted/90 backdrop-blur">
          <tr>
            <th className={TH}><SortLabel label="Time (UTC)" col="time" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Action" col="action" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Client IP" col="client_ip" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Host" col="host" {...sortProps} /></th>
            <th className={TH}><SortLabel label="URI" col="uri" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Matched value" col="value" {...sortProps} /></th>
            <th className={TH}><SortLabel label="Message" col="msg" {...sortProps} /></th>
            <th className={TH}></th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((e, i) => (
            <tr key={`${e.tracking_reference}-${i}`} className="border-t border-border/50 hover:bg-muted/40">
              <td className={`${SHORT} font-mono text-muted-foreground`}>{fmtTime(e.time)}</td>
              <td className={SHORT}>
                <Badge variant={e.action === "Block" ? "destructive" : "secondary"}>{e.action}</Badge>
              </td>
              <td className={`${SHORT} font-mono`}>{e.client_ip}</td>
              <td className={SHORT}>{e.host}</td>
              <td className={`${WIDE} font-mono`}>{e.request_uri}</td>
              <td className={`${WIDE} font-mono text-muted-foreground`}>{e.match_value}</td>
              <td className={`${WIDE} text-muted-foreground`}>{e.msg}</td>
              <td className={SHORT}>
                <InspectButton onClick={() => onOpenRequest(e.tracking_reference)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScannerCard({ scanner }: { scanner: ScannerReport }) {
  const { sorted, sortKey, dir, toggle } = useSort(scanner.by_ip, SCANNER_SORT);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scanner segmentation</CardTitle>
        <CardDescription>
          {scanner.total_blocks} blocks total · {scanner.scanner_ips.length} scanner IP(s) ·{" "}
          <b>{scanner.genuine_fp_candidate_blocks}</b> genuine FP-candidate blocks. Review FP candidates only.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {scanner.total_blocks === 0 ? (
          <p className="text-sm text-muted-foreground">
            No blocks in this dataset — the WAF blocked nothing in this window. See <b>Firing rules</b> below for what
            was scored or logged (these would block only if their anomaly score crosses the threshold).
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead><SortLabel label="Client IP" col="ip" {...sortProps} /></TableHead>
                <TableHead><SortLabel label="Blocks" col="blocks" {...sortProps} /></TableHead>
                <TableHead><SortLabel label="Rule groups" col="groups" {...sortProps} /></TableHead>
                <TableHead><SortLabel label="Rules" col="rules" {...sortProps} /></TableHead>
                <TableHead><SortLabel label="URIs" col="uris" {...sortProps} /></TableHead>
                <TableHead><SortLabel label="Verdict" col="verdict" {...sortProps} /></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.slice(0, 15).map((v) => (
                <TableRow key={v.ip}>
                  <TableCell className="font-mono">{v.ip}</TableCell>
                  <TableCell>{v.blocks}</TableCell>
                  <TableCell>{v.distinct_rule_groups}</TableCell>
                  <TableCell>{v.distinct_rules}</TableCell>
                  <TableCell>{v.distinct_uris}</TableCell>
                  <TableCell>
                    <Badge variant={v.verdict === "scanner" ? "destructive" : "success"}>{v.verdict}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function FiringRulesCard({
  firing,
  ctxLoading,
  onInvestigate,
}: {
  firing: FiringRule[];
  ctxLoading: string | null;
  onInvestigate: (id: string) => void;
}) {
  const { sorted, sortKey, dir, toggle } = useSort(firing, FIRING_SORT);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Firing rules</CardTitle>
        <CardDescription>
          Every rule that triggered in this window, by action and volume. <code>AnomalyScoring</code> rows score a
          request; a <code>Block</code> happens only when the combined score crosses the policy threshold.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead><SortLabel label="Action" col="action" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Rule" col="rule" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Group" col="group" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Count" col="count" {...sortProps} /></TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.slice(0, 25).map((r) => (
              <TableRow key={`${r.action}-${r.rule_name}`}>
                <TableCell>
                  <Badge variant={r.action === "Block" ? "destructive" : "secondary"}>{r.action}</Badge>
                </TableCell>
                <TableCell className="font-mono">{r.rule_id}</TableCell>
                <TableCell>{r.rule_group}</TableCell>
                <TableCell>{r.total.toLocaleString()}</TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={ctxLoading === r.rule_id}
                    onClick={() => onInvestigate(r.rule_id)}
                  >
                    {ctxLoading === r.rule_id ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
                    Investigate
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function BlocksByCauseCard({
  causes,
  ctxLoading,
  onInvestigate,
}: {
  causes: CauseRule[];
  ctxLoading: string | null;
  onInvestigate: (id: string) => void;
}) {
  const { sorted, sortKey, dir, toggle } = useSort(causes, CAUSE_SORT);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Blocks by cause (scanners excluded)</CardTitle>
        <CardDescription>Rules that block real (non-scanner) traffic. Click one to get exclusion context.</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead><SortLabel label="Rule" col="rule" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Group" col="group" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Message" col="msg" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="Hits" col="hits" {...sortProps} /></TableHead>
              <TableHead><SortLabel label="IPs" col="ips" {...sortProps} /></TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.map((r) => (
              <TableRow key={r.rule_name}>
                <TableCell className="font-mono">{r.rule_id}</TableCell>
                <TableCell>{r.rule_group}</TableCell>
                <TableCell className="max-w-md whitespace-normal break-words">{r.msg}</TableCell>
                <TableCell>{r.hits.toLocaleString()}</TableCell>
                <TableCell>{r.distinct_ips}</TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={ctxLoading === r.rule_id}
                    onClick={() => onInvestigate(r.rule_id)}
                  >
                    {ctxLoading === r.rule_id ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
                    Context
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

const DIFF_COLOR: Record<string, string> = {
  resolved: "text-emerald-500",
  gone: "text-emerald-500",
  new: "text-red-500",
  increased: "text-amber-500",
  reduced: "text-sky-500",
  unchanged: "text-muted-foreground",
};

function ScopeBar({
  datasets,
  selected,
  policies,
  policy,
  onPolicy,
  span,
  onSpan,
  against,
  onAgainst,
  disabled,
}: {
  datasets: DatasetMeta[];
  selected: string;
  policies: string[];
  policy: string;
  onPolicy: (p: string) => void;
  span: string[];
  onSpan: (s: string[]) => void;
  against: string;
  onAgainst: (a: string) => void;
  disabled: boolean;
}) {
  const others = datasets.filter((d) => d.dataset_id !== selected);
  const toggleSpan = (id: string) => onSpan(span.includes(id) ? span.filter((x) => x !== id) : [...span, id]);
  const sel = "h-8 rounded-md border border-input bg-transparent px-2 text-sm disabled:opacity-50";
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-3 py-3 text-sm">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="text-muted-foreground">Policy</span>
          <select
            className={sel}
            value={policy}
            disabled={disabled || policies.length === 0}
            onChange={(e) => onPolicy(e.target.value)}
            title={policies.length === 0 ? "No policy field in this data" : "Scope analysis to one WAF policy"}
          >
            <option value="">All policies</option>
            {policies.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>

        {others.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground">Analyze across</span>
            {others.map((d) => (
              <button
                key={d.dataset_id}
                disabled={disabled}
                onClick={() => toggleSpan(d.dataset_id)}
                className={`rounded-md border px-2 py-1 text-xs disabled:opacity-50 ${
                  span.includes(d.dataset_id)
                    ? "border-primary bg-primary/10 text-foreground"
                    : "text-muted-foreground hover:bg-muted"
                }`}
                title="Include this dataset in the analysis (multi-day)"
              >
                + {d.dataset_id}
              </button>
            ))}
          </div>
        )}

        {others.length > 0 && (
          <div className="flex items-center gap-2">
            <GitCompare className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">Compare against</span>
            <select
              className={sel}
              value={against}
              disabled={disabled}
              onChange={(e) => onAgainst(e.target.value)}
              title="Diff this dataset against another to verify an exclusion took effect"
            >
              <option value="">None</option>
              {others.map((d) => (
                <option key={d.dataset_id} value={d.dataset_id}>
                  {d.dataset_id}
                </option>
              ))}
            </select>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FiringDiffCard({ diff, onInvestigate }: { diff: FiringDiff; onInvestigate: (ruleId: string) => void }) {
  const changed = diff.rules.filter((r) => r.status !== "unchanged");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <GitCompare className="h-5 w-5" /> What changed
        </CardTitle>
        <CardDescription>
          Rule volume in <span className="font-mono">{diff.before_id}</span> (before) vs{" "}
          <span className="font-mono">{diff.after_id}</span> (after).{" "}
          {changed.length === 0
            ? "No rule changed between these windows."
            : `${changed.length} rule(s) changed — green means it stopped firing.`}
        </CardDescription>
      </CardHeader>
      {changed.length > 0 && (
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead>Group</TableHead>
                <TableHead>Before</TableHead>
                <TableHead>After</TableHead>
                <TableHead>Δ</TableHead>
                <TableHead>Status</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {changed.slice(0, 25).map((r) => (
                <TableRow key={r.rule_id}>
                  <TableCell className="font-mono">{r.rule_id}</TableCell>
                  <TableCell>{r.rule_group}</TableCell>
                  <TableCell className="tabular-nums">{r.before.toLocaleString()}</TableCell>
                  <TableCell className="tabular-nums">{r.after.toLocaleString()}</TableCell>
                  <TableCell className={`tabular-nums ${DIFF_COLOR[r.status]}`}>
                    {r.delta > 0 ? "+" : ""}
                    {r.delta.toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <span className={`text-xs font-medium ${DIFF_COLOR[r.status]}`}>{r.status}</span>
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="outline" onClick={() => onInvestigate(r.rule_id)}>
                      Investigate
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      )}
    </Card>
  );
}

function RuleDiffBanner({ diff }: { diff: RuleDiff }) {
  const status = diff.resolved
    ? "resolved"
    : diff.after_hits < diff.before_hits
      ? "reduced"
      : diff.after_hits > diff.before_hits
        ? "increased"
        : "unchanged";
  return (
    <div
      className={`rounded-md border p-3 text-sm ${
        diff.resolved ? "border-emerald-500/40 bg-emerald-500/10" : "bg-muted/40"
      }`}
    >
      <span className="font-medium">Before/after · </span>
      <span className="font-mono">{diff.before_id}</span> <b className="tabular-nums">{diff.before_hits}</b> hits →{" "}
      <span className="font-mono">{diff.after_id}</span> <b className="tabular-nums">{diff.after_hits}</b> hits ·{" "}
      <span className={`font-medium ${DIFF_COLOR[status]}`}>{status}</span>
      {diff.resolved && " — this rule stopped firing (exclusion looks effective)."}
    </div>
  );
}

function RequestDetailModal({
  trackingRef,
  detail,
  loading,
  onClose,
}: {
  trackingRef: string;
  detail: RequestDetail | null;
  loading: boolean;
  onClose: () => void;
}) {
  const head = detail?.rows[0];
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/50 p-4"
      onClick={onClose}
    >
      <Card className="my-8 w-full max-w-4xl" onClick={(e) => e.stopPropagation()}>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Search className="h-5 w-5" /> Request detail
            </span>
            <Button size="sm" variant="ghost" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </CardTitle>
          <CardDescription className="break-all font-mono">{trackingRef}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading…
            </div>
          ) : !detail || detail.rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">No rows found for this request in the current scope.</p>
          ) : (
            <>
              {head && (
                <div className="space-y-1 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    {detail.anomaly_score !== null && (
                      <Badge variant={detail.anomaly_score >= 5 ? "destructive" : "secondary"}>
                        anomaly score {detail.anomaly_score}
                      </Badge>
                    )}
                    <ModeBadge mode={head.policy_mode} />
                    {head.policy && <Badge variant="outline">{head.policy}</Badge>}
                    <span className="text-muted-foreground">{detail.rows.length} rule events</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">client:</span>{" "}
                    <span className="font-mono">{head.client_ip}</span>
                  </div>
                  <div className="break-all">
                    <span className="text-muted-foreground">uri:</span>{" "}
                    <span className="font-mono">{head.request_uri}</span>
                  </div>
                  {detail.anomaly_score !== null && (
                    <p className="text-xs text-muted-foreground">
                      The default-ruleset block threshold is typically 5 — a higher score means more rules would need
                      excluding to un-block this request.
                    </p>
                  )}
                </div>
              )}
              <div className="max-h-[26rem] overflow-auto rounded border text-xs">
                <table className="min-w-full">
                  <thead className="sticky top-0 z-10 bg-muted/90 backdrop-blur">
                    <tr>
                      <th className={TH}>Action</th>
                      <th className={TH}>Rule</th>
                      <th className={TH}>Group</th>
                      <th className={TH}>Matched variables</th>
                      <th className={TH}>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.rows.map((r, i) => (
                      <tr key={i} className="border-t border-border/50">
                        <td className={SHORT}>
                          <Badge variant={r.action === "Block" ? "destructive" : "secondary"}>{r.action}</Badge>
                        </td>
                        <td className={`${SHORT} font-mono`}>{r.rule_id}</td>
                        <td className={SHORT}>{r.rule_group}</td>
                        <td className={WIDE}>
                          {r.match_variable_names.length === 0 ? (
                            <span className="text-muted-foreground">—</span>
                          ) : (
                            r.match_variable_names.map((name, j) => (
                              <div key={j} className="font-mono">
                                {name}
                                {r.match_values[j] ? (
                                  <span className="text-muted-foreground"> = {r.match_values[j]}</span>
                                ) : null}
                              </div>
                            ))
                          )}
                        </td>
                        <td className={`${WIDE} text-muted-foreground`}>{r.msg}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CoverageCard({
  tf,
  onTf,
  onRun,
  loading,
  coverage,
  error,
  onInvestigate,
}: {
  tf: string;
  onTf: (t: string) => void;
  onRun: () => void;
  loading: boolean;
  coverage: Coverage | null;
  error: string | null;
  onInvestigate: (ruleId: string) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" /> Existing exclusions coverage
        </CardTitle>
        <CardDescription>
          Paste your <code>waf-exclusions.tf</code>. See which firing rules are already covered (skip them), which
          false-positive candidates are still uncovered (the work left), and any duplicate / conflicting / stale
          exclusions — without leaving the app.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <textarea
          className="h-32 w-full rounded-md border border-input bg-transparent p-2 font-mono text-xs"
          placeholder={'exclusion {\n  match_variable = "QueryStringArgNames"\n  operator       = "Equals"\n  selector       = "returnUrl"\n}'}
          value={tf}
          onChange={(e) => onTf(e.target.value)}
        />
        <Button onClick={onRun} disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
          Check coverage
        </Button>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {coverage && <CoverageResults coverage={coverage} onInvestigate={onInvestigate} />}
      </CardContent>
    </Card>
  );
}

function CoverageResults({ coverage, onInvestigate }: { coverage: Coverage; onInvestigate: (ruleId: string) => void }) {
  const covered = coverage.coverage.filter((c) => c.covered_by).length;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="Exclusions in file" value={coverage.total_exclusions} />
        <StatTile
          label="Slots remaining"
          value={coverage.remaining}
          accent={coverage.remaining < 10 ? "text-red-500" : undefined}
        />
        <StatTile label="Firing matches covered" value={covered} accent={covered ? "text-emerald-500" : undefined} />
        <StatTile
          label="Uncovered candidates"
          value={coverage.uncovered_candidates.length}
          accent={coverage.uncovered_candidates.length ? "text-amber-500" : undefined}
        />
      </div>

      {coverage.truncated && (
        <p className="text-xs text-amber-500">
          Only the first {coverage.rules_checked} firing rules were cross-referenced (the rest were skipped for speed).
        </p>
      )}

      {coverage.uncovered_candidates.length > 0 && (
        <div>
          <div className="mb-1 text-sm font-medium">Uncovered false-positive candidates (the work left)</div>
          <div className="overflow-auto rounded border text-xs">
            <table className="min-w-full">
              <thead className="bg-muted/80">
                <tr>
                  <th className={TH}>Rule</th>
                  <th className={TH}>Match variable</th>
                  <th className={TH}>Class</th>
                  <th className={TH}>Hits</th>
                  <th className={TH}></th>
                </tr>
              </thead>
              <tbody>
                {coverage.uncovered_candidates.map((c, i) => (
                  <tr key={i} className="border-t border-border/50">
                    <td className={`${SHORT} font-mono`}>{c.rule_id}</td>
                    <td className={`${SHORT} font-mono`}>{c.match_variable_name}</td>
                    <td className={SHORT}>
                      <Badge variant={CLASS_VARIANT[c.classification] ?? "outline"}>{c.classification}</Badge>
                    </td>
                    <td className={`${SHORT} tabular-nums`}>{c.hit_count.toLocaleString()}</td>
                    <td className={SHORT}>
                      <Button size="sm" variant="outline" onClick={() => onInvestigate(c.rule_id)}>
                        Investigate
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(coverage.duplicates.length > 0 || coverage.conflicts.length > 0 || coverage.stale_exclusions.length > 0) && (
        <div className="grid gap-3 text-xs md:grid-cols-3">
          <ExclusionList
            title="Duplicates"
            tone="text-amber-500"
            items={coverage.duplicates.map((e) => `${e.match_variable} ${e.operator} "${e.selector}"`)}
          />
          <ExclusionList
            title="Conflicts (same selector, different operator)"
            tone="text-red-500"
            items={coverage.conflicts.map(
              (e) => `${e.match_variable} "${e.selector}": ${e.operator} vs ${e.conflicts_with_operator}`,
            )}
          />
          <ExclusionList
            title="Stale (match nothing firing now)"
            tone="text-muted-foreground"
            items={coverage.stale_exclusions.map((e) => `${e.match_variable} ${e.operator} "${e.selector}"`)}
          />
        </div>
      )}
    </div>
  );
}

function ExclusionList({ title, tone, items }: { title: string; tone: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded-md border p-2">
      <div className={`mb-1 font-medium ${tone}`}>
        {title} ({items.length})
      </div>
      <ul className="space-y-0.5">
        {items.map((it, i) => (
          <li key={i} className="break-all font-mono text-muted-foreground">
            {it}
          </li>
        ))}
      </ul>
    </div>
  );
}
