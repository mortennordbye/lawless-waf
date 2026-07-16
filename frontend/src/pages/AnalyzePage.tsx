import {
  AlertCircle,
  Check,
  Copy,
  Database,
  GitCompare,
  Layers,
  Loader2,
  Search,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { ActivityFeed } from "@/components/ActivityFeed";
import { HBarChart, StatTile, Timeline } from "@/components/charts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  api,
  type CauseRule,
  type DatasetMeta,
  type DatasetSummary,
  type ExclusionContext,
  type ExclusionContextItem,
  type FiringDiff,
  type FiringRule,
  type IpVerdict,
  type RuleDiff,
  type RuleEvent,
  type ScannerReport,
  type ScopeParams,
  type SearchEvent,
} from "@/lib/api";

import { CoveragePanel } from "./analyze/CoveragePanel";
import { FullscreenPanel, FullscreenToggle } from "./analyze/Fullscreen";
import { LiveControls, LiveStatus, useLiveTail } from "./analyze/LiveTail";
import { RequestInspector } from "./analyze/RequestInspector";
import { SearchPanel } from "./analyze/SearchPanel";
import { SearchResultsTable } from "./analyze/SearchResultsTable";
import {
  type Accessors,
  CLASS_VARIANT,
  CopyButton,
  FilterValue,
  InspectButton,
  RowFilterBar,
  SHORT,
  SortLabel,
  TH,
  WIDE,
  fmtTime,
  useCapped,
  useRowFilter,
  useSort,
} from "./analyze/shared";

export function AnalyzePage({
  active,
  initialDataset,
}: {
  active: boolean;
  /** Dataset handed over from the Download tab; selected once it shows up in the list. */
  initialDataset?: string | null;
}) {
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
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [inspect, setInspect] = useState<string | null>(null);
  const [events, setEvents] = useState<RuleEvent[] | null>(null);
  const [eventsErr, setEventsErr] = useState<string | null>(null);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [offline, setOffline] = useState<boolean | null>(null);
  const [datasetsErr, setDatasetsErr] = useState<string | null>(null);

  // Live tailing of the current UTC hour. Only the on/off flag lives here (it disables the
  // dataset controls); the loop and its settings are in useLiveTail.
  const [live, setLive] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);

  // Scope: filter to one WAF policy, and/or span extra cached datasets (multi-day).
  const [policy, setPolicy] = useState("");
  const [policies, setPolicies] = useState<string[]>([]);
  const [spanDatasets, setSpanDatasets] = useState<string[]>([]);

  // Before/after diff against another dataset.
  const [against, setAgainst] = useState("");
  const [firingDiff, setFiringDiff] = useState<FiringDiff | null>(null);
  const [firingDiffErr, setFiringDiffErr] = useState<string | null>(null);
  const [ruleDiff, setRuleDiff] = useState<RuleDiff | null>(null);
  const [ruleDiffErr, setRuleDiffErr] = useState<string | null>(null);

  // Which request the inspector has open; it fetches the detail itself.
  const [reqRef, setReqRef] = useState<string | null>(null);

  // Overview stat-tile drill: which action tile is open ("all" = Total events), and its events.
  const [actionFilter, setActionFilter] = useState<string | null>(null);
  const [actionEvents, setActionEvents] = useState<SearchEvent[] | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const scope: ScopeParams = { datasets: spanDatasets, policy: policy || null };

  const liveTail = useLiveTail({
    live,
    active,
    onDataset: setSelected,
    onTick: () => setRefreshNonce((n) => n + 1),
  });

  useEffect(() => {
    if (!active) return;
    api
      .listDatasets()
      .then((r) => {
        setDatasets(r.datasets);
        setDatasetsErr(null);
      })
      .catch((e) =>
        setDatasetsErr(
          `Could not reach the backend — is the container running? (${e instanceof Error ? e.message : String(e)})`,
        ),
      );
    api.health().then((h) => setOffline(h.offline)).catch(() => setOffline(null));
  }, [active]);

  // Select the dataset the Download tab handed over, once the list has caught up with it (the
  // download that produced it may still have been in flight when it was passed).
  useEffect(() => {
    if (!initialDataset) return;
    if (datasets.some((d) => d.dataset_id === initialDataset)) setSelected(initialDataset);
  }, [initialDataset, datasets]);

  // Reset the row-level drill whenever a different rule is investigated.
  useEffect(() => {
    setInspect(null);
    setEvents(null);
    setEventsErr(null);
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

  // Clear per-dataset view state when switching to a different dataset (not on live ticks). The
  // panels reset themselves: SearchPanel is remounted by key, CoveragePanel watches `selected`.
  useEffect(() => {
    setCtx(null);
    setCtxError(null);
    setSummary(null);
    setFiring([]);
    setScanner(null);
    setCauses([]);
    setPolicy("");
    setSpanDatasets([]);
    setAgainst("");
    setFiringDiff(null);
    setReqRef(null);
    setActionFilter(null);
    setActionEvents(null);
    setActionErr(null);
  }, [selected]);

  // Load / refresh the selected dataset. refreshNonce bumps on each live tick so the same
  // hour reloads in place without a full reset (no flicker). Re-runs when the scope changes.
  useEffect(() => {
    if (!selected) return;
    setErr(null);
    setAnalysisLoading(true);
    loadAnalysis(selected)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setAnalysisLoading(false));
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
      setFiringDiffErr(null);
      return;
    }
    api
      .diffFiring(selected, against, { datasets: spanDatasets, policy: policy || null })
      .then((d) => {
        setFiringDiff(d);
        setFiringDiffErr(null);
      })
      .catch((e) => {
        setFiringDiff(null);
        setFiringDiffErr(e instanceof Error ? e.message : String(e));
      });
  }, [selected, against, policy, spanDatasets, refreshNonce]);

  // Per-rule diff for the rule under investigation, when comparing against another dataset.
  useEffect(() => {
    if (!ctx || !against) {
      setRuleDiff(null);
      setRuleDiffErr(null);
      return;
    }
    api
      .ruleDiff(selected, ctx.rule_id, against, null, { datasets: spanDatasets, policy: policy || null })
      .then((d) => {
        setRuleDiff(d);
        setRuleDiffErr(null);
      })
      .catch((e) => {
        setRuleDiff(null);
        setRuleDiffErr(e instanceof Error ? e.message : String(e));
      });
  }, [ctx, against, selected, policy, spanDatasets]);

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
    setEventsErr(null);
    setLoadingEvents(true);
    api
      .ruleEvents(selected, ctx.rule_id, matchVariable, 200, scope)
      .then((r) => setEvents(r.events))
      .catch((e) => setEventsErr(e instanceof Error ? e.message : String(e)))
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

  return (
    <div className="space-y-6">
      {datasetsErr && <p className="text-sm text-destructive">{datasetsErr}</p>}

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-3 text-sm text-muted-foreground">
          Dataset:
          <Select
            className="w-auto"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={live}
          >
            <option value="">Select…</option>
            {datasets.map((d) => (
              <option key={d.dataset_id} value={d.dataset_id}>
                {d.dataset_id} ({d.line_count.toLocaleString()} lines)
              </option>
            ))}
          </Select>
        </label>

        <LiveControls
          live={live}
          offline={offline}
          seconds={liveTail.seconds}
          full={liveTail.full}
          onToggle={() => setLive((v) => !v)}
          onSeconds={liveTail.setSeconds}
          onFull={() => liveTail.setFull((v) => !v)}
        />

        {err && <span className="w-full text-sm text-destructive">{err}</span>}
      </div>

      {!datasetsErr && !live && !selected && (
        <Card>
          <CardContent className="py-12 text-center">
            <Database className="mx-auto mb-3 h-8 w-8 text-muted-foreground/60" />
            {datasets.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No datasets yet. Go to the <b className="text-foreground">Download</b> tab to pull a
                time range of WAF logs, then come back here.
              </p>
            ) : (
              <p className="text-sm text-muted-foreground">Select a dataset above to see the analysis.</p>
            )}
          </CardContent>
        </Card>
      )}

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

      {live && <LiveStatus status={liveTail.status} error={liveTail.error} seconds={liveTail.seconds} />}

      {analysisLoading && !summary && (
        <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-4 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Analyzing {selected}
          {(() => {
            const n = datasets.find((d) => d.dataset_id === selected)?.line_count;
            return n ? ` (${n.toLocaleString()} lines)` : "";
          })()}
          … a big day can take a moment.
        </div>
      )}

      {summary && (
        <OverviewCard
          summary={summary}
          firing={firing}
          actionFilter={actionFilter}
          actionEvents={actionEvents}
          actionLoading={actionLoading}
          actionError={actionErr}
          onAction={showActionEvents}
          onOpenRequest={setReqRef}
        />
      )}

      {/* Below the Overview: for a first-time visitor with no MCP client connected this is dead space. */}
      <ActivityFeed />

      {firingDiffErr && (
        <Card>
          <CardContent className="flex items-center gap-2 py-4 text-sm text-destructive">
            <AlertCircle className="h-4 w-4" /> Couldn't compare against {against}: {firingDiffErr}
          </CardContent>
        </Card>
      )}
      {firingDiff && <FiringDiffCard diff={firingDiff} onInvestigate={investigate} />}

      {selected && (
        // Remounting on dataset change is the reset: results from the old day must not linger.
        <SearchPanel key={selected} selected={selected} scope={scope} onOpenRequest={setReqRef} />
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
            {ruleDiffErr && (
              <p className="text-sm text-destructive">
                Couldn't compare this rule against {against}: {ruleDiffErr}
              </p>
            )}
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
                ) : eventsErr ? (
                  <p className="text-sm text-destructive">Could not load matching requests: {eventsErr}</p>
                ) : (
                  events && <EventsTable events={events} onOpenRequest={setReqRef} />
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {selected && <CoveragePanel selected={selected} scope={scope} onInvestigate={investigate} />}

      {reqRef && (
        <RequestInspector
          trackingRef={reqRef}
          selected={selected}
          scope={scope}
          onClose={() => setReqRef(null)}
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
  const [drillFullscreen, setDrillFullscreen] = useState(false);
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
      // Rows are per rule+action, so a rule id can appear twice — name the action or it reads as a duplicate.
      label: `${r.rule_id} · ${r.action}`,
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
                <FullscreenPanel
                  on={drillFullscreen}
                  onExit={() => setDrillFullscreen(false)}
                  title={actionFilter === "all" ? "All events" : `${actionFilter} events`}
                  meta={actionEvents.length >= 200 && "capped at 200 — use Search to narrow"}
                >
                  <div className={drillFullscreen ? "flex min-h-0 flex-1 flex-col gap-2" : "space-y-2"}>
                    {!drillFullscreen && actionEvents.length >= 200 && (
                      <p className="text-xs text-muted-foreground">capped at 200 — use Search to narrow</p>
                    )}
                    <SearchResultsTable
                      events={actionEvents}
                      onOpenRequest={onOpenRequest}
                      fullscreen={drillFullscreen}
                      toolbar={
                        <FullscreenToggle on={drillFullscreen} onToggle={() => setDrillFullscreen((f) => !f)} />
                      }
                    />
                  </div>
                </FullscreenPanel>
              )
            )}
          </div>
        )}

        {blocks === 0 && detection && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-400">
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
  // This card is the deliverable, so the copy button has to say whether it worked.
  const [copied, setCopied] = useState<boolean | null>(null);
  useEffect(() => {
    if (copied === null) return;
    const t = setTimeout(() => setCopied(null), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  const copy = async () => {
    const tf = item.terraform;
    const line = tf
      ? `rule ${ruleId} (${ruleGroup}) → match_variable=${tf.match_variable} selector=${tf.selector} operator=${item.suggested_operator}`
      : `rule ${ruleId} (${ruleGroup}) ${item.match_variable_name}: NOT excludable — ${item.not_excludable_reason}`;
    try {
      await navigator.clipboard.writeText(line);
      setCopied(true);
    } catch {
      setCopied(false); // no clipboard permission, or a non-secure context
    }
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
        <Button size="sm" variant="ghost" onClick={copy} className={copied === false ? "text-destructive" : undefined}>
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : copied === false ? "Copy failed" : "Copy context"}
        </Button>
        <Button size="sm" variant={active ? "secondary" : "ghost"} onClick={onShowRequests} disabled={loading}>
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
          {active ? "Hide requests" : "Show matching requests"}
        </Button>
      </div>
    </div>
  );
}

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

function EventsTable({
  events,
  onOpenRequest,
}: {
  events: RuleEvent[];
  onOpenRequest: (ref: string) => void;
}) {
  const [fullscreen, setFullscreen] = useState(false);
  const { filter, setFilter, filtered } = useRowFilter(events, (e) => [
    e.client_ip,
    e.host,
    e.request_uri,
    e.match_value,
    e.action,
    e.msg,
  ]);
  const { sorted, sortKey, dir, toggle } = useSort(filtered, EVENT_SORT, "time");
  const sortProps = { sortKey, dir, onSort: toggle };
  if (events.length === 0) {
    return <p className="mt-3 text-xs text-muted-foreground">No request-level matches found.</p>;
  }
  return (
    <FullscreenPanel on={fullscreen} onExit={() => setFullscreen(false)} title="Matching requests">
      <div className={fullscreen ? "mt-3 flex min-h-0 flex-1 flex-col gap-2" : "mt-3 space-y-2"}>
        <RowFilterBar filter={filter} onFilter={setFilter} shown={filtered.length} total={events.length}>
          <FullscreenToggle on={fullscreen} onToggle={() => setFullscreen((f) => !f)} />
        </RowFilterBar>
        <div
          className={
            fullscreen
              ? "min-h-0 flex-1 overflow-auto rounded border text-xs"
              : "max-h-[28rem] overflow-auto rounded border text-xs"
          }
        >
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
                <tr key={`${e.tracking_reference}-${i}`} className="group border-t border-border/50 hover:bg-muted/40">
                  <td className={`${SHORT} font-mono text-muted-foreground`}>{fmtTime(e.time)}</td>
                  <td className={SHORT}>
                    <Badge variant={e.action === "Block" ? "destructive" : "secondary"}>{e.action}</Badge>
                  </td>
                  <td className={`${SHORT} font-mono`}>
                    <span className="inline-flex items-center gap-1">
                      <FilterValue value={e.client_ip ?? ""} onFilter={setFilter} />
                      <CopyButton
                        value={e.client_ip ?? ""}
                        what="client IP"
                        className="opacity-0 transition-opacity group-hover:opacity-100"
                      />
                    </span>
                  </td>
                  <td className={SHORT}>
                    <FilterValue value={e.host ?? ""} onFilter={setFilter} />
                  </td>
                  <td className={`${WIDE} font-mono`}>
                    <span className="inline-flex items-start gap-1">
                      <span>{e.request_uri}</span>
                      <CopyButton
                        value={e.request_uri ?? ""}
                        what="URI"
                        className="mt-0.5 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                      />
                    </span>
                  </td>
                  <td className={`${WIDE} font-mono text-muted-foreground`}>
                    <span className="inline-flex items-start gap-1">
                      <span>{e.match_value}</span>
                      <CopyButton
                        value={e.match_value ?? ""}
                        what="matched value"
                        className="mt-0.5 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                      />
                    </span>
                  </td>
                  <td className={`${WIDE} text-muted-foreground`}>{e.msg}</td>
                  <td className={SHORT}>
                    <InspectButton onClick={() => onOpenRequest(e.tracking_reference)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {sorted.length === 0 && <p className="p-3 text-xs text-muted-foreground">No rows match “{filter}”.</p>}
        </div>
      </div>
    </FullscreenPanel>
  );
}

function ScannerCard({ scanner }: { scanner: ScannerReport }) {
  const [fullscreen, setFullscreen] = useState(false);
  const { sorted, sortKey, dir, toggle } = useSort(scanner.by_ip, SCANNER_SORT);
  const { visible, notice } = useCapped(sorted, 15);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2">
          Scanner segmentation
          {scanner.total_blocks > 0 && (
            <FullscreenToggle on={fullscreen} onToggle={() => setFullscreen((f) => !f)} />
          )}
        </CardTitle>
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
          <FullscreenPanel on={fullscreen} onExit={() => setFullscreen(false)} title="Scanner segmentation">
            <div className={fullscreen ? "min-h-0 flex-1 overflow-auto rounded border" : ""}>
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
                  {visible.map((v) => (
                    <TableRow key={v.ip} className="group">
                      <TableCell className="font-mono">
                        <span className="inline-flex items-center gap-1">
                          {v.ip}
                          <CopyButton
                            value={v.ip}
                            what="client IP"
                            className="opacity-0 transition-opacity group-hover:opacity-100"
                          />
                        </span>
                      </TableCell>
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
            </div>
            {notice}
          </FullscreenPanel>
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
  const [fullscreen, setFullscreen] = useState(false);
  const { sorted, sortKey, dir, toggle } = useSort(firing, FIRING_SORT);
  const { visible, notice } = useCapped(sorted, 25);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2">
          Firing rules
          <FullscreenToggle on={fullscreen} onToggle={() => setFullscreen((f) => !f)} />
        </CardTitle>
        <CardDescription>
          Every rule that triggered in this window, by action and volume. <code>AnomalyScoring</code> rows score a
          request; a <code>Block</code> happens only when the combined score crosses the policy threshold.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FullscreenPanel on={fullscreen} onExit={() => setFullscreen(false)} title="Firing rules">
        <div className={fullscreen ? "min-h-0 flex-1 overflow-auto rounded border" : ""}>
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
            {visible.map((r) => (
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
        </div>
        {notice}
        </FullscreenPanel>
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
  const [fullscreen, setFullscreen] = useState(false);
  const { sorted, sortKey, dir, toggle } = useSort(causes, CAUSE_SORT);
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2">
          Blocks by cause (scanners excluded)
          <FullscreenToggle on={fullscreen} onToggle={() => setFullscreen((f) => !f)} />
        </CardTitle>
        <CardDescription>Rules that block real (non-scanner) traffic. Click one to get exclusion context.</CardDescription>
      </CardHeader>
      <CardContent>
        <FullscreenPanel on={fullscreen} onExit={() => setFullscreen(false)} title="Blocks by cause (scanners excluded)">
        <div className={fullscreen ? "min-h-0 flex-1 overflow-auto rounded border" : ""}>
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
        </div>
        </FullscreenPanel>
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
  // Only offer same-WAF-type datasets to span/compare: mixing Front Door and Application Gateway
  // in one analysis (or diffing across them) is meaningless — different schemas and rule sets.
  const selectedType = datasets.find((d) => d.dataset_id === selected)?.waf_type;
  const others = datasets.filter((d) => d.dataset_id !== selected && d.waf_type === selectedType);
  const toggleSpan = (id: string) => onSpan(span.includes(id) ? span.filter((x) => x !== id) : [...span, id]);
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-3 py-3 text-sm">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="text-muted-foreground">Policy</span>
          <Select
            className="h-8 w-auto"
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
          </Select>
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
            <Select
              className="h-8 w-auto"
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
            </Select>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FiringDiffCard({ diff, onInvestigate }: { diff: FiringDiff; onInvestigate: (ruleId: string) => void }) {
  const changed = diff.rules.filter((r) => r.status !== "unchanged");
  const { visible, notice } = useCapped(changed, 25);
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
              {visible.map((r) => (
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
          {notice}
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
