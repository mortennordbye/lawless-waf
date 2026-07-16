import { CheckCircle2, Clock, Database, Download, Gauge, HardDrive, Loader2, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type DatasetMeta, type EstimateResult, type WafType } from "@/lib/api";

type DayStatus = "pending" | "downloading" | "done" | "error";
interface DayProgress {
  date: string;
  hour: number | null;
  status: DayStatus;
  detail?: string;
  downloaded?: number;
  total?: number | null;
  repairing?: boolean;
  merging?: boolean;
}

interface Range {
  from: string;
  to: string;
  hour: number | null;
}

const ymd = (d: Date) => d.toISOString().slice(0, 10);
const dayMs = 86_400_000;

// Quick ranges, adapted to the WAF blob layout: the finest selectable unit is an hour
// (download patterns stop at h=HH), so there are no sub-hour ranges.
const QUICK_RANGES: { label: string; make: (now: Date) => Range }[] = [
  { label: "This hour", make: (n) => ({ from: ymd(n), to: ymd(n), hour: n.getUTCHours() }) },
  {
    label: "Last hour",
    make: (n) => {
      const t = new Date(n.getTime() - 3_600_000);
      return { from: ymd(t), to: ymd(t), hour: t.getUTCHours() };
    },
  },
  { label: "Today", make: (n) => ({ from: ymd(n), to: ymd(n), hour: null }) },
  { label: "Yesterday", make: (n) => ({ from: ymd(new Date(n.getTime() - dayMs)), to: ymd(new Date(n.getTime() - dayMs)), hour: null }) },
  { label: "Last 3 days", make: (n) => ({ from: ymd(new Date(n.getTime() - 2 * dayMs)), to: ymd(n), hour: null }) },
  { label: "Last 7 days", make: (n) => ({ from: ymd(new Date(n.getTime() - 6 * dayMs)), to: ymd(n), hour: null }) },
  { label: "Last 14 days", make: (n) => ({ from: ymd(new Date(n.getTime() - 13 * dayMs)), to: ymd(n), hour: null }) },
  { label: "Last 30 days", make: (n) => ({ from: ymd(new Date(n.getTime() - 29 * dayMs)), to: ymd(n), hour: null }) },
];

function datesInRange(from: string, to: string): string[] {
  const out: string[] = [];
  const start = new Date(from + "T00:00:00Z");
  const end = new Date(to + "T00:00:00Z");
  for (let d = start; d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    out.push(d.toISOString().slice(0, 10));
  }
  return out;
}

function humanBytes(n: number): string {
  if (n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function humanDuration(s: number): string {
  if (s < 1) return "<1s";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

export function DownloadPage({
  onAnalyze,
  onDownloaded,
}: {
  /** Hand this dataset to the Analyze tab and go there. */
  onAnalyze: (datasetId: string) => void;
  /** Preselect a freshly downloaded dataset in Analyze, without pulling the operator off the
   *  progress list (a multi-day run may still have errored days worth looking at). */
  onDownloaded: (datasetId: string) => void;
}) {
  const today = ymd(new Date());
  const now = new Date();
  const nowUtc = now.toISOString().slice(11, 16);
  const nowLocal = now.toTimeString().slice(0, 5);
  const [range, setRange] = useState<Range>({ from: today, to: today, hour: null });
  const [active, setActive] = useState<string>("Today");
  const [offline, setOffline] = useState<boolean | null>(null);

  const [estimate, setEstimate] = useState<EstimateResult | null>(null);
  const [estimating, setEstimating] = useState(false);
  const [estErr, setEstErr] = useState<string | null>(null);

  const [measuredRate, setMeasuredRate] = useState<number | null>(null);
  const [measuring, setMeasuring] = useState(false);
  const [speedErr, setSpeedErr] = useState<string | null>(null);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<DayProgress[]>([]);
  const [datasets, setDatasets] = useState<DatasetMeta[]>([]);
  // The configured WAF type — datasets are namespaced by it, so partial-download deletes (which
  // only have a date, not a returned dataset id) need it to build "<waf_type>:<date>".
  const [wafType, setWafType] = useState<WafType>("frontdoor");
  const [listErr, setListErr] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  // Two-step confirm: the first click arms a destructive button, the second commits it.
  const [confirmKey, setConfirmKey] = useState<string | null>(null);

  function refresh() {
    api
      .listDatasets()
      .then((r) => {
        setDatasets(r.datasets);
        setListErr(null);
      })
      .catch((e) =>
        setListErr(
          `Could not reach the backend — is the container running? (${e instanceof Error ? e.message : String(e)})`,
        ),
      );
  }
  useEffect(refresh, []);

  // An armed button disarms itself, so a stray one can't be committed by a later stray click.
  useEffect(() => {
    if (!confirmKey) return;
    const t = setTimeout(() => setConfirmKey(null), 5000);
    return () => clearTimeout(t);
  }, [confirmKey]);

  function armOrRun(key: string, action: () => void) {
    if (confirmKey === key) {
      setConfirmKey(null);
      action();
    } else {
      setConfirmKey(key);
    }
  }
  useEffect(() => {
    api.health().then((h) => setOffline(h.offline)).catch(() => setOffline(null));
  }, []);
  useEffect(() => {
    api.getConfig().then((c) => setWafType(c.waf_type ?? "frontdoor")).catch(() => {});
  }, []);

  const rangeDays = datesInRange(range.from, range.to).length;
  const rangeInvalid = rangeDays === 0 || rangeDays > 92;

  // Auto-estimate (debounced) whenever the range changes and we have a live Azure session.
  useEffect(() => {
    // An invalid range would only earn a 422; the inline message already says why.
    if (rangeInvalid) {
      setEstimate(null);
      setEstErr(null);
      return;
    }
    if (offline !== false) {
      setEstimate(null);
      setEstErr(offline ? "Estimates need a live Azure session (OFFLINE=true)." : null);
      return;
    }
    let cancelled = false;
    setEstimating(true);
    setEstErr(null);
    const t = setTimeout(() => {
      api
        .estimate(range.from, range.to, range.hour)
        .then((r) => !cancelled && setEstimate(r))
        .catch((e) => {
          if (!cancelled) {
            setEstimate(null);
            setEstErr(e instanceof Error ? e.message : String(e));
          }
        })
        .finally(() => !cancelled && setEstimating(false));
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [range.from, range.to, range.hour, offline, rangeInvalid]);

  function applyQuick(label: string) {
    const r = QUICK_RANGES.find((q) => q.label === label);
    if (r) {
      setActive(label);
      setRange(r.make(new Date()));
    }
  }
  function editRange(patch: Partial<Range>) {
    setActive("");
    setRange((r) => ({ ...r, ...patch }));
  }

  async function runSpeedtest() {
    setMeasuring(true);
    setSpeedErr(null);
    try {
      const r = await api.speedtest();
      setMeasuredRate(r.blobs_per_sec);
    } catch (e) {
      setSpeedErr(e instanceof Error ? e.message : String(e));
    } finally {
      setMeasuring(false);
    }
  }

  async function run() {
    const dates = datesInRange(range.from, range.to);
    setRunning(true);
    setProgress(dates.map((date) => ({ date, hour: range.hour, status: "pending" })));
    let lastDownloaded: string | null = null;
    for (let i = 0; i < dates.length; i++) {
      // Seed the bar's denominator from the estimate the UI already has (cached days → 0).
      const total = estimate?.days.find((d) => d.date === dates[i])?.blob_count ?? null;
      setProgress((p) => p.map((d, idx) => (idx === i ? { ...d, status: "downloading", downloaded: 0, total } : d)));
      try {
        const meta = await api.streamDataset(dates[i], range.hour, { total }, (ev) => {
          if (ev.phase === "progress" || ev.phase === "start") {
            setProgress((p) =>
              p.map((d, idx) =>
                idx === i
                  ? {
                      ...d,
                      downloaded: ev.downloaded ?? d.downloaded ?? 0,
                      total: ev.total ?? d.total ?? total,
                      repairing: ev.repairing ?? d.repairing,
                      merging: ev.merging ?? d.merging,
                    }
                  : d,
              ),
            );
          }
        });
        lastDownloaded = meta.dataset_id;
        setProgress((p) =>
          p.map((d, idx) =>
            idx === i
              ? { ...d, status: "done", detail: `${meta.line_count.toLocaleString()} lines${meta.cached ? " (cached)" : ""}` }
              : d,
          ),
        );
      } catch (e) {
        setProgress((p) =>
          p.map((d, idx) => (idx === i ? { ...d, status: "error", detail: e instanceof Error ? e.message : String(e) } : d)),
        );
      }
    }
    setRunning(false);
    refresh();
    if (lastDownloaded) onDownloaded(lastDownloaded);
  }

  // A failed download leaves partial blobs on disk (a retry re-pulls them automatically);
  // this lets the operator reclaim that space instead if they prefer.
  async function removePartial(day: DayProgress) {
    const date = day.hour == null ? day.date : `${day.date}-h${String(day.hour).padStart(2, "0")}`;
    const id = `${wafType}:${date}`;
    try {
      const res = await api.deleteDataset(id);
      setProgress((p) =>
        p.map((d) =>
          d.date === day.date ? { ...d, detail: res.deleted ? "partial data deleted" : "nothing left to delete" } : d,
        ),
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setProgress((p) => p.map((d) => (d.date === day.date ? { ...d, detail: `delete failed: ${msg}` } : d)));
    }
    refresh();
  }

  async function removeDataset(id: string) {
    setActionErr(null);
    try {
      await api.deleteDataset(id);
    } catch (e) {
      setActionErr(`Could not remove ${id}: ${e instanceof Error ? e.message : String(e)}`);
    }
    refresh();
  }

  async function clearAll() {
    setActionErr(null);
    try {
      await api.clearDatasets();
    } catch (e) {
      setActionErr(`Could not clear the cached datasets: ${e instanceof Error ? e.message : String(e)}`);
    }
    refresh();
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Download WAF logs</CardTitle>
          <CardDescription>
            Pick a time range, see the estimated size and time, then pull the blobs. Days already cached are reused.
            The finest granularity is one hour. Azure stores the logs partitioned by <b>UTC</b>, so dates and the
            hour field are UTC — right now it's <b>{nowUtc} UTC</b> ({nowLocal} your local time).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-[1fr_220px]">
            {/* Left: absolute range + estimate */}
            <div className="space-y-4">
              <div className="flex flex-wrap items-end gap-4">
                <div className="space-y-1.5">
                  <Label>From</Label>
                  <Input type="date" value={range.from} onChange={(e) => editRange({ from: e.target.value })} className="w-44" />
                </div>
                <div className="space-y-1.5">
                  <Label>To</Label>
                  <Input type="date" value={range.to} onChange={(e) => editRange({ to: e.target.value })} className="w-44" />
                </div>
                <div className="space-y-1.5">
                  <Label className="flex items-center gap-2">
                    Hour (UTC, optional)
                    <span className="text-xs font-normal text-muted-foreground" title={`${nowLocal} local = ${nowUtc} UTC`}>
                      now {nowUtc} UTC
                    </span>
                  </Label>
                  <Input
                    type="number"
                    min={0}
                    max={23}
                    placeholder="all"
                    value={range.hour ?? ""}
                    // min/max only bound the spinners; a typed "99" would otherwise reach the API.
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      const clamped = e.target.value === "" || Number.isNaN(n) ? null : Math.max(0, Math.min(23, Math.trunc(n)));
                      editRange({ hour: clamped });
                    }}
                    className="w-28"
                  />
                </div>
                <Button onClick={run} disabled={running || rangeInvalid}>
                  {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  Download
                </Button>
                <Button
                  variant="outline"
                  onClick={runSpeedtest}
                  disabled={offline !== false || measuring}
                  title="Download one real hour of blobs to measure your actual throughput"
                >
                  {measuring ? <Loader2 className="h-4 w-4 animate-spin" /> : <Gauge className="h-4 w-4" />}
                  Speedtest
                </Button>
              </div>

              {rangeInvalid && (
                <p className="text-sm text-destructive">
                  {rangeDays === 0
                    ? "Pick a valid range — “To” must be on or after “From”."
                    : `That range is ${rangeDays} days; pick at most 92.`}
                </p>
              )}

              {(measuredRate !== null || speedErr) && (
                <div className="text-sm">
                  {speedErr ? (
                    <span className="text-destructive">{speedErr}</span>
                  ) : (
                    <span className="text-emerald-500">
                      Measured {measuredRate} blobs/s — ETA updated below.
                    </span>
                  )}
                </div>
              )}

              <EstimatePanel estimate={estimate} estimating={estimating} error={estErr} measuredRate={measuredRate} />

              {progress.length > 0 && (
                <div className="space-y-3 border-t pt-4">
                  <OverallProgress progress={progress} running={running} />
                  <div className="space-y-1.5">
                    {progress.map((d) => (
                      <DayRow
                        key={d.date}
                        day={d}
                        armed={confirmKey === `partial:${d.date}`}
                        onDeletePartial={(day) => armOrRun(`partial:${day.date}`, () => removePartial(day))}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right: quick ranges */}
            <div className="space-y-1 md:border-l md:pl-4">
              <Label className="mb-2 block text-muted-foreground">Quick ranges</Label>
              {QUICK_RANGES.map((q) => (
                <button
                  key={q.label}
                  onClick={() => applyQuick(q.label)}
                  className={`block w-full rounded-md px-3 py-1.5 text-left text-sm transition-colors hover:bg-muted ${
                    active === q.label ? "bg-muted font-medium text-foreground" : "text-muted-foreground"
                  }`}
                >
                  {q.label}
                </button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            Cached datasets
            {datasets.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:text-destructive"
                onClick={() => armOrRun("clear", clearAll)}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                {confirmKey === "clear" ? `Really remove all ${datasets.length}?` : "Clear all"}
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {listErr && <p className="mb-3 text-sm text-destructive">{listErr}</p>}
          {actionErr && <p className="mb-3 text-sm text-destructive">{actionErr}</p>}
          {listErr ? null : datasets.length === 0 ? (
            <p className="text-sm text-muted-foreground">None yet.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {datasets.map((d) => (
                <div key={d.dataset_id} className="flex items-center overflow-hidden rounded-md border">
                  <button
                    className="px-3 py-1.5 text-sm hover:bg-muted"
                    onClick={() => onAnalyze(d.dataset_id)}
                    title={`Analyze ${d.dataset_id}`}
                  >
                    {d.dataset_id} · {d.line_count.toLocaleString()} lines
                  </button>
                  <button
                    className={`border-l px-2 py-1.5 hover:bg-muted ${
                      confirmKey === `ds:${d.dataset_id}`
                        ? "text-xs text-destructive"
                        : "text-muted-foreground hover:text-destructive"
                    }`}
                    onClick={() => armOrRun(`ds:${d.dataset_id}`, () => removeDataset(d.dataset_id))}
                    title={`Remove ${d.dataset_id}`}
                  >
                    {confirmKey === `ds:${d.dataset_id}` ? "Remove?" : <Trash2 className="h-4 w-4" />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ProgressBar({ value, indeterminate }: { value: number; indeterminate?: boolean }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
      <div
        className={`h-full rounded-full bg-primary ${indeterminate ? "w-full animate-pulse" : "transition-all"}`}
        style={indeterminate ? undefined : { width: `${Math.min(100, Math.max(0, value * 100))}%` }}
      />
    </div>
  );
}

// Batch progress across all days: a settled day (done or errored) counts as one full unit, the
// in-flight day contributes its blob fraction — so a single-day range fills smoothly too.
function OverallProgress({ progress, running }: { progress: DayProgress[]; running: boolean }) {
  const total = progress.length;
  const settled = progress.filter((d) => d.status === "done" || d.status === "error").length;
  const failed = progress.filter((d) => d.status === "error").length;
  const current = progress.find((d) => d.status === "downloading");
  // A repairing day's `downloaded` already counts only freshly re-pulled blobs, so the
  // plain fraction stays honest in every phase.
  const fraction =
    progress.reduce((acc, d) => {
      if (d.status === "done" || d.status === "error") return acc + 1;
      if (d.status === "downloading" && d.total && d.total > 0) return acc + Math.min(1, (d.downloaded ?? 0) / d.total);
      return acc;
    }, 0) / total;

  const blobCount = current?.total
    ? ` · ${(current.downloaded ?? 0).toLocaleString()} / ${current.total.toLocaleString()} blobs`
    : "";
  const activity = current?.merging
    ? " · merging blobs into one dataset…"
    : current?.repairing
      ? `${blobCount} · re-pulling files left by an aborted download`
      : blobCount;

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className={!running && failed > 0 ? "text-destructive" : undefined}>
          {running ? "Downloading" : failed > 0 ? `Finished with ${failed} error${failed === 1 ? "" : "s"}` : "Finished"} ·{" "}
          {settled} / {total} day{total === 1 ? "" : "s"}
          {activity}
        </span>
        <span className="tabular-nums">{Math.round(fraction * 100)}%</span>
      </div>
      <ProgressBar value={fraction} />
    </div>
  );
}

function DayRow({
  day,
  armed,
  onDeletePartial,
}: {
  day: DayProgress;
  armed: boolean;
  onDeletePartial: (day: DayProgress) => void;
}) {
  const known = !!(day.total && day.total > 0);
  const merging = day.status === "downloading" && day.merging;
  // During the self-heal re-pull of an aborted run, `downloaded` counts freshly re-pulled
  // blobs (the leftovers already on disk don't count), so the bar stays honest.
  const repairing = day.status === "downloading" && day.repairing && !merging;
  return (
    <div className="text-sm">
      <div className="flex items-center gap-2">
        {day.status === "done" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
        {day.status === "error" && <XCircle className="h-4 w-4 text-destructive" />}
        {day.status === "downloading" && <Loader2 className="h-4 w-4 animate-spin" />}
        {day.status === "pending" && <span className="h-4 w-4" />}
        <span className="font-mono">{day.date}</span>
        {merging ? (
          <span className="text-xs text-muted-foreground">merging blobs into one dataset…</span>
        ) : repairing ? (
          <span className="text-xs text-amber-500">
            re-pulling files left by an aborted download
            {known ? ` · ${(day.downloaded ?? 0).toLocaleString()} / ${day.total!.toLocaleString()} blobs` : "…"}
          </span>
        ) : (
          day.status === "downloading" &&
          known && (
            <span className="text-xs text-muted-foreground">
              {(day.downloaded ?? 0).toLocaleString()} / {day.total!.toLocaleString()} blobs
            </span>
          )
        )}
        {day.detail && <span className="text-muted-foreground">{day.detail}</span>}
        {day.status === "error" && (
          <Button
            variant="ghost"
            size="sm"
            className={`h-6 px-2 text-xs ${armed ? "text-destructive" : "text-muted-foreground"}`}
            onClick={() => onDeletePartial(day)}
            title="Remove the partially downloaded files (a retry re-pulls them automatically)"
          >
            <Trash2 className="mr-1 h-3 w-3" /> {armed ? "Really delete?" : "Delete partial data"}
          </Button>
        )}
      </div>
      {day.status === "downloading" && (
        <div className="ml-6 mt-1">
          <ProgressBar
            value={known ? (day.downloaded ?? 0) / day.total! : 0}
            indeterminate={!known}
          />
        </div>
      )}
    </div>
  );
}

function EstimatePanel({
  estimate,
  estimating,
  error,
  measuredRate,
}: {
  estimate: EstimateResult | null;
  estimating: boolean;
  error: string | null;
  measuredRate: number | null;
}) {
  if (estimating) {
    return (
      <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Estimating…
      </div>
    );
  }
  if (error) {
    return <div className="rounded-md border bg-muted/40 p-3 text-sm text-amber-500">{error}</div>;
  }
  if (!estimate) return null;

  const toFetch = estimate.days.filter((d) => !d.cached).length;
  const rate = measuredRate ?? estimate.blobs_per_sec;
  const seconds = rate > 0 ? estimate.download_blob_count / rate : 0;
  const allCached = toFetch === 0;
  return (
    <div className="space-y-3 rounded-md border bg-muted/40 p-3">
      <div className="flex flex-wrap gap-6 text-sm">
        <Metric
          icon={<HardDrive className="h-4 w-4" />}
          label="On laptop"
          value={humanBytes(estimate.on_disk_bytes)}
          hint={estimate.cached_days ? "incl. cached" : undefined}
        />
        <Metric
          icon={<Download className="h-4 w-4" />}
          label="To download"
          value={allCached ? "nothing" : humanBytes(estimate.download_bytes)}
          hint={estimate.cached_days ? `${estimate.cached_days} cached, skipped` : undefined}
        />
        <Metric
          icon={<Clock className="h-4 w-4" />}
          label="Est. time"
          value={allCached ? "—" : `~${humanDuration(seconds)}`}
          hint={allCached ? undefined : `@ ${rate} blobs/s${measuredRate !== null ? " measured" : ""}`}
        />
        <Metric
          icon={<Database className="h-4 w-4" />}
          label="Blobs to fetch"
          value={estimate.download_blob_count.toLocaleString()}
          hint={toFetch ? `${toFetch} day${toFetch > 1 ? "s" : ""}` : undefined}
        />
      </div>
      {estimate.days.length > 1 && (
        <div className="max-h-40 overflow-auto text-xs">
          <table className="w-full">
            <tbody>
              {estimate.days.map((d) => (
                <tr key={d.date} className="border-t border-border/50">
                  <td className="py-1 font-mono">{d.date}</td>
                  <td className="py-1 text-right text-muted-foreground">{humanBytes(d.bytes)}</td>
                  <td className="py-1 text-right text-muted-foreground">{d.cached ? "" : `${d.blob_count} blobs`}</td>
                  <td className="py-1 pl-3 text-right">{d.cached && <span className="text-emerald-500">cached</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Metric({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-muted-foreground">{icon}</span>
      <div>
        <div className="font-medium">{value}</div>
        <div className="text-xs text-muted-foreground">
          {label}
          {hint && ` · ${hint}`}
        </div>
      </div>
    </div>
  );
}
