import { CheckCircle2, Clock, Database, Download, Gauge, HardDrive, Loader2, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type DatasetMeta, type EstimateResult } from "@/lib/api";

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

export function DownloadPage({ onDone }: { onDone: () => void }) {
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

  function refresh() {
    api.listDatasets().then((r) => setDatasets(r.datasets)).catch(() => undefined);
  }
  useEffect(refresh, []);
  useEffect(() => {
    api.health().then((h) => setOffline(h.offline)).catch(() => setOffline(null));
  }, []);

  // Auto-estimate (debounced) whenever the range changes and we have a live Azure session.
  useEffect(() => {
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
  }, [range.from, range.to, range.hour, offline]);

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
    if (dates.length === 0 || dates.length > 92) {
      alert("Pick a valid range of at most 92 days.");
      return;
    }
    setRunning(true);
    setProgress(dates.map((date) => ({ date, hour: range.hour, status: "pending" })));
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
        setProgress((p) =>
          p.map((d, idx) =>
            idx === i ? { ...d, status: "done", detail: `${meta.line_count} lines${meta.cached ? " (cached)" : ""}` } : d,
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
  }

  // A failed download leaves partial blobs on disk (a retry re-pulls them automatically);
  // this lets the operator reclaim that space instead if they prefer.
  async function removePartial(day: DayProgress) {
    const id = day.hour == null ? day.date : `${day.date}-h${String(day.hour).padStart(2, "0")}`;
    if (!window.confirm(`Delete the partially downloaded files for ${id} from this laptop?`)) return;
    try {
      const res = await api.deleteDataset(id);
      setProgress((p) =>
        p.map((d) =>
          d.date === day.date ? { ...d, detail: res.deleted ? "partial data deleted" : "nothing left to delete" } : d,
        ),
      );
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
    refresh();
  }

  async function removeDataset(id: string) {
    if (!window.confirm(`Remove dataset ${id}? Its cached files will be deleted from this laptop.`)) return;
    try {
      await api.deleteDataset(id);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
    refresh();
  }

  async function clearAll() {
    if (!window.confirm(`Remove all ${datasets.length} cached datasets from this laptop?`)) return;
    try {
      await api.clearDatasets();
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
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
                    onChange={(e) => editRange({ hour: e.target.value === "" ? null : Number(e.target.value) })}
                    className="w-28"
                  />
                </div>
                <Button onClick={run} disabled={running}>
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
                      <DayRow key={d.date} day={d} onDeletePartial={removePartial} />
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
              <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={clearAll}>
                <Trash2 className="mr-2 h-4 w-4" /> Clear all
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {datasets.length === 0 ? (
            <p className="text-sm text-muted-foreground">None yet.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {datasets.map((d) => (
                <div key={d.dataset_id} className="flex items-center overflow-hidden rounded-md border">
                  <button className="px-3 py-1.5 text-sm hover:bg-muted" onClick={onDone}>
                    {d.dataset_id} · {d.line_count} lines
                  </button>
                  <button
                    className="border-l px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-destructive"
                    onClick={() => removeDataset(d.dataset_id)}
                    title={`Remove ${d.dataset_id}`}
                  >
                    <Trash2 className="h-4 w-4" />
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
        <span>
          {running ? "Downloading" : "Finished"} · {settled} / {total} day{total === 1 ? "" : "s"}
          {activity}
        </span>
        <span className="tabular-nums">{Math.round(fraction * 100)}%</span>
      </div>
      <ProgressBar value={fraction} />
    </div>
  );
}

function DayRow({ day, onDeletePartial }: { day: DayProgress; onDeletePartial: (day: DayProgress) => void }) {
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
            className="h-6 px-2 text-xs text-muted-foreground"
            onClick={() => onDeletePartial(day)}
            title="Remove the partially downloaded files (a retry re-pulls them automatically)"
          >
            <Trash2 className="mr-1 h-3 w-3" /> Delete partial data
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
