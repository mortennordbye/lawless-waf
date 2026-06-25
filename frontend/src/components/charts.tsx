// Dependency-free charts (CSS/flex bars) — enough insight without pulling in a chart lib.

import type { TimelineBucket } from "@/lib/api";

export function StatTile({
  label,
  value,
  accent,
  onClick,
  active,
}: {
  label: string;
  value: string | number;
  accent?: string;
  onClick?: () => void;
  active?: boolean;
}) {
  const body = (
    <>
      <div className={`text-2xl font-semibold tabular-nums ${accent ?? ""}`}>{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </>
  );
  if (!onClick) return <div className="rounded-md border bg-muted/30 p-3">{body}</div>;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-md border p-3 text-left transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
        active ? "border-primary bg-muted/60 ring-1 ring-primary" : "bg-muted/30"
      }`}
    >
      {body}
    </button>
  );
}

export interface BarDatum {
  label: string;
  value: number;
  hint?: string;
  color?: string;
}

export function HBarChart({ data, format }: { data: BarDatum[]; format?: (n: number) => string }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="space-y-1.5">
      {data.map((d, i) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <span className="w-44 shrink-0 truncate font-mono" title={d.hint ?? d.label}>
            {d.label}
          </span>
          <div className="h-4 flex-1 overflow-hidden rounded bg-muted">
            <div
              className={`h-full rounded ${d.color ?? "bg-primary"}`}
              style={{ width: `${(d.value / max) * 100}%` }}
            />
          </div>
          <span className="w-16 shrink-0 text-right tabular-nums text-muted-foreground">
            {format ? format(d.value) : d.value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

function bucketLabel(b: string | undefined): string {
  // backend buckets are "YYYY-MM-DDTHH:M" (10-minute granularity) -> "HH:M0"
  if (!b) return "";
  return `${b.slice(11)}0`;
}

export function Timeline({ points }: { points: TimelineBucket[] }) {
  const max = Math.max(1, ...points.map((p) => p.block + p.anomaly + p.log));
  return (
    <div>
      <div className="flex h-32 items-end gap-px">
        {points.map((p, i) => {
          const title = `${bucketLabel(p.bucket)} UTC — block ${p.block}, anomaly ${p.anomaly}, log ${p.log}`;
          return (
            <div key={i} className="flex h-full flex-1 flex-col justify-end" title={title}>
              {p.log > 0 && <div className="w-full bg-sky-500/50" style={{ height: `${(p.log / max) * 100}%` }} />}
              {p.anomaly > 0 && <div className="w-full bg-amber-500" style={{ height: `${(p.anomaly / max) * 100}%` }} />}
              {p.block > 0 && <div className="w-full bg-red-500" style={{ height: `${(p.block / max) * 100}%` }} />}
            </div>
          );
        })}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
        <span>{bucketLabel(points[0]?.bucket)}</span>
        <span>{bucketLabel(points[points.length - 1]?.bucket)} UTC</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-3 text-[10px] text-muted-foreground">
        <Legend swatch="bg-red-500" label="Block" />
        <Legend swatch="bg-amber-500" label="AnomalyScoring" />
        <Legend swatch="bg-sky-500/50" label="Log" />
      </div>
    </div>
  );
}

function Legend({ swatch, label }: { swatch: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className={`inline-block h-2 w-2 rounded-sm ${swatch}`} /> {label}
    </span>
  );
}
