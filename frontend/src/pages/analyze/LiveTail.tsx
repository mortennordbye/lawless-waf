/** Live tailing of the current UTC hour: the polling loop, its controls, and its status line.
 *
 * A hook rather than one component because the pieces render in two places (controls sit in the
 * dataset row, status below it) and `live` itself gates the rest of the page. AnalyzePage keeps
 * only the on/off flag; the interval, mode, and status live here. */
import { Radio, Square } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";

// Live tailing targets the current UTC hour — Azure partitions the blobs by UTC.
const ymd = (d: Date) => d.toISOString().slice(0, 10);
const LIVE_INTERVALS = [15, 30, 60];

export function useLiveTail({
  live,
  active,
  onDataset,
  onTick,
}: {
  live: boolean;
  active: boolean;
  /** The hour the tail landed on: it may fall back to the previous hour early in a new one. */
  onDataset: (datasetId: string) => void;
  /** Fired after each successful tick so the page can reload its analysis in place. */
  onTick: () => void;
}) {
  const [seconds, setSeconds] = useState(30);
  // Off (default): light incremental tail — pull only new blobs. On: re-pull the whole hour each
  // tick (force) for the freshest data, including any still-being-written window, at more cost.
  const [full, setFull] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Live loop: incrementally tail the current UTC hour (pull only new blobs, not the whole
  // pile), then reload analysis. Chained (not an interval) so ticks never overlap an in-flight
  // download. Pauses when the tab is inactive.
  useEffect(() => {
    if (!live || !active) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function tick() {
      if (cancelled) return;
      try {
        const now = new Date();
        // Full refresh re-pulls the hour (force); otherwise tail incrementally (new blobs only).
        let meta = await api.createDataset(ymd(now), now.getUTCHours(), full, !full);
        if (meta.line_count === 0) {
          // WAF logs lag a few minutes — early in the hour fall back to the previous one.
          const prev = new Date(now.getTime() - 3_600_000);
          meta = await api.createDataset(ymd(prev), prev.getUTCHours(), full, !full);
        }
        if (cancelled) return;
        onDataset(meta.dataset_id);
        onTick();
        setError(null);
        setStatus(`updated ${new Date().toISOString().slice(11, 19)} UTC · ${meta.dataset_id} · ${meta.line_count} lines`);
      } catch (e) {
        if (cancelled) {
          // nothing to do
        } else if (e instanceof ApiError && e.status === 409) {
          // A download for this hour is already running (e.g. another tab) — skip this tick
          // quietly and try again next interval instead of surfacing a scary error.
          setError(null);
          setStatus(`waiting — a download is already in progress (retry in ${seconds}s)`);
        } else {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
      if (!cancelled) timer = setTimeout(tick, seconds * 1000);
    }
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // onDataset/onTick are redefined every render by the caller; including them would restart
    // the loop on every tick.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, seconds, full, active]);

  return { seconds, setSeconds, full, setFull, status, error };
}

export function LiveControls({
  live,
  offline,
  seconds,
  full,
  onToggle,
  onSeconds,
  onFull,
}: {
  live: boolean;
  offline: boolean | null;
  seconds: number;
  full: boolean;
  onToggle: () => void;
  onSeconds: (s: number) => void;
  onFull: () => void;
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
        className="h-8 rounded-md border border-input bg-background px-2 text-xs"
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
      <label
        className="flex items-center gap-1.5 text-xs text-muted-foreground"
        title="Off: tail only new blobs (light). On: re-pull the whole hour each tick — freshest, including any window still being written, but heavier."
      >
        <input type="checkbox" checked={full} onChange={onFull} className="h-3.5 w-3.5 accent-primary" />
        Full refresh
      </label>
    </div>
  );
}

export function LiveStatus({ status, error, seconds }: { status: string | null; error: string | null; seconds: number }) {
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      {error ? (
        <span className="text-destructive">Live refresh failed: {error} (retrying every {seconds}s)</span>
      ) : (
        <span>{status ?? "Starting live tail of the current UTC hour…"}</span>
      )}
    </div>
  );
}
