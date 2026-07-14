/** Table primitives shared by the Analyze panels and the cards that stay in AnalyzePage. */
import { ArrowDown, ArrowUp, ChevronsUpDown, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";

export const CLASS_VARIANT: Record<string, "success" | "destructive" | "secondary" | "warning" | "outline"> = {
  false_positive: "success",
  attack: "destructive",
  scanner_noise: "secondary",
  not_excludable: "warning",
  mixed: "warning",
  unknown: "outline",
};

// Shared cell styles. Short columns stay on one line (nowrap); text-heavy columns wrap inside
// a bounded width instead of truncating, so nothing clips and the full value is readable. The
// whole table scrolls horizontally as a fallback for very wide rows.
export const CELL = "p-2 align-top";
export const SHORT = `${CELL} whitespace-nowrap`;
export const WIDE = `${CELL} min-w-[220px] max-w-[420px] whitespace-normal break-all`;
export const TH = "p-2 text-left font-medium whitespace-nowrap";

export function fmtTime(t: string | undefined): string {
  return t?.slice(0, 19).replace("T", " ") ?? "";
}

// Click-to-sort for the row-level tables. Accessor maps are module-level constants (stable, so
// the memo doesn't re-sort every render). Click a header to sort by it; click again to flip
// direction — e.g. sort by Action to group all "Block" (deny) rows together.
export type SortDir = "asc" | "desc";
export type Accessors<T> = Record<string, (row: T) => string | number>;

export function useSort<T>(rows: T[], accessors: Accessors<T>, initialKey = "", initialDir: SortDir = "desc") {
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

// Long tables show the first `cap` rows until asked for the rest. Truncating silently is the
// problem this solves: on a real day these lists run to hundreds, sorting happens before the cut,
// so rows appear and vanish as you sort with nothing on screen admitting it.
export function useCapped<T>(rows: T[], cap: number) {
  const [showAll, setShowAll] = useState(false);
  const notice =
    rows.length > cap ? (
      <p className="mt-2 text-xs text-muted-foreground">
        {showAll ? `Showing all ${rows.length}.` : `Showing ${cap} of ${rows.length}.`}{" "}
        <button className="underline underline-offset-2 hover:text-foreground" onClick={() => setShowAll((v) => !v)}>
          {showAll ? "Show fewer" : "Show all"}
        </button>
      </p>
    ) : null;
  return { visible: showAll ? rows : rows.slice(0, cap), notice };
}

// Generic clickable sort control. Drops into ANY header cell — the raw `<th>` event tables and
// the shadcn `<TableHead>` data tables alike — so sorting isn't bolted onto one specific table.
export function SortLabel({
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

export function ModeBadge({ mode }: { mode: string | null }) {
  if (!mode) return null;
  return <Badge variant={/detection/i.test(mode) ? "warning" : "secondary"}>{mode}</Badge>;
}

export function InspectButton({ onClick }: { onClick: () => void }) {
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
