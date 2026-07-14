/** Table primitives shared by the Analyze panels and the cards that stay in AnalyzePage. */
import { ArrowDown, ArrowUp, Check, ChevronsUpDown, Copy, Search, X } from "lucide-react";
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
      // aria-sort belongs on the <th>, not on a button inside it; the state rides on the name instead.
      aria-label={active ? `${label}, sorted ${dir === "asc" ? "ascending" : "descending"}` : `${label}, not sorted`}
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

// Copy the values that get pasted onwards — into a ticket, a Terraform exclusion, an `az` command.
// Selecting them by hand out of a dense table is fiddly and easy to get subtly wrong.
export function CopyButton({ value, what, className = "" }: { value: string; what: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          },
          () => {/* clipboard denied — the value is still on screen to select by hand */},
        );
      }}
      title={`Copy ${what}`}
      aria-label={`Copy ${what}`}
      className={`rounded text-muted-foreground hover:text-foreground ${className}`}
    >
      {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

// Narrow the rows already on screen. Distinct from the Search panel's query, which refetches from
// the server and is capped: this only ever hides rows you already have, so it's instant and can't
// push anything past the cap. `fields` returns the values a row is matched against.
export function useRowFilter<T>(rows: T[], fields: (row: T) => (string | null | undefined)[]) {
  const [filter, setFilter] = useState("");
  const q = filter.trim().toLowerCase();
  const filtered = useMemo(
    () => (q ? rows.filter((r) => fields(r).some((v) => v?.toLowerCase().includes(q))) : rows),
    // `fields` is an inline arrow at every call site; re-running on rows/q is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rows, q],
  );
  return { filter, setFilter, filtered };
}

export function RowFilterBar({
  filter,
  onFilter,
  shown,
  total,
  children,
}: {
  filter: string;
  onFilter: (v: string) => void;
  shown: number;
  total: number;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative">
        <input
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
          placeholder="Filter these rows…"
          aria-label="Filter the rows on screen"
          className="h-7 w-56 rounded-md border border-input bg-transparent px-2 pr-6 font-mono text-xs shadow-sm placeholder:font-sans placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        />
        {filter && (
          <button
            type="button"
            onClick={() => onFilter("")}
            title="Clear filter"
            aria-label="Clear filter"
            className="absolute right-1 top-1/2 -translate-y-1/2 rounded text-muted-foreground hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>
      <span className="text-xs tabular-nums text-muted-foreground">
        {filter ? `${shown.toLocaleString()} / ${total.toLocaleString()}` : `${total.toLocaleString()}`} row
        {total === 1 ? "" : "s"}
      </span>
      {children}
    </div>
  );
}

// A value you can click to filter the table down to it — the "show me only this rule / IP / host"
// move, without retyping it into the filter box.
export function FilterValue({
  value,
  onFilter,
  className = "",
  children,
}: {
  value: string;
  onFilter: (v: string) => void;
  className?: string;
  children?: React.ReactNode;
}) {
  if (!value) return null;
  return (
    <button
      type="button"
      onClick={() => onFilter(value)}
      title={`Filter to ${value}`}
      className={`text-left hover:underline ${className}`}
    >
      {children ?? value}
    </button>
  );
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
