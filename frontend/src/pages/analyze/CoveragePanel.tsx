/** Existing-exclusions coverage: paste waf-exclusions.tf, see what's already covered, what's
 *  left, and the slot budget.
 *
 * Owns the pasted text and the results. The text deliberately survives a dataset change (paste
 * once, check it against several days); the results don't, since they're per-dataset. */
import { FolderGit2, Loader2, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatTile } from "@/components/charts";
import { api, type ConsolidationHint, type Coverage, type ScopeParams } from "@/lib/api";

import { CLASS_VARIANT, SHORT, TH } from "./shared";

export function CoveragePanel({
  selected,
  scope,
  onInvestigate,
}: {
  selected: string;
  scope: ScopeParams;
  onInvestigate: (ruleId: string) => void;
}) {
  const [tf, setTf] = useState("");
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [consolidation, setConsolidation] = useState<ConsolidationHint[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileAvailable, setFileAvailable] = useState(false);
  const [loadingFile, setLoadingFile] = useState(false);
  const [fileNote, setFileNote] = useState<string | null>(null);

  // Whether a local exclusions file is configured (mounted repo) — gates the "Load from file" button.
  useEffect(() => {
    api
      .exclusionsSource()
      .then((s) => setFileAvailable(s.available && !!s.source.path))
      .catch(() => setFileAvailable(false));
  }, []);

  // Results belong to the dataset they were run against; the pasted file doesn't.
  useEffect(() => {
    setCoverage(null);
    setConsolidation([]);
  }, [selected]);

  function loadFromFile() {
    setLoadingFile(true);
    setError(null);
    setFileNote(null);
    api
      .readLocalExclusions()
      .then((r) => {
        setTf(r.content);
        const at = r.from_git ? ` @ ${r.ref}${r.resolved_commit ? ` (${r.resolved_commit})` : ""}` : " (working tree)";
        setFileNote(`Loaded ${r.path}${at}`);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoadingFile(false));
  }

  function runCoverage() {
    if (!selected) return;
    setLoading(true);
    setError(null);
    api
      .exclusionCoverage(selected, tf, scope)
      .then(setCoverage)
      .catch((e) => {
        setCoverage(null);
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setLoading(false));
    // Hints are a side dish: if they fail, the coverage report above still stands on its own.
    api
      .exclusionsCount(tf)
      .then((r) => setConsolidation(r.consolidation_hints))
      .catch(() => setConsolidation([]));
  }

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
          className="h-32 w-full rounded-md border border-input bg-transparent p-2 font-mono text-xs shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          placeholder={'exclusion {\n  match_variable = "QueryStringArgNames"\n  operator       = "Equals"\n  selector       = "returnUrl"\n}'}
          value={tf}
          onChange={(e) => setTf(e.target.value)}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={runCoverage} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Check coverage
          </Button>
          {fileAvailable && (
            <Button variant="outline" onClick={loadFromFile} disabled={loadingFile}>
              {loadingFile ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderGit2 className="h-4 w-4" />}
              Load from file
            </Button>
          )}
          {fileNote && <span className="text-xs text-muted-foreground">{fileNote}</span>}
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {coverage && (
          <CoverageResults coverage={coverage} consolidation={consolidation} onInvestigate={onInvestigate} />
        )}
      </CardContent>
    </Card>
  );
}

function CoverageResults({
  coverage,
  consolidation,
  onInvestigate,
}: {
  coverage: Coverage;
  consolidation: ConsolidationHint[];
  onInvestigate: (ruleId: string) => void;
}) {
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

      {(coverage.duplicates.length > 0 ||
        coverage.conflicts.length > 0 ||
        coverage.stale_exclusions.length > 0 ||
        consolidation.length > 0) && (
        <div className="grid gap-3 text-xs md:grid-cols-2 lg:grid-cols-4">
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
          <ExclusionList
            title="Consolidation hints (free up slots)"
            tone="text-sky-500"
            items={consolidation.map(
              (h) => `${h.match_variable} ${h.selectors.join(" + ")}: ${h.suggestion} (saves ${h.slots_saved})`,
            )}
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
