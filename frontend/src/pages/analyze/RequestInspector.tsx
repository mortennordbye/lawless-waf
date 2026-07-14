/** Full-request inspector: every rule one request tripped, plus its anomaly score.
 *
 * Fetches its own detail from the tracking reference it's given, so AnalyzePage only tracks
 * *which* request is open, not the request. Rendered only while a ref is set. */
import { Loader2, Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type RequestDetail, type ScopeParams } from "@/lib/api";

import { ModeBadge, SHORT, TH, WIDE } from "./shared";

export function RequestInspector({
  trackingRef,
  selected,
  scope,
  onClose,
}: {
  trackingRef: string;
  selected: string;
  scope: ScopeParams;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setError(null);
    setLoading(true);
    api
      .requestDetail(selected, trackingRef, scope)
      .then((d) => !cancelled && setDetail(d))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
    // scope is rebuilt each render; its parts are what actually change the query.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trackingRef, selected, scope.policy, scope.datasets]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // The modal scrolls itself; letting the page scroll behind it loses the operator's place.
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  const head = detail?.rows[0];
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/50 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Request detail"
    >
      <Card className="my-8 w-full max-w-4xl" onClick={(e) => e.stopPropagation()}>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Search className="h-5 w-5" /> Request detail
            </span>
            <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close" title="Close (Esc)">
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
          ) : error ? (
            <p className="text-sm text-destructive">Could not load this request: {error}</p>
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
