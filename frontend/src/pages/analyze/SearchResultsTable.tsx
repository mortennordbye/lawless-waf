/** The row-level event table. Shared: the Search panel renders it, and so does the Overview
 *  stat-tile drill in AnalyzePage. */
import { X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { type GeoInfo, type SearchEvent } from "@/lib/api";

import {
  type Accessors,
  InspectButton,
  ModeBadge,
  SHORT,
  SortLabel,
  TH,
  WIDE,
  fmtTime,
  useSort,
} from "./shared";

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

export function SearchResultsTable({
  events,
  onOpenRequest,
  fullscreen = false,
  ipGeo = {},
  onExclude,
}: {
  events: SearchEvent[];
  onOpenRequest: (ref: string) => void;
  fullscreen?: boolean;
  ipGeo?: Record<string, GeoInfo>;
  onExclude?: (ip: string) => void;
}) {
  const { sorted, sortKey, dir, toggle } = useSort(events, SEARCH_SORT, "time");
  const sortProps = { sortKey, dir, onSort: toggle };
  return (
    <div className={fullscreen ? "flex-1 overflow-auto rounded border text-xs min-h-0" : "max-h-[28rem] overflow-auto rounded border text-xs"}>
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
          {sorted.map((e, i) => {
            const geo = ipGeo[e.client_ip];
            return (
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
                <td className={`${SHORT} font-mono`}>
                  <span className="inline-flex items-center gap-1">
                    <span>{e.client_ip}</span>
                    {geo && (
                      <span title={geo.country} className="text-[11px] text-muted-foreground">
                        {geo.flag} {geo.country_code !== "private" ? geo.country_code : ""}
                      </span>
                    )}
                    {onExclude && (
                      <button
                        onClick={() => onExclude(e.client_ip)}
                        title={`Exclude ${e.client_ip} from results`}
                        className="ml-0.5 rounded text-muted-foreground hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </span>
                </td>
                <td className={SHORT}>{e.host}</td>
                <td className={`${WIDE} font-mono`}>{e.request_uri}</td>
                <td className={`${WIDE} text-muted-foreground`}>{e.msg}</td>
                <td className={SHORT}>
                  <InspectButton onClick={() => onOpenRequest(e.tracking_reference)} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
