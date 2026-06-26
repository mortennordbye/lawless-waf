import { Activity, ChevronDown, ChevronUp } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type ActivityEvent } from "@/lib/api";

// Recent MCP activity is "active" if the newest tool call landed within this window.
const ACTIVE_WINDOW_S = 8;
const COLLAPSE_KEY = "mcp-activity-collapsed";

function relTime(ts: number, now: number): string {
  const s = Math.max(0, Math.round(now - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function argsLine(args: ActivityEvent["args"]): string {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${v}`)
    .join(" · ");
}

export function ActivityFeed() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(COLLAPSE_KEY) === "1");

  function toggleCollapsed() {
    setCollapsed((c) => {
      const next = !c;
      localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
      return next;
    });
  }

  useEffect(() => {
    const ctrl = api.streamActivity(
      (e) => setEvents((prev) => [e, ...prev].slice(0, 100)),
      setConnected,
    );
    return () => ctrl.abort();
  }, []);

  // Tick so relative times and the "in use" pulse stay current without a server round-trip.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);

  const active = events.length > 0 && now - events[0].ts < ACTIVE_WINDOW_S;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" /> MCP activity
          {active ? (
            <span className="flex items-center gap-1 text-xs font-medium text-emerald-500">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-500" /> in use
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <span
                className={`inline-block h-2 w-2 rounded-full ${connected ? "bg-muted-foreground/40" : "bg-muted-foreground/20"}`}
              />
              {connected ? "idle" : "disconnected"}
            </span>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto h-7 px-2 text-xs text-muted-foreground"
            onClick={toggleCollapsed}
            aria-expanded={!collapsed}
            title={collapsed ? "Show MCP activity" : "Hide MCP activity"}
          >
            {collapsed ? (
              <>
                <ChevronDown className="h-4 w-4" /> Show
              </>
            ) : (
              <>
                <ChevronUp className="h-4 w-4" /> Hide
              </>
            )}
          </Button>
        </CardTitle>
        {!collapsed && (
          <CardDescription>
            What the AI agent is doing through the MCP server — each tool call as it happens.
          </CardDescription>
        )}
      </CardHeader>
      {!collapsed && (
      <CardContent>
        {events.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No MCP calls yet. When an agent runs a tool (a live check, a search, an analysis), it shows up here.
          </p>
        ) : (
          <div className="max-h-72 space-y-1 overflow-auto">
            {events.map((e, i) => (
              <div
                key={`${e.ts}-${i}`}
                className="flex items-center gap-2 rounded border-l-2 border-border/60 py-1 pl-2 text-xs hover:bg-muted/40"
              >
                <span className="w-16 shrink-0 font-mono text-muted-foreground">{relTime(e.ts, now)}</span>
                <Badge variant={e.ok ? "secondary" : "destructive"} className="shrink-0 font-mono">
                  {e.tool}
                </Badge>
                {argsLine(e.args) && <span className="shrink-0 font-mono text-muted-foreground">{argsLine(e.args)}</span>}
                <span className={`ml-auto truncate pl-2 text-right ${e.ok ? "text-muted-foreground" : "text-destructive"}`}>
                  {e.summary}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
      )}
    </Card>
  );
}
