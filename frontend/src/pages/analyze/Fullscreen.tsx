/** Expand-to-window shell for the Analyze tables.
 *
 * Troubleshooting means reading wide rows (URI, matched value, message) in bulk, and a card in a
 * 3-column page never has the room. Any panel can opt in: keep a boolean, put `FullscreenToggle`
 * in the header, wrap the content in `FullscreenPanel`. The content renders in exactly one place
 * either way, so nothing is mounted twice. */
import { Maximize2, Minimize2, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";

export function FullscreenToggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      title={on ? "Exit fullscreen (Esc)" : "Expand to fullscreen"}
      className="inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground"
    >
      {on ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
      {on ? "Exit" : "Fullscreen"}
    </button>
  );
}

export function FullscreenPanel({
  on,
  onExit,
  title,
  meta,
  children,
}: {
  on: boolean;
  onExit: () => void;
  title: string;
  meta?: ReactNode;
  children: ReactNode;
}) {
  // Esc is the reflex for a full-window view; without it the only way out is finding the button.
  useEffect(() => {
    if (!on) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onExit();
    };
    window.addEventListener("keydown", onKey);
    // The panel scrolls itself; letting the page scroll behind it loses the operator's place.
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [on, onExit]);

  // One wrapper in one tree position, expanded with CSS rather than re-parented: toggling
  // fullscreen must not remount the content, or the filter and sort you set up are wiped
  // exactly when you go looking closer.
  return (
    <div className={on ? "fixed inset-0 z-50 flex flex-col overflow-hidden bg-background p-4" : undefined}>
      {on && (
        <div className="mb-3 flex shrink-0 items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="text-base font-semibold">{title}</h2>
            {meta && <div className="text-xs text-muted-foreground">{meta}</div>}
          </div>
          <button
            type="button"
            onClick={onExit}
            title="Exit fullscreen (Esc)"
            className="inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" /> Close
          </button>
        </div>
      )}
      {children}
    </div>
  );
}
