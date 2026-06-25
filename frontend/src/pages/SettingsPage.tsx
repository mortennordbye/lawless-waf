import { CheckCircle2, Circle, Loader2, Pencil, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { api, type AzureStatus, type AzureSubscription, type AzureTarget } from "@/lib/api";

type Option = { value: string; label: string };

const PREFLIGHT = [
  "Activate the PIM role granting Storage Blob Data Reader on the logs account (if you use PIM)",
  "Connect your VPN, if the storage account is network-restricted",
  "Run `az login` on the host (the app reuses that session)",
];

export function SettingsPage({
  azure,
  onAzureRefresh,
}: {
  azure: AzureStatus | null;
  onAzureRefresh: () => void;
}) {
  const [target, setTarget] = useState<AzureTarget>({ storage_account: "", container: "", subscription: "" });
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [manual, setManual] = useState(false);

  useEffect(() => {
    api.getConfig().then(setTarget).catch((e) => setErr(String(e.message)));
  }, []);

  async function save() {
    setMsg(null);
    setErr(null);
    try {
      const saved = await api.putConfig(target);
      setTarget(saved);
      setMsg("Saved.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            Azure target
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setManual((m) => !m)}
              title={manual ? "Pick from Azure" : "Enter manually"}
            >
              <Pencil className={manual ? "h-4 w-4 text-primary" : "h-4 w-4"} />
            </Button>
          </CardTitle>
          <CardDescription>Storage account holding the Azure WAF logs.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {manual ? (
            <>
              <TextField label="Subscription" value={target.subscription} onChange={(v) => setTarget({ ...target, subscription: v })} />
              <TextField label="Storage account" value={target.storage_account} onChange={(v) => setTarget({ ...target, storage_account: v })} />
              <TextField label="Container" value={target.container} onChange={(v) => setTarget({ ...target, container: v })} />
            </>
          ) : (
            <AzurePickers
              target={target}
              loggedIn={!!azure?.logged_in}
              onChange={(patch) => setTarget((t) => ({ ...t, ...patch }))}
            />
          )}
          <div className="flex items-center gap-3">
            <Button onClick={save}>Save settings</Button>
            {msg && <span className="text-sm text-emerald-500">{msg}</span>}
            {err && <span className="text-sm text-destructive">{err}</span>}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            Preflight
            <Button variant="ghost" size="icon" onClick={onAzureRefresh} title="Re-check Azure">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </CardTitle>
          <CardDescription>These must be done on the host before downloading.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {PREFLIGHT.map((step, i) => {
            const done = i === 2 && azure?.logged_in;
            return (
              <div key={i} className="flex items-start gap-2 text-sm">
                {done ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                ) : (
                  <Circle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                )}
                <span>{step}</span>
              </div>
            );
          })}
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            {azure?.logged_in ? (
              <>
                Signed in as <b>{azure.user}</b> — subscription <b>{azure.subscription}</b>.
              </>
            ) : (
              <span className="text-amber-500">{azure?.detail ?? "Not signed in. Run `az login` on the host."}</span>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function AzurePickers({
  target,
  loggedIn,
  onChange,
}: {
  target: AzureTarget;
  loggedIn: boolean;
  onChange: (patch: Partial<AzureTarget>) => void;
}) {
  const [subs, setSubs] = useState<AzureSubscription[]>([]);
  const [accounts, setAccounts] = useState<string[]>([]);
  const [containers, setContainers] = useState<string[]>([]);
  const [loading, setLoading] = useState<"subs" | "accounts" | "containers" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadSubs = useCallback(async () => {
    setError(null);
    setLoading("subs");
    try {
      const { subscriptions } = await api.azureSubscriptions();
      setSubs(subscriptions);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(null);
    }
  }, []);

  // Auto-load subscriptions once signed in.
  useEffect(() => {
    if (loggedIn) loadSubs();
  }, [loggedIn, loadSubs]);

  // Load storage accounts when the subscription changes.
  useEffect(() => {
    if (!target.subscription) {
      setAccounts([]);
      return;
    }
    let cancelled = false;
    setError(null);
    setLoading("accounts");
    api
      .azureStorageAccounts(target.subscription)
      .then(({ storage_accounts }) => {
        if (!cancelled) setAccounts(storage_accounts.map((a) => a.name));
      })
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(null));
    return () => {
      cancelled = true;
    };
  }, [target.subscription]);

  // Load containers when the storage account changes.
  useEffect(() => {
    if (!target.subscription || !target.storage_account) {
      setContainers([]);
      return;
    }
    let cancelled = false;
    setError(null);
    setLoading("containers");
    api
      .azureContainers(target.storage_account, target.subscription)
      .then(({ containers }) => {
        if (!cancelled) setContainers(containers.map((c) => c.name));
      })
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(null));
    return () => {
      cancelled = true;
    };
  }, [target.subscription, target.storage_account]);

  if (!loggedIn) {
    return (
      <p className="text-sm text-amber-500">
        Sign in with <code>az login</code> on the host to pick from your Azure resources, or use
        the pencil to enter values manually.
      </p>
    );
  }

  return (
    <>
      <SelectField
        label="Subscription"
        value={target.subscription}
        options={subs.map((s) => ({ value: s.name, label: `${s.name} (${s.id})` }))}
        loading={loading === "subs"}
        onChange={(v) => onChange({ subscription: v, storage_account: "", container: "" })}
      />
      <SelectField
        label="Storage account"
        value={target.storage_account}
        options={accounts.map((a) => ({ value: a, label: a }))}
        loading={loading === "accounts"}
        disabled={!target.subscription}
        onChange={(v) => onChange({ storage_account: v, container: "" })}
      />
      <SelectField
        label="Container"
        value={target.container}
        options={containers.map((c) => ({ value: c, label: c }))}
        loading={loading === "containers"}
        disabled={!target.storage_account}
        onChange={(v) => onChange({ container: v })}
      />
      <div className="flex items-center gap-3">
        <Button variant="outline" size="sm" onClick={loadSubs}>
          <RefreshCw className="mr-2 h-3.5 w-3.5" /> Reload
        </Button>
        {error && <span className="text-sm text-destructive">{error}</span>}
      </div>
    </>
  );
}

function SelectField({
  label,
  value,
  options,
  loading,
  disabled,
  onChange,
}: {
  label: string;
  value: string;
  options: Option[];
  loading?: boolean;
  disabled?: boolean;
  onChange: (v: string) => void;
}) {
  // Keep the saved value visible even before its list has loaded.
  const opts =
    value && !options.some((o) => o.value === value) ? [{ value, label: value }, ...options] : options;
  return (
    <div className="space-y-1.5">
      <Label className="flex items-center gap-2">
        {label}
        {loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
      </Label>
      <Select value={value} disabled={disabled || loading} onChange={(e) => onChange(e.target.value)}>
        <option value="" disabled>
          {loading ? "Loading…" : `Select ${label.toLowerCase()}…`}
        </option>
        {opts.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

function TextField({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
