import { ShieldAlert, Star } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, type AzureStatus } from "@/lib/api";
import { AnalyzePage } from "@/pages/AnalyzePage";
import { DownloadPage } from "@/pages/DownloadPage";
import { SettingsPage } from "@/pages/SettingsPage";

export default function App() {
  const [azure, setAzure] = useState<AzureStatus | null>(null);
  const [tab, setTab] = useState("settings");
  // The dataset the Download tab last handed over: clicking a cached chip, or finishing a
  // download, preselects it in Analyze instead of making the user find it in the dropdown.
  const [pendingDataset, setPendingDataset] = useState<string | null>(null);

  function refreshAzure() {
    api
      .azureStatus()
      .then(setAzure)
      .catch(() => setAzure(null));
  }

  useEffect(refreshAzure, []);

  return (
    <div className="mx-auto max-w-6xl p-6">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-xl font-bold">lawless-waf</h1>
            <p className="text-sm text-muted-foreground">Azure WAF block analysis &amp; exclusion context</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {azure ? (
            azure.logged_in ? (
              <Badge variant="success">az: {azure.user ?? "signed in"}</Badge>
            ) : (
              <Badge variant="warning">az: not signed in</Badge>
            )
          ) : (
            <Badge variant="outline">az: unknown</Badge>
          )}
          <a
            href="https://github.com/mortennordbye/lawless-waf"
            target="_blank"
            rel="noreferrer"
            title="lawless-waf on GitHub — a star helps if you find it useful"
            className="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <Star className="h-3.5 w-3.5" />
            Star on GitHub
          </a>
        </div>
      </header>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="download">Download</TabsTrigger>
          <TabsTrigger value="analyze">Analyze</TabsTrigger>
        </TabsList>
        <TabsContent value="settings">
          <SettingsPage azure={azure} onAzureRefresh={refreshAzure} />
        </TabsContent>
        <TabsContent value="download">
          <DownloadPage
            onAnalyze={(id) => {
              setPendingDataset(id);
              setTab("analyze");
            }}
            onDownloaded={setPendingDataset}
          />
        </TabsContent>
        <TabsContent value="analyze">
          <AnalyzePage active={tab === "analyze"} initialDataset={pendingDataset} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
