"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

interface ProxyStatus {
  running: boolean;
  address?: string;
  pac_url?: string;
}

interface ChromeStatus {
  running: boolean;
  chrome_path?: string;
  pid?: number;
}

interface ServerStatus {
  http_port: number;
  https_port: number;
  proxy_port: number;
  proxy_enabled: boolean;
}

interface StatusResponse {
  proxy: ProxyStatus;
  chrome: ChromeStatus;
  server: ServerStatus;
}

interface DoActionConfig {
  endpoint: string;
  actionLabel: string;
  payload?: Record<string, unknown>;
}

const DEFAULT_CLOSE_AFTER_SECONDS = 10;
const STATUS_POLL_INTERVAL = 2000;

function useStatusPolling() {
  const [status, setStatus] = useState<StatusResponse | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: StatusResponse = await res.json();
      setStatus(data);
    } catch {
      // Silently fail status polling — backend may not be running
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, STATUS_POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  return { status, fetchStatus, setStatus };
}

function useDoAction(fetchStatus: () => Promise<void>) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const doAction = useCallback(
    async ({ endpoint, actionLabel, payload }: DoActionConfig) => {
      setLoading(actionLabel);
      setError(null);
      try {
        const options: RequestInit = { method: "POST" };
        if (payload) {
          options.headers = { "Content-Type": "application/json" };
          options.body = JSON.stringify(payload);
        }
        const res = await fetch(endpoint, options);
        const data = await res.json();
        if (!data.ok) {
          setError(data.error || "Unknown error");
        }
        await fetchStatus();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Request failed");
      } finally {
        setLoading(null);
      }
    },
    [fetchStatus]
  );

  return { loading, error, setError, doAction };
}

function useControlPanel() {
  const [targetUrl, setTargetUrl] = useState("");
  const [headless, setHeadless] = useState(false);
  const [closeAfter, setCloseAfter] = useState(DEFAULT_CLOSE_AFTER_SECONDS);
  const { status, fetchStatus, setStatus } = useStatusPolling();
  const { loading, error, setError, doAction } = useDoAction(fetchStatus);

  return {
    status,
    setStatus,
    loading,
    error,
    setError,
    targetUrl,
    setTargetUrl,
    headless,
    setHeadless,
    closeAfter,
    setCloseAfter,
    doAction,
  };
}

interface ProxyControlsProps {
  running: boolean;
  address?: string;
  loading: string | null;
  onToggle: () => void;
}

function ProxyControls({ running, address, loading, onToggle }: ProxyControlsProps) {
  return (
    <div className="skeuo-inset rounded-lg p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={running ? "led-green" : "led-red"} />
          <span className="text-xs font-semibold text-foreground uppercase tracking-wider">
            MITM Proxy
          </span>
        </div>
        <Badge
          variant="outline"
          className={`text-[9px] px-2 py-0 ${
            running
              ? "text-emerald-glow border-emerald-glow/30 bg-emerald-glow/10"
              : "text-muted-foreground border-border"
          }`}
        >
          {running ? "RUNNING" : "STOPPED"}
        </Badge>
      </div>
      {running && address && (
        <div className="text-[10px] font-mono text-muted-foreground">↳ {address}</div>
      )}
      <Button
        size="sm"
        className={`w-full text-xs skeuo-button h-7 ${
          running
            ? "bg-red-glow/20 hover:bg-red-glow/30 text-red-glow border-red-glow/30"
            : "bg-emerald-glow/20 hover:bg-emerald-glow/30 text-emerald-glow border-emerald-glow/30"
        }`}
        variant="outline"
        disabled={loading !== null}
        onClick={onToggle}
      >
        {loading === "proxy" ? (
          <span className="animate-pulse">•••</span>
        ) : running ? (
          "Stop Proxy"
        ) : (
          "Start Proxy"
        )}
      </Button>
    </div>
  );
}

interface HeadlessToggleProps {
  headless: boolean;
  setHeadless: (value: boolean) => void;
}

function HeadlessToggle({ headless, setHeadless }: HeadlessToggleProps) {
  const handleToggle = () => setHeadless(!headless);
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setHeadless(!headless);
    }
  };

  return (
    <div className="flex items-center justify-between">
      <label
        htmlFor="headless-toggle"
        className="text-[10px] text-muted-foreground uppercase tracking-wider cursor-pointer select-none"
      >
        Headless Mode
      </label>
      <button
        id="headless-toggle"
        type="button"
        role="switch"
        aria-checked={headless}
        aria-label="Headless mode"
        onClick={handleToggle}
        onKeyDown={handleKeyDown}
        className={`relative h-6 w-11 rounded-full p-1 transition-all duration-300 skeuo-inset focus-visible:ring-2 focus-visible:ring-cyan-glow focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
          headless
            ? "border-cyan-glow/50 shadow-[inset_0_2px_4px_rgba(0,0,0,0.6),0_0_8px_rgba(34,211,238,0.2)]"
            : "border-black/50"
        }`}
      >
        <div
          className={`h-4 w-4 rounded-full transition-all duration-300 skeuo-raised shadow-md flex items-center justify-center ${
            headless ? "translate-x-5 border-cyan-glow/30" : "translate-x-0 border-red-glow/30"
          }`}
        >
          <div
            className={`w-1.5 h-1.5 rounded-full ${
              headless
                ? "bg-cyan-glow shadow-[0_0_5px_#22d3ee]"
                : "bg-red-glow shadow-[0_0_5px_#f87171]"
            }`}
          />
        </div>
      </button>
    </div>
  );
}

interface ChromeLaunchFormProps {
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  headless: boolean;
  setHeadless: (value: boolean) => void;
  closeAfter: number;
  setCloseAfter: (value: number) => void;
}

function ChromeLaunchForm({
  targetUrl,
  setTargetUrl,
  headless,
  setHeadless,
  closeAfter,
  setCloseAfter,
}: ChromeLaunchFormProps) {
  return (
    <div className="space-y-2 mt-2">
      <div>
        <label
          htmlFor="target-url"
          className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1"
        >
          Target URL
        </label>
        <input
          id="target-url"
          type="url"
          name="target-url"
          autoComplete="url"
          placeholder="https://example.com…"
          className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all placeholder:text-muted-foreground/30"
          value={targetUrl}
          onChange={e => setTargetUrl(e.target.value)}
        />
      </div>
      <HeadlessToggle headless={headless} setHeadless={setHeadless} />
      <div>
        <label
          htmlFor="close-after"
          className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1"
        >
          Auto-close (Seconds)
        </label>
        <input
          id="close-after"
          type="number"
          name="close-after"
          min="0"
          placeholder="0 to disable…"
          className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all placeholder:text-muted-foreground/30"
          value={closeAfter}
          onChange={e => setCloseAfter(parseInt(e.target.value) || 0)}
        />
      </div>
    </div>
  );
}

interface ChromeStatusHeaderProps {
  running: boolean;
}

function ChromeStatusHeader({ running }: ChromeStatusHeaderProps) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className={running ? "led-green" : "led-red"} />
        <span className="text-xs font-semibold text-foreground uppercase tracking-wider">
          Chrome
        </span>
      </div>
      <Badge
        variant="outline"
        className={`text-[9px] px-2 py-0 ${
          running
            ? "text-emerald-glow border-emerald-glow/30 bg-emerald-glow/10"
            : "text-muted-foreground border-border"
        }`}
      >
        {running ? "RUNNING" : "STOPPED"}
      </Badge>
    </div>
  );
}

interface ChromeToggleButtonProps {
  running: boolean;
  loading: string | null;
  onToggle: () => void;
}

function ChromeToggleButton({ running, loading, onToggle }: ChromeToggleButtonProps) {
  return (
    <Button
      size="sm"
      className={`w-full text-xs skeuo-button h-7 ${
        running
          ? "bg-red-glow/20 hover:bg-red-glow/30 text-red-glow border-red-glow/30"
          : "bg-cyan-glow/20 hover:bg-cyan-glow/30 text-cyan-glow border-cyan-glow/30"
      }`}
      variant="outline"
      disabled={loading !== null}
      onClick={onToggle}
    >
      {loading === "chrome" ? (
        <span className="animate-pulse">•••</span>
      ) : running ? (
        "Stop Chrome"
      ) : (
        "Launch Chrome"
      )}
    </Button>
  );
}

interface ChromeControlsProps {
  running: boolean;
  pid?: number;
  loading: string | null;
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  headless: boolean;
  setHeadless: (value: boolean) => void;
  closeAfter: number;
  setCloseAfter: (value: number) => void;
  onToggle: () => void;
}

function ChromeControls({
  running,
  pid,
  loading,
  targetUrl,
  setTargetUrl,
  headless,
  setHeadless,
  closeAfter,
  setCloseAfter,
  onToggle,
}: ChromeControlsProps) {
  return (
    <div className="skeuo-inset rounded-lg p-3 space-y-3">
      <ChromeStatusHeader running={running} />
      {running && pid && (
        <div className="text-[10px] font-mono text-muted-foreground">↳ PID {pid}</div>
      )}
      {!running && (
        <ChromeLaunchForm
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          headless={headless}
          setHeadless={setHeadless}
          closeAfter={closeAfter}
          setCloseAfter={setCloseAfter}
        />
      )}
      <ChromeToggleButton running={running} loading={loading} onToggle={onToggle} />
    </div>
  );
}

interface ServerInfoProps {
  server: ServerStatus;
}

function ServerInfo({ server }: ServerInfoProps) {
  return (
    <>
      <Separator className="bg-border/20" />
      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="skeuo-inset rounded p-1.5">
          <div className="text-[9px] text-muted-foreground uppercase">HTTP</div>
          <div className="text-xs font-mono text-foreground">:{server.http_port}</div>
        </div>
        <div className="skeuo-inset rounded p-1.5">
          <div className="text-[9px] text-muted-foreground uppercase">HTTPS</div>
          <div className="text-xs font-mono text-foreground">:{server.https_port}</div>
        </div>
        <div className="skeuo-inset rounded p-1.5">
          <div className="text-[9px] text-muted-foreground uppercase">Proxy</div>
          <div className="text-xs font-mono text-foreground">:{server.proxy_port}</div>
        </div>
      </div>
    </>
  );
}

interface ErrorDisplayProps {
  error: string;
}

function ErrorDisplay({ error }: ErrorDisplayProps) {
  return (
    <div className="rounded-lg bg-red-glow/10 border border-red-glow/20 px-3 py-2">
      <p className="text-[10px] text-red-glow">{error}</p>
    </div>
  );
}

interface ControlPanelContentProps {
  status: StatusResponse | null;
  loading: string | null;
  error: string | null;
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  headless: boolean;
  setHeadless: (value: boolean) => void;
  closeAfter: number;
  setCloseAfter: (value: number) => void;
  doAction: (config: DoActionConfig) => Promise<void>;
}

interface UseControlPanelActionsConfig {
  status: StatusResponse | null;
  targetUrl: string;
  headless: boolean;
  closeAfter: number;
  doAction: (config: DoActionConfig) => Promise<void>;
}

function useControlPanelActions({
  status,
  targetUrl,
  headless,
  closeAfter,
  doAction,
}: UseControlPanelActionsConfig) {
  const proxyRunning = status?.proxy?.running ?? false;
  const chromeRunning = status?.chrome?.running ?? false;

  const handleProxyToggle = () => {
    doAction({
      endpoint: proxyRunning ? "/api/proxy/stop" : "/api/proxy/start",
      actionLabel: "proxy",
    });
  };

  const handleChromeToggle = () => {
    if (chromeRunning) {
      doAction({ endpoint: "/api/chrome/stop", actionLabel: "chrome" });
    } else {
      doAction({
        endpoint: "/api/chrome/launch",
        actionLabel: "chrome",
        payload: { url: targetUrl, headless, close_after: closeAfter },
      });
    }
  };

  return { proxyRunning, chromeRunning, handleProxyToggle, handleChromeToggle };
}

function ControlPanelContent({
  status,
  loading,
  error,
  targetUrl,
  setTargetUrl,
  headless,
  setHeadless,
  closeAfter,
  setCloseAfter,
  doAction,
}: ControlPanelContentProps) {
  const { proxyRunning, chromeRunning, handleProxyToggle, handleChromeToggle } =
    useControlPanelActions({ status, targetUrl, headless, closeAfter, doAction });

  return (
    <CardContent className="space-y-4">
      <ProxyControls
        running={proxyRunning}
        address={status?.proxy?.address}
        loading={loading}
        onToggle={handleProxyToggle}
      />
      <Separator className="bg-border/20" />
      <ChromeControls
        running={chromeRunning}
        pid={status?.chrome?.pid}
        loading={loading}
        targetUrl={targetUrl}
        setTargetUrl={setTargetUrl}
        headless={headless}
        setHeadless={setHeadless}
        closeAfter={closeAfter}
        setCloseAfter={setCloseAfter}
        onToggle={handleChromeToggle}
      />
      {status?.server && <ServerInfo server={status.server} />}
      {error && <ErrorDisplay error={error} />}
    </CardContent>
  );
}

export function ControlPanel() {
  const {
    status,
    loading,
    error,
    targetUrl,
    setTargetUrl,
    headless,
    setHeadless,
    closeAfter,
    setCloseAfter,
    doAction,
  } = useControlPanel();

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-lg">⚡</span>
          Controls
        </CardTitle>
      </CardHeader>
      <ControlPanelContent
        status={status}
        loading={loading}
        error={error}
        targetUrl={targetUrl}
        setTargetUrl={setTargetUrl}
        headless={headless}
        setHeadless={setHeadless}
        closeAfter={closeAfter}
        setCloseAfter={setCloseAfter}
        doAction={doAction}
      />
    </Card>
  );
}
