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

export function ControlPanel() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null); // which action is in flight
  const [error, setError] = useState<string | null>(null);
  
  // Chrome Launch Options
  const [targetUrl, setTargetUrl] = useState("");
  const [headless, setHeadless] = useState(false);
  const [closeAfter, setCloseAfter] = useState(10);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: StatusResponse = await res.json();
      setStatus(data);
      setError(null);
    } catch (err) {
      // Silently fail status polling — backend may not be running
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const doAction = async (endpoint: string, actionLabel: string, payload?: any) => {
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
      // Refresh status
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setLoading(null);
    }
  };

  const proxyRunning = status?.proxy?.running ?? false;
  const chromeRunning = status?.chrome?.running ?? false;

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
      <CardContent className="space-y-4">
        {/* Proxy Controls */}
        <div className="skeuo-inset rounded-lg p-3 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={proxyRunning ? "led-green" : "led-red"} />
              <span className="text-xs font-semibold text-foreground uppercase tracking-wider">
                MITM Proxy
              </span>
            </div>
            <Badge
              variant="outline"
              className={`text-[9px] px-2 py-0 ${
                proxyRunning
                  ? "text-emerald-glow border-emerald-glow/30 bg-emerald-glow/10"
                  : "text-muted-foreground border-border"
              }`}
            >
              {proxyRunning ? "RUNNING" : "STOPPED"}
            </Badge>
          </div>
          {proxyRunning && status?.proxy?.address && (
            <div className="text-[10px] font-mono text-muted-foreground">
              ↳ {status.proxy.address}
            </div>
          )}
          <Button
            size="sm"
            className={`w-full text-xs skeuo-button h-7 ${
              proxyRunning
                ? "bg-red-glow/20 hover:bg-red-glow/30 text-red-glow border-red-glow/30"
                : "bg-emerald-glow/20 hover:bg-emerald-glow/30 text-emerald-glow border-emerald-glow/30"
            }`}
            variant="outline"
            disabled={loading !== null}
            onClick={() =>
              proxyRunning
                ? doAction("/api/proxy/stop", "proxy")
                : doAction("/api/proxy/start", "proxy")
            }
          >
            {loading === "proxy" ? (
              <span className="animate-pulse">•••</span>
            ) : proxyRunning ? (
              "Stop Proxy"
            ) : (
              "Start Proxy"
            )}
          </Button>
        </div>

        <Separator className="bg-border/20" />

        {/* Chrome Controls */}
        <div className="skeuo-inset rounded-lg p-3 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={chromeRunning ? "led-green" : "led-red"} />
              <span className="text-xs font-semibold text-foreground uppercase tracking-wider">
                Chrome
              </span>
            </div>
            <Badge
              variant="outline"
              className={`text-[9px] px-2 py-0 ${
                chromeRunning
                  ? "text-emerald-glow border-emerald-glow/30 bg-emerald-glow/10"
                  : "text-muted-foreground border-border"
              }`}
            >
              {chromeRunning ? "RUNNING" : "STOPPED"}
            </Badge>
          </div>
          {chromeRunning && status?.chrome?.pid && (
            <div className="text-[10px] font-mono text-muted-foreground">
              ↳ PID {status.chrome.pid}
            </div>
          )}

          {!chromeRunning && (
            <div className="space-y-2 mt-2">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Target URL</label>
                <input
                  type="text"
                  placeholder="e.g. https://example.com"
                  className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all placeholder:text-muted-foreground/30"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              <div className="flex items-center justify-between">
                <label 
                  className="text-[10px] text-muted-foreground uppercase tracking-wider cursor-pointer select-none" 
                  onClick={() => setHeadless(!headless)}
                >
                  Headless Mode
                </label>
                <button
                  type="button"
                  role="switch"
                  aria-checked={headless}
                  onClick={() => setHeadless(!headless)}
                  className={`relative h-6 w-11 rounded-full p-1 transition-all duration-300 skeuo-inset ${
                    headless ? "border-cyan-glow/50 shadow-[inset_0_2px_4px_rgba(0,0,0,0.6),0_0_8px_rgba(34,211,238,0.2)]" : "border-black/50"
                  }`}
                >
                  <div
                    className={`h-4 w-4 rounded-full transition-all duration-300 skeuo-raised shadow-md flex items-center justify-center ${
                      headless ? "translate-x-5 border-cyan-glow/30" : "translate-x-0 border-red-glow/30"
                    }`}
                  >
                    <div className={`w-1.5 h-1.5 rounded-full ${headless ? "bg-cyan-glow shadow-[0_0_5px_#22d3ee]" : "bg-red-glow shadow-[0_0_5px_#f87171]"}`} />
                  </div>
                </button>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Auto-close (Seconds)</label>
                <input
                  type="number"
                  placeholder="0 to disable"
                  min="0"
                  className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all placeholder:text-muted-foreground/30"
                  value={closeAfter}
                  onChange={(e) => setCloseAfter(parseInt(e.target.value) || 0)}
                />
              </div>
            </div>
          )}

          <Button
            size="sm"
            className={`w-full text-xs skeuo-button h-7 ${
              chromeRunning
                ? "bg-red-glow/20 hover:bg-red-glow/30 text-red-glow border-red-glow/30"
                : "bg-cyan-glow/20 hover:bg-cyan-glow/30 text-cyan-glow border-cyan-glow/30"
            }`}
            variant="outline"
            disabled={loading !== null}
            onClick={() => {
              if (chromeRunning) {
                doAction("/api/chrome/stop", "chrome");
              } else {
                doAction("/api/chrome/launch", "chrome", {
                  url: targetUrl,
                  headless: headless,
                  close_after: closeAfter
                });
              }
            }}
          >
            {loading === "chrome" ? (
              <span className="animate-pulse">•••</span>
            ) : chromeRunning ? (
              "Stop Chrome"
            ) : (
              "Launch Chrome"
            )}
          </Button>
        </div>

        {/* Server Info */}
        {status?.server && (
          <>
            <Separator className="bg-border/20" />
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="skeuo-inset rounded p-1.5">
                <div className="text-[9px] text-muted-foreground uppercase">HTTP</div>
                <div className="text-xs font-mono text-foreground">:{status.server.http_port}</div>
              </div>
              <div className="skeuo-inset rounded p-1.5">
                <div className="text-[9px] text-muted-foreground uppercase">HTTPS</div>
                <div className="text-xs font-mono text-foreground">:{status.server.https_port}</div>
              </div>
              <div className="skeuo-inset rounded p-1.5">
                <div className="text-[9px] text-muted-foreground uppercase">Proxy</div>
                <div className="text-xs font-mono text-foreground">:{status.server.proxy_port}</div>
              </div>
            </div>
          </>
        )}

        {/* Error Display */}
        {error && (
          <div className="rounded-lg bg-red-glow/10 border border-red-glow/20 px-3 py-2">
            <p className="text-[10px] text-red-glow">{error}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
