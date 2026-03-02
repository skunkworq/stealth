"use client";

import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useFingerprint } from "@/components/FingerprintProvider";
import { useToasts } from "@/components/Toasts";

const HTTP_STATUS_OK_MAX = 400,
  INTERNAL_URL = "http://localhost:8080/api/stealth-test",
  DEFAULT_TARGET = "https://tls.peet.ws/api/all";

interface TestResult {
  success: boolean;
  status_code?: number;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
}
interface SignatureTestState {
  isInternal: boolean;
  targetUrl: string;
  testing: boolean;
  result: TestResult | null;
  setIsInternal: (v: boolean) => void;
  setTargetUrl: (v: string) => void;
  runTest: () => Promise<void>;
}

function useSignatureTest(
  id: string | undefined,
  toast: (m: string, t: "success" | "error" | "warning") => void
): SignatureTestState {
  const [isInternal, setIsInternal] = useState(true),
    [targetUrl, setTargetUrl] = useState(DEFAULT_TARGET),
    [testing, setTesting] = useState(false),
    [result, setResult] = useState<TestResult | null>(null);
  const runTest = useCallback(async () => {
    if (!id) {
      toast(
        "No Capture Selected: Please select a fingerprint capture from the history log first.",
        "warning"
      );
      return;
    }
    const url = isInternal ? INTERNAL_URL : targetUrl;
    if (!url.startsWith("http")) {
      toast("Invalid URL: Target URL must start with http:// or https://", "error");
      return;
    }
    setTesting(true);
    setResult(null);
    try {
      const res = await fetch("/api/test-signature", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, url }),
      });
      const data = await res.json();
      setResult(data);
      if (data.success)
        toast(`Test Complete: Received HTTP ${data.status_code} from ${url}`, "success");
      else toast(`Test Failed: ${data.error || "Connection failed"}`, "error");
    } catch (e) {
      toast(`Test Error: ${String(e)}`, "error");
    } finally {
      setTesting(false);
    }
  }, [id, isInternal, targetUrl, toast]);
  return { isInternal, targetUrl, testing, result, setIsInternal, setTargetUrl, runTest };
}

function TesterEmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-center">
      <span className="text-2xl mb-2 opacity-50">🧪</span>
      <p className="text-xs text-muted-foreground">
        No signature loaded. Select a capture from the history to begin testing.
      </p>
    </div>
  );
}

function TargetInput({
  url,
  setUrl,
  disabled,
}: {
  url: string;
  setUrl: (v: string) => void;
  disabled: boolean;
}) {
  return (
    <div>
      <label className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider mb-1 block">
        Target URL
      </label>
      <input
        type="text"
        value={url}
        onChange={e => setUrl(e.target.value)}
        disabled={disabled}
        className="w-full bg-black/40 border border-white/10 rounded px-2.5 py-1.5 text-xs text-cyan-50 focus:outline-none focus:border-cyan-glow/50 transition-colors font-mono disabled:opacity-50"
      />
    </div>
  );
}

function ActionButtons({
  onTest,
  testing,
  disabled,
}: {
  onTest: () => void;
  testing: boolean;
  disabled: boolean;
}) {
  const base = "w-full py-2 rounded text-xs font-semibold uppercase tracking-wider transition-all";
  const state = testing
    ? "bg-cyan-900/40 text-cyan-glow/50 cursor-not-allowed border border-cyan-glow/10"
    : disabled
      ? "bg-white/5 text-muted-foreground/30 border border-white/5 cursor-not-allowed"
      : "bg-cyan-900/40 text-cyan-glow border border-cyan-glow/30 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,255,255,0.15)] active:scale-[0.98]";
  return (
    <button onClick={onTest} disabled={testing || disabled} className={`${base} ${state}`}>
      {testing ? "Testing Payload..." : "Execute Stealth Request"}
    </button>
  );
}

function StatusBadge({ code }: { code?: number }) {
  return (
    <Badge
      className={`font-mono text-[10px] ${code && code < HTTP_STATUS_OK_MAX ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"}`}
    >
      {code}
    </Badge>
  );
}

function HeadersList({ headers }: { headers: Record<string, string> }) {
  return (
    <div className="space-y-1">
      <span className="text-[10px] text-muted-foreground ml-1">Response Headers</span>
      <div className="bg-[#0a0a0a] border border-white/5 rounded p-2 max-h-[150px] overflow-y-auto">
        {Object.entries(headers).map(([k, v]) => (
          <div key={k} className="flex gap-2 text-[10px] mb-1 leading-tight font-mono">
            <span className="text-cyan-glow/70 whitespace-nowrap">{k}:</span>
            <span className="text-gray-400 break-all">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BodyDisplay({ body, toast }: { body: string; toast: (m: string, t: "success") => void }) {
  const fmt = (() => {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  })();
  const copy = () => {
    navigator.clipboard.writeText(body);
    toast("Trace copied to clipboard!", "success");
  };
  return (
    <div className="space-y-1 mt-3">
      <div className="flex items-center justify-between ml-1 mb-1">
        <span className="text-[10px] text-muted-foreground">Trace Output (Body)</span>
        <button
          onClick={copy}
          className="text-[9px] text-cyan-glow/70 hover:text-cyan-glow uppercase tracking-wider active:scale-95 transition-all"
        >
          Copy JSON
        </button>
      </div>
      <div className="bg-[#0a0a0a] border border-cyan-glow/20 rounded p-3 overflow-x-auto">
        <pre className="text-[10px] text-emerald-400 font-mono leading-relaxed whitespace-pre-wrap word-break-all">
          {fmt}
        </pre>
      </div>
    </div>
  );
}

function ErrorDisplay({ error }: { error?: string }) {
  return (
    <div className="bg-red-950/30 border border-red-500/20 rounded p-3">
      <p className="text-xs text-red-400 font-mono leading-relaxed break-all">Error: {error}</p>
    </div>
  );
}

function ResultsPanel({
  result,
  toast,
}: {
  result: TestResult;
  toast: (m: string, t: "success" | "error" | "warning") => void;
}) {
  return (
    <div className="mt-4 border-t border-white/5 pt-4">
      <h4 className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider mb-2">
        Test Result
      </h4>
      {result.success ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between bg-black/40 p-2 rounded border border-white/5">
            <span className="text-xs text-muted-foreground">Status Code</span>
            <StatusBadge code={result.status_code} />
          </div>
          {result.headers && Object.keys(result.headers).length > 0 && (
            <HeadersList headers={result.headers} />
          )}
          {result.body && <BodyDisplay body={result.body} toast={toast} />}
        </div>
      ) : (
        <ErrorDisplay error={result.error} />
      )}
    </div>
  );
}

function InternalToggle({
  isInternal,
  setIsInternal,
  disabled,
}: {
  isInternal: boolean;
  setIsInternal: (v: boolean) => void;
  disabled: boolean;
}) {
  return (
    <div className="flex items-center justify-between mb-4 bg-black/30 p-2 rounded-lg border border-white/5">
      <div className="flex flex-col">
        <span className="text-[10px] font-semibold text-cyan-glow uppercase tracking-wider">
          Internal Shield
        </span>
        <span className="text-[9px] text-muted-foreground">
          Test against built-in Adversarial WAF
        </span>
      </div>
      <button
        onClick={() => setIsInternal(!isInternal)}
        disabled={disabled}
        className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center justify-center rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50 ${isInternal ? "bg-cyan-600" : "bg-gray-700"}`}
      >
        <span
          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition duration-200 ease-in-out ${isInternal ? "translate-x-1.5" : "-translate-x-1.5"}`}
        />
      </button>
    </div>
  );
}

export function SignatureTester() {
  const { selectedCaptureId } = useFingerprint(),
    { addToast } = useToasts();
  const { isInternal, targetUrl, testing, result, setIsInternal, setTargetUrl, runTest } =
    useSignatureTest(selectedCaptureId, addToast);
  return (
    <Card className="skeuo-panel border-cyan-glow/20 shadow-[0_4px_20px_rgba(0,0,0,0.5),inset_0_1px_rgba(255,255,255,0.05)] mt-4">
      <CardHeader className="border-b border-border/30 bg-background/50 backdrop-blur-sm pb-4">
        <div className="flex items-center gap-2">
          <span className="text-cyan-glow animate-pulse">🧪</span>
          <CardTitle className="text-sm font-bold tracking-tight text-foreground shadow-black drop-shadow-md">
            Signature Tester
          </CardTitle>
          {selectedCaptureId && (
            <Badge
              variant="outline"
              className="ml-auto font-mono text-[9px] border-cyan-glow/50 text-cyan-glow"
            >
              Active Signature Loaded
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          Play back the selected fingerprint dynamically against any URL.
        </p>
      </CardHeader>
      <CardContent className="pt-4 space-y-4">
        {!selectedCaptureId ? (
          <TesterEmptyState />
        ) : (
          <>
            <InternalToggle
              isInternal={isInternal}
              setIsInternal={setIsInternal}
              disabled={testing}
            />
            {!isInternal && (
              <TargetInput url={targetUrl} setUrl={setTargetUrl} disabled={testing} />
            )}
            <ActionButtons onTest={runTest} testing={testing} disabled={!selectedCaptureId} />
            {result && <ResultsPanel result={result} toast={addToast} />}
          </>
        )}
      </CardContent>
    </Card>
  );
}
