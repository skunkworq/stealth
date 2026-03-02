"use client";

import { useState, useCallback } from "react";
import { useFingerprint } from "@/components/FingerprintProvider";
import type {
  CompleteFingerprint,
  TLSFingerprint,
  HTTP2Fingerprint,
  HTTPFingerprint,
} from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// Constants for magic numbers
const COPY_TIMEOUT_MS = 2000;
const ID_SLICE_LENGTH = 8;
const HASH_PREVIEW_LENGTH = 16;

// Hook for copy functionality
function useFingerprintCopy(jsonOutput: string | null) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (!jsonOutput) return;
    try {
      await navigator.clipboard.writeText(jsonOutput);
      setCopied(true);
      setTimeout(() => setCopied(false), COPY_TIMEOUT_MS);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = jsonOutput;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), COPY_TIMEOUT_MS);
    }
  }, [jsonOutput]);

  return { copied, handleCopy };
}

// Copy button component
function CopyButton({ copied, onCopy }: { copied: boolean; onCopy: () => void }) {
  return (
    <Button
      variant="outline"
      size="xs"
      onClick={onCopy}
      className={`text-[9px] uppercase font-bold tracking-wider transition-colors ${
        copied
          ? "border-emerald-glow/30 text-emerald-glow"
          : "border-cyan-glow/30 text-cyan-glow hover:bg-cyan-glow/10"
      }`}
    >
      {copied ? "Copied" : "Copy to Clipboard"}
    </Button>
  );
}

// IP badge component
function IPBadge({ ip }: { ip: string }) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className="text-[9px] font-mono border-cyan-glow/30 text-cyan-glow bg-cyan-glow/5"
          >
            IP: {ip || "N/A"}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>Source IP address</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// JA3 hash badge component
function JA3Badge({ hash }: { hash: string }) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className="text-[9px] font-mono border-emerald-glow/30 text-emerald-glow bg-emerald-glow/5 max-w-[180px] truncate"
          >
            JA3: {hash.slice(0, HASH_PREVIEW_LENGTH)}...
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs break-all font-mono text-[10px]">{hash}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// JA4 hash badge component
function JA4Badge({ hash }: { hash: string }) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className="text-[9px] font-mono border-purple-glow/30 text-purple-glow bg-purple-glow/5 max-w-[180px] truncate"
          >
            JA4: {hash.slice(0, HASH_PREVIEW_LENGTH)}...
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs break-all font-mono text-[10px]">{hash}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// Header badges row component
function HeaderBadges({ fingerprint }: { fingerprint: CompleteFingerprint }) {
  const tls = fingerprint.tls;

  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <IPBadge ip={fingerprint.source_ip} />
      {tls?.ja3_hash && <JA3Badge hash={tls.ja3_hash} />}
      {tls?.ja4 && <JA4Badge hash={tls.ja4} />}
      {fingerprint.http?.protocol && (
        <Badge
          variant="outline"
          className="text-[9px] font-mono border-amber-glow/30 text-amber-glow bg-amber-glow/5"
        >
          {fingerprint.http.protocol}
        </Badge>
      )}
      {tls?.alpn && tls.alpn.length > 0 && (
        <Badge
          variant="outline"
          className="text-[9px] font-mono border-cyan-glow/30 text-cyan-glow/70 bg-cyan-glow/5"
        >
          ALPN: {tls.alpn.join(", ")}
        </Badge>
      )}
    </div>
  );
}

// Viewer header component
function ViewerHeader({ fingerprint }: { fingerprint: CompleteFingerprint }) {
  return (
    <CardHeader className="relative pb-3">
      <div className="absolute top-3 right-3 flex gap-2">
        <div className="screw-hole" />
        <div className="screw-hole" />
      </div>
      <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-lg">🔬</span>
        Multi-Layer Fingerprint Viewer
      </CardTitle>
      <HeaderBadges fingerprint={fingerprint} />
    </CardHeader>
  );
}

// TLS Viewer component
function TLSViewer({ tls }: { tls: TLSFingerprint | undefined }) {
  if (!tls) {
    return <EmptyState message="No TLS data captured. Connect via HTTPS to populate." />;
  }

  return (
    <div className="space-y-3">
      <ScrollArea className="h-[400px]">
        <Table>
          <TableHeader>
            <TableRow className="border-white/10 bg-white/5">
              <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 w-[180px]">
                Field
              </TableHead>
              <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
                Value
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <KVRow field="Version" value={tls.version_name} />
            <KVRow field="JA3 Hash" value={tls.ja3_hash} color="text-cyan-glow" mono />
            <KVRow field="JA3 String" value={tls.ja3_string} mono truncate />
            {tls.ja4 && <KVRow field="JA4" value={tls.ja4} color="text-purple-glow" mono />}
            {tls.alpn && <KVRow field="ALPN" value={tls.alpn.join(", ")} />}
            {tls.alps && <KVRow field="ALPS" value={tls.alps} />}
            <CipherSuitesViewer cipherSuites={tls.cipher_suites} />
            <ExtensionsViewer extensions={tls.extensions} />
            {tls.supported_groups && tls.supported_groups.length > 0 && (
              <KVRow field="Supported Groups" value={tls.supported_groups.join(", ")} mono />
            )}
            {tls.key_share_groups && tls.key_share_groups.length > 0 && (
              <KVRow field="Key Share Groups" value={tls.key_share_groups.join(", ")} mono />
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  );
}

// Cipher suites viewer
function CipherSuitesViewer({ cipherSuites }: { cipherSuites?: TLSFingerprint["cipher_suites"] }) {
  if (!cipherSuites?.length) return null;

  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Cipher Suites ({cipherSuites.length})
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-0.5">
          {cipherSuites.map(c => (
            <div
              key={`cipher-${c.name}-${c.position}`}
              className="flex items-center gap-2 text-[10px] font-mono"
            >
              <span className="text-muted-foreground/50 w-4 text-right shrink-0">
                {c.position}.
              </span>
              <span className={c.is_grease ? "text-amber-glow/70 italic" : "text-emerald-glow/90"}>
                {c.name}
              </span>
              {c.is_grease && (
                <Badge
                  variant="outline"
                  className="text-[8px] px-1 py-0 h-3 text-amber-glow/60 border-amber-glow/20"
                >
                  GREASE
                </Badge>
              )}
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Extensions viewer
function ExtensionsViewer({ extensions }: { extensions?: TLSFingerprint["extensions"] }) {
  if (!extensions?.length) return null;

  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Extensions ({extensions.length})
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-0.5">
          {extensions.map(e => (
            <div
              key={`ext-${e.name}-${e.position}`}
              className="flex items-center gap-2 text-[10px] font-mono"
            >
              <span className="text-muted-foreground/50 w-4 text-right shrink-0">
                {e.position}.
              </span>
              <span className={e.is_grease ? "text-amber-glow/70 italic" : "text-foreground/80"}>
                {e.name}
              </span>
              {e.is_grease && (
                <Badge
                  variant="outline"
                  className="text-[8px] px-1 py-0 h-3 text-amber-glow/60 border-amber-glow/20"
                >
                  GREASE
                </Badge>
              )}
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// HTTP/2 Viewer component
function HTTP2Viewer({ http2 }: { http2: HTTP2Fingerprint | undefined }) {
  if (!http2) {
    return <EmptyState message="No HTTP/2 data captured. Requires HTTP/2 connection." />;
  }

  return (
    <ScrollArea className="h-[400px]">
      <Table>
        <TableHeader>
          <TableRow className="border-white/10 bg-white/5">
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 w-[180px]">
              Field
            </TableHead>
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
              Value
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <HTTP2Settings settings={http2.settings} />
          <PseudoHeaderOrder order={http2.pseudo_header_order} />
          {http2.header_order && http2.header_order.length > 0 && (
            <HeaderOrderViewer headers={http2.header_order} />
          )}
          {http2.window_updates && http2.window_updates.length > 0 && (
            <WindowUpdatesViewer updates={http2.window_updates} />
          )}
          {http2.frame_sequence && http2.frame_sequence.length > 0 && (
            <FrameSequenceViewer frames={http2.frame_sequence} />
          )}
        </TableBody>
      </Table>
    </ScrollArea>
  );
}

// HTTP/2 settings viewer
function HTTP2Settings({ settings }: { settings?: HTTP2Fingerprint["settings"] }) {
  if (!settings?.length) return null;

  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        SETTINGS Frame
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-1">
          {settings.map(s => (
            <div
              key={`setting-${s.name}-${s.position}`}
              className="flex items-center gap-3 text-[10px]"
            >
              <span className="text-muted-foreground/50 w-4 text-right shrink-0">
                {s.position}.
              </span>
              <span className="font-mono text-foreground/70 w-[200px]">{s.name}</span>
              <span className="font-mono text-emerald-glow font-bold">
                {s.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Pseudo header order viewer
function PseudoHeaderOrder({ order }: { order: string[] }) {
  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Pseudo Header Order
      </TableCell>
      <TableCell className="py-2">
        <div className="flex flex-wrap gap-1">
          {order.map(h => (
            <Badge
              key={`pseudo-${h}`}
              variant="outline"
              className="text-[9px] font-mono border-cyan-glow/30 text-cyan-glow bg-cyan-glow/5"
            >
              {h}
            </Badge>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Header order viewer
function HeaderOrderViewer({ headers }: { headers: string[] }) {
  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Header Order
      </TableCell>
      <TableCell className="py-2">
        <div className="flex flex-wrap gap-1">
          {headers.map(h => (
            <Badge
              key={`header-${h}`}
              variant="outline"
              className="text-[9px] font-mono border-amber-glow/30 text-amber-glow bg-amber-glow/5"
            >
              {h}
            </Badge>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Window updates viewer
function WindowUpdatesViewer({
  updates,
}: {
  updates: NonNullable<HTTP2Fingerprint["window_updates"]>;
}) {
  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Window Updates
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-0.5">
          {updates.map(wu => (
            <div
              key={`window-${wu.stream_id}-${wu.increment}`}
              className="text-[10px] font-mono text-foreground/70"
            >
              Stream {wu.stream_id}:{" "}
              <span className="text-emerald-glow">{wu.increment.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Frame sequence viewer
function FrameSequenceViewer({
  frames,
}: {
  frames: NonNullable<HTTP2Fingerprint["frame_sequence"]>;
}) {
  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Priority Frames
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-0.5">
          {frames.map(f => (
            <div
              key={`frame-${f.stream_id}-${f.type}`}
              className="text-[10px] font-mono text-foreground/70"
            >
              <span className="text-amber-glow">{f.type}</span> @ stream {f.stream_id}
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// HTTP Viewer component
function HTTPViewer({ http }: { http: HTTPFingerprint | undefined }) {
  if (!http) {
    return <EmptyState message="No HTTP data captured." />;
  }

  return (
    <ScrollArea className="h-[400px]">
      <Table>
        <TableHeader>
          <TableRow className="border-white/10 bg-white/5">
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 w-[180px]">
              Field
            </TableHead>
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
              Value
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <KVRow field="Method" value={http.method} />
          <KVRow field="Path" value={http.path} mono />
          <KVRow field="Protocol" value={http.protocol} />
          <KVRow field="User Agent" value={http.user_agent} mono truncate />
          <KVRow field="Accept" value={http.accept} mono truncate />
          <KVRow field="Accept-Language" value={http.accept_language} mono />
          <KVRow field="Accept-Encoding" value={http.accept_encoding} mono />
          <KVRow field="Cookie Count" value={String(http.cookie_count)} />
          <ClientHintsViewer hints={http.client_hints} />
          <HTTPHeaders headers={http.headers} />
        </TableBody>
      </Table>
    </ScrollArea>
  );
}

// Client hints viewer
function ClientHintsViewer({ hints }: { hints?: HTTPFingerprint["client_hints"] }) {
  if (!hints) return null;

  return (
    <>
      {hints.sec_ch_ua && <KVRow field="sec-ch-ua" value={hints.sec_ch_ua} mono />}
      {hints.sec_ch_ua_mobile && (
        <KVRow field="sec-ch-ua-mobile" value={hints.sec_ch_ua_mobile} mono />
      )}
      {hints.sec_ch_ua_platform && (
        <KVRow field="sec-ch-ua-platform" value={hints.sec_ch_ua_platform} mono />
      )}
    </>
  );
}

// HTTP headers viewer
function HTTPHeaders({ headers }: { headers?: HTTPFingerprint["headers"] }) {
  if (!headers?.length) return null;

  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 align-top text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Headers ({headers.length})
      </TableCell>
      <TableCell className="py-2">
        <div className="space-y-0.5">
          {headers.map(h => (
            <div
              key={`http-hdr-${h.name}-${h.position}`}
              className="flex items-start gap-2 text-[10px] font-mono py-0.5 border-b border-border/10 last:border-b-0"
            >
              <span className="text-muted-foreground/50 w-4 text-right shrink-0">
                {h.position}.
              </span>
              <span className={`shrink-0 ${h.is_pseudo ? "text-purple-glow" : "text-cyan-glow"}`}>
                {h.name}
              </span>
              {h.value && (
                <>
                  <span className="text-muted-foreground/30">:</span>
                  <span className="text-foreground/60 break-all">{h.value}</span>
                </>
              )}
              {h.is_pseudo && (
                <Badge
                  variant="outline"
                  className="text-[8px] px-1 py-0 h-3 text-purple-glow/60 border-purple-glow/20 shrink-0"
                >
                  PSEUDO
                </Badge>
              )}
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Behavior viewer component
function BehaviorViewer({ fingerprint }: { fingerprint: CompleteFingerprint }) {
  const tls = fingerprint.tls;
  const http = fingerprint.http;
  const http2 = fingerprint.http2;
  const modifications = fingerprint._modifications;

  return (
    <ScrollArea className="h-[400px]">
      <Table>
        <TableHeader>
          <TableRow className="border-white/10 bg-white/5">
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 w-[180px]">
              Metric
            </TableHead>
            <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
              Value
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <KVRow field="Capture ID" value={fingerprint.id} mono />
          <KVRow field="Timestamp" value={fingerprint.timestamp} mono />
          <KVRow field="Source IP" value={fingerprint.source_ip} mono />
          {fingerprint.server_name && (
            <KVRow field="Server Name" value={fingerprint.server_name} mono />
          )}
          {tls && <TLSMetrics tls={tls} />}
          {http && <HTTPMetrics http={http} />}
          {http2 && <HTTP2Metrics http2={http2} />}
          {fingerprint.http_response && <ResponseMetrics response={fingerprint.http_response} />}
          {modifications && modifications.length > 0 && (
            <ModificationsViewer modifications={modifications} />
          )}
        </TableBody>
      </Table>
    </ScrollArea>
  );
}

// TLS metrics
function TLSMetrics({ tls }: { tls: TLSFingerprint }) {
  return (
    <>
      <KVRow field="TLS Version" value={tls.version_name} />
      <KVRow field="Cipher Suite Count" value={String(tls.cipher_suites?.length ?? 0)} />
      <KVRow field="Extension Count" value={String(tls.extensions?.length ?? 0)} />
      <KVRow
        field="GREASE Ciphers"
        value={String(tls.cipher_suites?.filter(c => c.is_grease).length ?? 0)}
      />
      <KVRow
        field="GREASE Extensions"
        value={String(tls.extensions?.filter(e => e.is_grease).length ?? 0)}
      />
    </>
  );
}

// HTTP metrics
function HTTPMetrics({ http }: { http: HTTPFingerprint }) {
  return (
    <>
      <KVRow field="HTTP Method" value={http.method} />
      <KVRow field="Header Count" value={String(http.headers?.length ?? 0)} />
      <KVRow
        field="Pseudo Headers"
        value={String(http.headers?.filter(h => h.is_pseudo).length ?? 0)}
      />
      <KVRow field="Cookie Count" value={String(http.cookie_count)} />
      <KVRow
        field="Client Hints"
        value={http.client_hints ? "Present" : "Absent"}
        color={http.client_hints ? "text-emerald-glow" : "text-red-glow"}
      />
    </>
  );
}

// HTTP/2 metrics
function HTTP2Metrics({ http2 }: { http2: HTTP2Fingerprint }) {
  return (
    <>
      <KVRow field="H2 Settings Count" value={String(http2.settings?.length ?? 0)} />
      <KVRow field="H2 Frame Sequence" value={String(http2.frame_sequence?.length ?? 0)} />
    </>
  );
}

// Response metrics
function ResponseMetrics({
  response,
}: {
  response: NonNullable<CompleteFingerprint["http_response"]>;
}) {
  return (
    <>
      <KVRow field="Response Status" value={`${response.status_code} ${response.status}`} />
      <KVRow field="Response Protocol" value={response.protocol} />
      <KVRow field="Response Body Length" value={response.body_length.toLocaleString()} />
      <KVRow field="Response Header Count" value={String(response.headers?.length ?? 0)} />
    </>
  );
}

// Modifications viewer
function ModificationsViewer({ modifications }: { modifications: string[] }) {
  return (
    <TableRow className="border-white/5">
      <TableCell className="py-2 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        Modifications
      </TableCell>
      <TableCell className="py-2">
        <div className="flex flex-wrap gap-1">
          {modifications.map(m => (
            <Badge
              key={`mod-${m}`}
              variant="outline"
              className="text-[9px] font-mono border-amber-glow/30 text-amber-glow bg-amber-glow/5"
            >
              {m}
            </Badge>
          ))}
        </div>
      </TableCell>
    </TableRow>
  );
}

// Raw JSON viewer
function RawViewer({ jsonOutput }: { jsonOutput: string }) {
  const { copied, handleCopy } = useFingerprintCopy(jsonOutput);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
          Complete JSON Output
        </span>
        <CopyButton copied={copied} onCopy={handleCopy} />
      </div>
      <ScrollArea className="h-[400px]">
        <div className="skeuo-inset rounded-lg p-3">
          <pre className="text-[10px] font-mono text-foreground/70 whitespace-pre-wrap break-all">
            {jsonOutput}
          </pre>
        </div>
      </ScrollArea>
    </div>
  );
}

// Export button component
function ExportButton({
  fingerprint,
  jsonOutput,
}: {
  fingerprint: CompleteFingerprint | null;
  jsonOutput: string | null;
}) {
  const handleExport = useCallback(() => {
    if (!jsonOutput) return;
    const blob = new Blob([jsonOutput], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fingerprint-${fingerprint?.id?.slice(0, ID_SLICE_LENGTH) ?? "export"}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [jsonOutput, fingerprint?.id]);

  return (
    <Button
      variant="outline"
      size="xs"
      onClick={handleExport}
      className="text-[9px] uppercase font-bold tracking-wider border-cyan-glow/30 text-cyan-glow hover:bg-cyan-glow/10"
    >
      Export JSON
    </Button>
  );
}

// Tab triggers component
function TabTriggers() {
  const tabs = [
    { value: "tls", label: "TLS", color: "cyan" },
    { value: "http2", label: "HTTP/2", color: "emerald" },
    { value: "http", label: "HTTP", color: "amber" },
    { value: "behavior", label: "Behavior", color: "purple" },
    { value: "raw", label: "Raw", color: "red" },
  ] as const;

  return (
    <TabsList className="skeuo-inset bg-black/40 border border-white/5 p-1 h-auto">
      {tabs.map(tab => (
        <TabsTrigger
          key={tab.value}
          value={tab.value}
          className={`text-[10px] uppercase font-bold px-3 py-1.5 data-[state=active]:bg-${tab.color}-glow/20 data-[state=active]:text-${tab.color}-glow`}
        >
          {tab.label}
        </TabsTrigger>
      ))}
    </TabsList>
  );
}

// Tab list component
function ViewerTabs({
  fingerprint,
  jsonOutput,
}: {
  fingerprint: CompleteFingerprint;
  jsonOutput: string;
}) {
  return (
    <Tabs defaultValue="tls" className="w-full">
      <div className="flex items-center justify-between mb-3">
        <TabTriggers />
        <ExportButton fingerprint={fingerprint} jsonOutput={jsonOutput} />
      </div>

      <TabsContent value="tls" className="mt-0 outline-none">
        <TLSViewer tls={fingerprint.tls} />
      </TabsContent>

      <TabsContent value="http2" className="mt-0 outline-none">
        <HTTP2Viewer http2={fingerprint.http2} />
      </TabsContent>

      <TabsContent value="http" className="mt-0 outline-none">
        <HTTPViewer http={fingerprint.http} />
      </TabsContent>

      <TabsContent value="behavior" className="mt-0 outline-none">
        <BehaviorViewer fingerprint={fingerprint} />
      </TabsContent>

      <TabsContent value="raw" className="mt-0 outline-none">
        <RawViewer jsonOutput={jsonOutput} />
      </TabsContent>
    </Tabs>
  );
}

// Loading state
function LoadingState() {
  return (
    <Card className="skeuo-panel">
      <CardContent className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_FINGERPRINT_DATA...
      </CardContent>
    </Card>
  );
}

// Error state
function ErrorState({ message }: { message: string | null }) {
  return (
    <Card className="skeuo-panel">
      <CardContent className="p-12 text-center">
        <p className="text-xs text-red-glow font-mono">
          {message ?? "No fingerprint data available"}
        </p>
      </CardContent>
    </Card>
  );
}

// Empty state for tabs
function EmptyState({ message }: { message: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-8 text-center">
      <p className="text-xs text-muted-foreground italic font-mono">{message}</p>
    </div>
  );
}

// Key-value row component
function KVRow({
  field,
  value,
  color,
  mono,
  truncate: truncateValue,
}: {
  field: string;
  value: string;
  color?: string;
  mono?: boolean;
  truncate?: boolean;
}) {
  return (
    <TableRow className="border-white/5 hover:bg-white/[0.02]">
      <TableCell className="py-2 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
        {field}
      </TableCell>
      <TableCell
        className={`py-2 text-[10px] ${mono ? "font-mono" : ""} ${color ?? "text-foreground/80"} ${truncateValue ? "max-w-[300px] truncate" : ""}`}
      >
        {value || "N/A"}
      </TableCell>
    </TableRow>
  );
}

// Main component
export function FingerprintViewer() {
  const { fingerprint, loading, error, jsonOutput } = useFingerprint();

  if (loading) {
    return <LoadingState />;
  }

  if (error || !fingerprint) {
    return <ErrorState message={error} />;
  }

  return (
    <Card className="skeuo-panel overflow-hidden">
      <ViewerHeader fingerprint={fingerprint} />
      <CardContent className="pt-0">
        <ViewerTabs fingerprint={fingerprint} jsonOutput={jsonOutput} />
      </CardContent>
    </Card>
  );
}
