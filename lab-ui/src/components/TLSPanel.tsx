"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Panel,
  PanelHeader,
  PanelContent,
  PanelEmpty,
  PanelSection,
  PanelMetricGrid,
  PanelMetric,
} from "@/components/Panel";

interface CipherSuite {
  name: string;
  is_grease?: boolean;
}

interface Extension {
  name: string;
  is_grease?: boolean;
}

interface TLSData {
  version_name: string;
  ja3_hash: string;
  ja4?: string;
  alpn?: string[];
  alps?: string;
  cipher_suites?: CipherSuite[];
  extensions?: Extension[];
}

function TLSEmptyState() {
  return (
    <Panel>
      <PanelEmpty message="TLS Fingerprint — No TLS data. Connect via HTTPS to capture." />
    </Panel>
  );
}

function TLSVersionInfo({ tls }: { tls: TLSData }) {
  return (
    <PanelMetricGrid>
      <PanelMetric label="Version" value={tls.version_name} />
      <PanelMetric label="Cipher Suites" value={tls.cipher_suites?.length ?? 0} />
    </PanelMetricGrid>
  );
}

function CipherList({ cipherSuites }: { cipherSuites: CipherSuite[] }) {
  return (
    <PanelSection title="Cipher Suites" count={cipherSuites.length}>
      <ScrollArea className="h-[180px]">
        <div className="skeuo-inset rounded-lg p-3 space-y-1">
          {cipherSuites.map((c, i) => (
            <div
              key={c.name}
              className="flex items-center gap-2 text-xs font-mono py-1 border-b border-border/20 last:border-b-0"
            >
              <span className="text-muted-foreground w-5 text-right">{i + 1}.</span>
              <span className={c.is_grease ? "text-amber-glow/70 italic" : "text-emerald-glow/90"}>
                {c.name}
              </span>
              {c.is_grease && (
                <Badge
                  variant="outline"
                  className="text-[10px] px-1 py-0 text-amber-glow/60 border-amber-glow/20"
                >
                  GREASE
                </Badge>
              )}
            </div>
          ))}
        </div>
      </ScrollArea>
    </PanelSection>
  );
}

function ExtensionList({ extensions }: { extensions: Extension[] }) {
  return (
    <PanelSection title="Extensions" count={extensions.length}>
      <ScrollArea className="h-[180px]">
        <div className="skeuo-inset rounded-lg p-3 space-y-1">
          {extensions.map((e, i) => (
            <div
              key={e.name}
              className="flex items-center gap-2 text-xs font-mono py-1 border-b border-border/20 last:border-b-0"
            >
              <span className="text-muted-foreground w-5 text-right">{i + 1}.</span>
              <span className={e.is_grease ? "text-amber-glow/70 italic" : "text-foreground/80"}>
                {e.name}
              </span>
            </div>
          ))}
        </div>
      </ScrollArea>
    </PanelSection>
  );
}

export function TLSPanel() {
  const { fingerprint } = useFingerprint();
  const tls = fingerprint?.tls;

  if (!tls) {
    return <TLSEmptyState />;
  }

  return (
    <Panel>
      <PanelHeader
        title="TLS Fingerprint"
        icon={<span className="text-violet-glow text-lg">🔒</span>}
      />
      <PanelContent>
        <TLSVersionInfo tls={tls} />

        <div className="space-y-2">
          <HashRow label="JA3" value={tls.ja3_hash} color="text-cyan-glow" />
          {tls.ja4 && <HashRow label="JA4" value={tls.ja4} color="text-violet-glow" />}
        </div>

        {(tls.alpn || tls.alps) && (
          <div className="flex gap-2 flex-wrap">
            {tls.alpn?.map(a => (
              <Badge
                key={a}
                variant="outline"
                className="text-cyan-glow border-cyan-glow/30 bg-cyan-glow/5 font-mono text-xs"
              >
                ALPN: {a}
              </Badge>
            ))}
            {tls.alps && (
              <Badge
                variant="outline"
                className="text-violet-glow border-violet-glow/30 bg-violet-glow/5 font-mono text-xs"
              >
                ALPS: {tls.alps}
              </Badge>
            )}
          </div>
        )}

        {tls.cipher_suites && tls.cipher_suites.length > 0 && (
          <CipherList cipherSuites={tls.cipher_suites} />
        )}

        {tls.extensions && tls.extensions.length > 0 && (
          <ExtensionList extensions={tls.extensions} />
        )}
      </PanelContent>
    </Panel>
  );
}

function HashRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-2 px-3">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="text-[10px] shrink-0 font-bold px-1.5 py-0">
          {label}
        </Badge>
        <span className={`font-mono text-xs ${color} truncate`}>{value}</span>
      </div>
    </div>
  );
}
