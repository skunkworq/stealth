"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

export function TLSPanel() {
  const { fingerprint } = useFingerprint();
  const tls = fingerprint?.tls;

  if (!tls) {
    return (
      <Card className="skeuo-panel overflow-hidden">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <span className="led-red" />
            TLS Fingerprint
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground italic">No TLS data — connect via HTTPS to capture</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-violet-glow text-lg">🔒</span>
          TLS Fingerprint
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Key metrics */}
        <div className="grid grid-cols-2 gap-3">
          <MetricBox label="Version" value={tls.version_name} />
          <MetricBox label="Cipher Suites" value={String(tls.cipher_suites?.length ?? 0)} />
        </div>

        {/* JA3/JA4 hashes */}
        <div className="space-y-2">
          <HashRow label="JA3" value={tls.ja3_hash} color="text-cyan-glow" />
          {tls.ja4 && <HashRow label="JA4" value={tls.ja4} color="text-violet-glow" />}
        </div>

        {/* ALPN/ALPS */}
        {(tls.alpn || tls.alps) && (
          <div className="flex gap-2 flex-wrap">
            {tls.alpn?.map((a, i) => (
              <Badge key={i} variant="outline" className="text-cyan-glow border-cyan-glow/30 bg-cyan-glow/5 font-mono text-xs">
                ALPN: {a}
              </Badge>
            ))}
            {tls.alps && (
              <Badge variant="outline" className="text-violet-glow border-violet-glow/30 bg-violet-glow/5 font-mono text-xs">
                ALPS: {tls.alps}
              </Badge>
            )}
          </div>
        )}

        {/* Cipher Suites */}
        {tls.cipher_suites?.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Cipher Suites ({tls.cipher_suites.length})
            </h4>
            <ScrollArea className="h-[180px]">
              <div className="skeuo-inset rounded-lg p-3 space-y-1">
                {tls.cipher_suites.map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs font-mono py-1 border-b border-border/20 last:border-b-0">
                    <span className="text-muted-foreground w-5 text-right">{i + 1}.</span>
                    <span className={c.is_grease ? "text-amber-glow/70 italic" : "text-emerald-glow/90"}>
                      {c.name}
                    </span>
                    {c.is_grease && <Badge variant="outline" className="text-[10px] px-1 py-0 text-amber-glow/60 border-amber-glow/20">GREASE</Badge>}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        )}

        {/* Extensions */}
        {tls.extensions?.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Extensions ({tls.extensions.length})
            </h4>
            <ScrollArea className="h-[180px]">
              <div className="skeuo-inset rounded-lg p-3 space-y-1">
                {tls.extensions.map((e, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs font-mono py-1 border-b border-border/20 last:border-b-0">
                    <span className="text-muted-foreground w-5 text-right">{i + 1}.</span>
                    <span className={e.is_grease ? "text-amber-glow/70 italic" : "text-foreground/80"}>
                      {e.name}
                    </span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MetricBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-3 text-center">
      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">{label}</div>
      <div className="text-lg font-bold font-mono text-emerald-glow glow-text">{value}</div>
    </div>
  );
}

function HashRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-2 px-3">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="text-[10px] shrink-0 font-bold px-1.5 py-0">{label}</Badge>
        <span className={`font-mono text-xs ${color} truncate`}>{value}</span>
      </div>
    </div>
  );
}
