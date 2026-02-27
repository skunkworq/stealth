"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function OverviewCard() {
  const { fingerprint, loading, modifications } = useFingerprint();

  if (loading) {
    return (
      <Card className="skeuo-panel overflow-hidden">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <span className="led-amber" />
            Loading...
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-5 bg-muted/30 rounded animate-pulse" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!fingerprint) return null;

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="led-green" />
          Overview
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-0">
        <InfoRow label="Capture ID" value={fingerprint.id} mono />
        <InfoRow
          label="Timestamp"
          value={new Date(fingerprint.timestamp).toLocaleString()}
        />
        <InfoRow label="Source IP" value={fingerprint.source_ip} mono />
        {fingerprint.server_name && (
          <InfoRow label="Host / SNI" value={fingerprint.server_name} />
        )}
        <InfoRow
          label="Protocol"
          value={fingerprint.http?.protocol || "Unknown"}
          badge
        />
        {fingerprint.tls && (
          <InfoRow
            label="TLS Version"
            value={fingerprint.tls.version_name}
            badge
          />
        )}
        {modifications.length > 0 && (
          <div className="pt-3 mt-3 border-t border-border/50">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="outline" className="text-amber-glow border-amber-glow/30 bg-amber-glow/5 text-xs">
                {modifications.length} modification{modifications.length !== 1 ? "s" : ""}
              </Badge>
              {modifications.slice(-3).map((mod, i) => (
                <span key={i} className="text-xs text-muted-foreground">{mod}</span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function InfoRow({ label, value, mono, badge }: { label: string; value: string; mono?: boolean; badge?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border/30 last:border-b-0">
      <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</span>
      {badge ? (
        <Badge variant="secondary" className="font-mono text-xs skeuo-raised px-2 py-0.5">
          {value}
        </Badge>
      ) : (
        <span className={`text-sm ${mono ? "font-mono text-emerald-glow/90" : "text-foreground"} max-w-[60%] text-right truncate`}>
          {value}
        </span>
      )}
    </div>
  );
}
