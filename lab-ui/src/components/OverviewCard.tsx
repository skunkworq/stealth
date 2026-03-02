"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const SKELETON_ROWS = [1, 2, 3, 4]; // eslint-disable-line no-magic-numbers
const MAX_MODIFICATION_PREVIEW = 3;
const MODIFICATION_KEY_PREFIX_LENGTH = 10;
const MAX_WIDTH_PERCENT = 60;

export function OverviewCard() {
  const { fingerprint, loading, modifications } = useFingerprint();

  if (loading) {
    return <OverviewSkeleton />;
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
        <InfoRow label="Timestamp" value={new Date(fingerprint.timestamp).toLocaleString()} />
        <InfoRow label="Source IP" value={fingerprint.source_ip} mono />
        {fingerprint.server_name && <InfoRow label="Host / SNI" value={fingerprint.server_name} />}
        <InfoRow label="Protocol" value={fingerprint.http?.protocol || "Unknown"} badge />
        {fingerprint.tls && (
          <InfoRow label="TLS Version" value={fingerprint.tls.version_name} badge />
        )}
        <ModificationsList modifications={modifications} />
      </CardContent>
    </Card>
  );
}

function OverviewSkeleton() {
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
          {SKELETON_ROWS.map(i => (
            <div key={i} className="h-5 bg-muted/30 rounded animate-pulse" />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ModificationsList({ modifications }: { modifications: string[] }) {
  if (modifications.length === 0) return null;

  return (
    <div className="pt-3 mt-3 border-t border-border/50">
      <div className="flex items-center gap-2 flex-wrap">
        <Badge
          variant="outline"
          className="text-amber-glow border-amber-glow/30 bg-amber-glow/5 text-xs"
        >
          {modifications.length} modification{modifications.length !== 1 ? "s" : ""}
        </Badge>
        {modifications.slice(-MAX_MODIFICATION_PREVIEW).map(mod => (
          <span
            key={`mod-${mod.slice(0, MODIFICATION_KEY_PREFIX_LENGTH)}-${mod.slice(-MODIFICATION_KEY_PREFIX_LENGTH)}`}
            className="text-xs text-muted-foreground"
          >
            {mod}
          </span>
        ))}
      </div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono,
  badge,
}: {
  label: string;
  value: string;
  mono?: boolean;
  badge?: boolean;
}) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border/30 last:border-b-0">
      <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        {label}
      </span>
      {badge ? (
        <Badge variant="secondary" className="font-mono text-xs skeuo-raised px-2 py-0.5">
          {value}
        </Badge>
      ) : (
        <span
          className={`text-sm ${mono ? "font-mono text-emerald-glow/90" : "text-foreground"} max-w-[${MAX_WIDTH_PERCENT}%] text-right truncate`}
        >
          {value}
        </span>
      )}
    </div>
  );
}
