"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function HTTP2Panel() {
  const { fingerprint } = useFingerprint();
  const http2 = fingerprint?.http2;

  if (!http2) {
    return (
      <Card className="skeuo-panel overflow-hidden">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <span className="led-red" />
            HTTP/2 Fingerprint
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground italic">No HTTP/2 data available</p>
        </CardContent>
      </Card>
    );
  }

  // Calculate max value for gauge bars
  const maxVal = Math.max(...(http2.settings?.map(s => s.value) ?? [1]));

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-amber-glow text-lg">📡</span>
          HTTP/2 Fingerprint
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* SETTINGS table with gauge bars */}
        {http2.settings?.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">SETTINGS</h4>
            <div className="skeuo-inset rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/20 hover:bg-transparent">
                    <TableHead className="text-xs text-muted-foreground h-8">Setting</TableHead>
                    <TableHead className="text-xs text-muted-foreground h-8 text-right">Value</TableHead>
                    <TableHead className="text-xs text-muted-foreground h-8 w-[100px]">Level</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {http2.settings.map((s, i) => (
                    <TableRow key={i} className="border-border/10 hover:bg-white/[0.02]">
                      <TableCell className="font-mono text-xs py-2 text-foreground/80">{s.name}</TableCell>
                      <TableCell className="font-mono text-xs py-2 text-right text-emerald-glow">
                        {s.value.toLocaleString()}
                      </TableCell>
                      <TableCell className="py-2 w-[100px]">
                        <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden border border-black/30">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${Math.max(5, (Math.log(s.value + 1) / Math.log(maxVal + 1)) * 100)}%`,
                              background: `linear-gradient(90deg, #34d399, #22d3ee)`,
                              boxShadow: `0 0 6px rgba(52, 211, 153, 0.4)`,
                            }}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}

        {/* Pseudo-Header Order */}
        {http2.pseudo_header_order?.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Pseudo-Header Order</h4>
            <div className="skeuo-inset rounded-lg p-3">
              <div className="flex items-center gap-1 flex-wrap">
                {http2.pseudo_header_order.map((h, i) => (
                  <div key={i} className="flex items-center gap-1">
                    <span className="skeuo-raised rounded px-2 py-1 font-mono text-xs text-cyan-glow">
                      {h}
                    </span>
                    {i < http2.pseudo_header_order.length - 1 && (
                      <span className="text-muted-foreground text-xs">→</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
