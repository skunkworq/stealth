"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";

export function ConfigPanel() {
  const {
    fingerprint,
    modifications,
    applyPlatformPreset,
    applyBrowserPreset,
    resetToOriginal,
    refresh,
    platformPresets: platforms,
    browserPresets: browsers,
  } = useFingerprint();

  if (!fingerprint) return null;

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-lg">⚙️</span>
          Configuration
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Platform selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Platform</label>
          <Select onValueChange={applyPlatformPreset}>
            <SelectTrigger className="skeuo-raised border-0 h-9 text-sm font-mono">
              <SelectValue placeholder="Auto-detect" />
            </SelectTrigger>
            <SelectContent className="skeuo-panel border-border/30">
              {Object.entries(platforms).map(([key, p]) => (
                <SelectItem key={key} value={key} className="font-mono text-sm">
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Browser selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Browser</label>
          <Select onValueChange={applyBrowserPreset}>
            <SelectTrigger className="skeuo-raised border-0 h-9 text-sm font-mono">
              <SelectValue placeholder="Auto-detect" />
            </SelectTrigger>
            <SelectContent className="skeuo-panel border-border/30">
              {Object.entries(browsers).map(([key, b]) => (
                <SelectItem key={key} value={key} className="font-mono text-sm">
                  {b.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Modification status */}
        {modifications.length > 0 && (
          <div className="skeuo-inset rounded-lg p-2.5">
            <div className="flex items-center gap-2">
              <span className="led-amber" />
              <Badge variant="outline" className="text-amber-glow border-amber-glow/30 bg-amber-glow/5 text-[10px]">
                {modifications.length} change{modifications.length !== 1 ? "s" : ""}
              </Badge>
            </div>
            <div className="mt-2 space-y-0.5">
              {modifications.map((mod, i) => (
                <p key={i} className="text-xs text-muted-foreground">• {mod}</p>
              ))}
            </div>
          </div>
        )}

        {/* Action buttons */}
        <div className="flex gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={resetToOriginal}
            className="skeuo-button border-0 text-xs flex-1"
          >
            ↩ Reset
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={refresh}
            className="skeuo-button border-0 text-xs flex-1"
          >
            🔄 Refresh
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
