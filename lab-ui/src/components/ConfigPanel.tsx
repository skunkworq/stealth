"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";

const MODIFICATION_PREVIEW_LENGTH = 10;

interface PlatformSelectProps {
  platforms: Record<string, { name: string }>;
  onValueChange: (value: string) => void;
}

function PlatformSelect({ platforms, onValueChange }: PlatformSelectProps) {
  return (
    <div className="space-y-1.5">
      <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Platform
      </label>
      <Select onValueChange={onValueChange}>
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
  );
}

interface BrowserSelectProps {
  browsers: Record<string, { name: string }>;
  onValueChange: (value: string) => void;
}

function BrowserSelect({ browsers, onValueChange }: BrowserSelectProps) {
  return (
    <div className="space-y-1.5">
      <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Browser
      </label>
      <Select onValueChange={onValueChange}>
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
  );
}

interface ModificationsListProps {
  modifications: string[];
}

function ModificationsList({ modifications }: ModificationsListProps) {
  if (modifications.length === 0) return null;

  return (
    <div className="skeuo-inset rounded-lg p-2.5">
      <div className="flex items-center gap-2">
        <span className="led-amber" />
        <Badge
          variant="outline"
          className="text-amber-glow border-amber-glow/30 bg-amber-glow/5 text-[10px]"
        >
          {modifications.length} change{modifications.length !== 1 ? "s" : ""}
        </Badge>
      </div>
      <div className="mt-2 space-y-0.5">
        {modifications.map(mod => (
          <p
            key={mod.slice(0, MODIFICATION_PREVIEW_LENGTH)}
            className="text-xs text-muted-foreground"
          >
            • {mod}
          </p>
        ))}
      </div>
    </div>
  );
}

interface ActionButtonsProps {
  onReset: () => void;
  onRefresh: () => void;
}

function ActionButtons({ onReset, onRefresh }: ActionButtonsProps) {
  return (
    <div className="flex gap-2">
      <Button
        variant="ghost"
        size="sm"
        onClick={onReset}
        className="skeuo-button border-0 text-xs flex-1"
      >
        ↩ Reset
      </Button>
      <Button
        variant="ghost"
        size="sm"
        onClick={onRefresh}
        className="skeuo-button border-0 text-xs flex-1"
      >
        🔄 Refresh
      </Button>
    </div>
  );
}

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
        <PlatformSelect platforms={platforms} onValueChange={applyPlatformPreset} />
        <BrowserSelect browsers={browsers} onValueChange={applyBrowserPreset} />
        <ModificationsList modifications={modifications} />
        <ActionButtons onReset={resetToOriginal} onRefresh={refresh} />
      </CardContent>
    </Card>
  );
}
