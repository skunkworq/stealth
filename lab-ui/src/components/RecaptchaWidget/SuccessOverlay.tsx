"use client";

import { Badge } from "@/components/ui/badge";

interface SuccessOverlayProps {
  token: string;
  remainingSec: number;
}

export function SuccessOverlay({ token, remainingSec }: SuccessOverlayProps) {
  return (
    <div className="border border-emerald-500/30 rounded-lg p-3 bg-emerald-500/5 space-y-2">
      <div className="flex items-center justify-between">
        <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 text-[10px]">
          VERIFIED
        </Badge>
        <span className="text-[10px] font-mono text-muted-foreground/60">
          expires in {remainingSec}s
        </span>
      </div>
      <code className="block text-[10px] font-mono text-muted-foreground/70 break-all leading-relaxed">
        {token}
      </code>
    </div>
  );
}
