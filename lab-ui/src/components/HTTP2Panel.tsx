"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Panel, PanelHeader, PanelContent, PanelEmpty } from "@/components/Panel";
interface HTTP2Setting {
  id: number;
  name: string;
  value: number;
  position: number;
}

type HTTP2Settings = HTTP2Setting;

const MIN_PERCENTAGE_WIDTH = 5;
const PERCENTAGE_MULTIPLIER = 100;

interface HTTP2SettingRowProps {
  setting: HTTP2Settings;
  maxVal: number;
}

function HTTP2SettingRow({ setting, maxVal }: HTTP2SettingRowProps) {
  const width = Math.max(
    MIN_PERCENTAGE_WIDTH,
    (Math.log(setting.value + 1) / Math.log(maxVal + 1)) * PERCENTAGE_MULTIPLIER
  );

  return (
    <TableRow className="border-border/10 hover:bg-white/[0.02]">
      <TableCell className="font-mono text-xs py-2 text-foreground/80">{setting.name}</TableCell>
      <TableCell className="font-mono text-xs py-2 text-right text-emerald-glow">
        {setting.value.toLocaleString()}
      </TableCell>
      <TableCell className="py-2 w-[100px]">
        <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden border border-black/30">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${width}%`,
              background: `linear-gradient(90deg, #34d399, #22d3ee)`,
              boxShadow: `0 0 6px rgba(52, 211, 153, 0.4)`,
            }}
          />
        </div>
      </TableCell>
    </TableRow>
  );
}

interface HTTP2MetricsProps {
  settings: HTTP2Settings[];
}

// Helper to convert fingerprint settings to our format
function normalizeSettings(settings: { name: string; value: number }[]): HTTP2Settings[] {
  return settings.map((s, i) => ({
    id: i + 1,
    name: s.name,
    value: s.value,
    position: i + 1,
  }));
}

function HTTP2Metrics({ settings }: HTTP2MetricsProps) {
  const maxVal = Math.max(...settings.map(s => s.value));

  return (
    <div>
      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
        SETTINGS
      </h4>
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
            {settings.map(s => (
              <HTTP2SettingRow key={`setting-${s.name}-${s.value}`} setting={s} maxVal={maxVal} />
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

interface HTTP2StreamRowProps {
  header: string;
  isLast: boolean;
}

function HTTP2StreamRow({ header, isLast }: HTTP2StreamRowProps) {
  return (
    <div className="flex items-center gap-1">
      <span className="skeuo-raised rounded px-2 py-1 font-mono text-xs text-cyan-glow">
        {header}
      </span>
      {!isLast && <span className="text-muted-foreground text-xs">→</span>}
    </div>
  );
}

interface HTTP2StreamsListProps {
  pseudoHeaderOrder: string[];
}

function HTTP2StreamsList({ pseudoHeaderOrder }: HTTP2StreamsListProps) {
  return (
    <div>
      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
        Pseudo-Header Order
      </h4>
      <div className="skeuo-inset rounded-lg p-3">
        <div className="flex items-center gap-1 flex-wrap">
          {pseudoHeaderOrder.map((h, i) => (
            <HTTP2StreamRow
              key={`pseudo-${h}`}
              header={h}
              isLast={i === pseudoHeaderOrder.length - 1}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function HTTP2EmptyState() {
  return (
    <Panel>
      <PanelEmpty message="HTTP/2 Fingerprint — No HTTP/2 data available" />
    </Panel>
  );
}

export function HTTP2Panel() {
  const { fingerprint } = useFingerprint();
  const http2 = fingerprint?.http2;

  if (!http2) {
    return <HTTP2EmptyState />;
  }

  return (
    <Panel>
      <PanelHeader
        title="HTTP/2 Fingerprint"
        icon={<span className="text-amber-glow text-lg">📡</span>}
      />
      <PanelContent>
        {http2.settings && http2.settings.length > 0 && (
          <HTTP2Metrics settings={normalizeSettings(http2.settings)} />
        )}
        {http2.pseudo_header_order && http2.pseudo_header_order.length > 0 && (
          <HTTP2StreamsList pseudoHeaderOrder={http2.pseudo_header_order} />
        )}
      </PanelContent>
    </Panel>
  );
}
