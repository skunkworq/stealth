"use client";

import { useEffect, useRef, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WebSocketMessage } from "@/hooks/useWebSocket";

// Constants for scroll detection and millisecond padding
const SCROLL_BOTTOM_THRESHOLD = 10;
const MILLISECONDS_PAD_LENGTH = 3;

interface PacketRowProps {
  packet: WebSocketMessage;
  index: number;
}

function PacketRow({ packet, index }: PacketRowProps) {
  const isTCP = packet.protocol === "TCP";
  const isUDP = packet.protocol === "UDP";
  const isTLS = packet.info?.includes("443") || packet.info?.includes("8443");

  let rowColor = "text-gray-300";
  let bgColor = "hover:bg-white/5";
  if (isTLS) {
    rowColor = "text-purple-300";
    bgColor = "bg-purple-900/10 hover:bg-purple-900/20";
  } else if (isTCP) {
    rowColor = "text-emerald-300";
    bgColor = "bg-emerald-900/10 hover:bg-emerald-900/20";
  } else if (isUDP) {
    rowColor = "text-cyan-300";
    bgColor = "bg-cyan-900/10 hover:bg-cyan-900/20";
  }

  const date = new Date(Number(packet.timestamp));
  const timeStr = isNaN(date.getTime())
    ? "0.000"
    : `${date.getSeconds()}.${date.getMilliseconds().toString().padStart(MILLISECONDS_PAD_LENGTH, "0")}`;
  const cell = "py-1 px-3 whitespace-nowrap border-r border-white/5";
  const trunc = "truncate max-w-[150px]";

  return (
    <tr
      key={`pkt-${packet.timestamp}-${index}`}
      className={`border-b border-white/5 transition-colors ${bgColor} ${rowColor}`}
    >
      <td className={`${cell} opacity-60 text-center`}>{index + 1}</td>
      <td className={`${cell} opacity-60`}>{timeStr}</td>
      <td className={`${cell} ${trunc}`} title={packet.source_ip}>
        {packet.source_ip}
      </td>
      <td className={`${cell} ${trunc}`} title={packet.dest_ip}>
        {packet.dest_ip}
      </td>
      <td className={`${cell} font-bold text-center`}>{packet.protocol}</td>
      <td className={`${cell} text-right`}>{packet.length}</td>
      <td
        className="py-1 px-3 truncate max-w-[200px] sm:max-w-[300px] lg:max-w-[400px]"
        title={packet.info}
      >
        {packet.info}
      </td>
    </tr>
  );
}

interface PacketTableProps {
  packets: WebSocketMessage[];
}

function PacketTable({ packets }: PacketTableProps) {
  if (packets.length === 0) {
    return (
      <tbody>
        <PacketEmptyState />
      </tbody>
    );
  }

  return (
    <tbody>
      {packets.map((packet, idx) => (
        <PacketRow
          key={`${packet.timestamp}-${packet.source_ip}-${packet.dest_ip}-${packet.protocol}-${packet.length}`}
          packet={packet}
          index={idx}
        />
      ))}
    </tbody>
  );
}

function PacketEmptyState() {
  return (
    <tr>
      <td colSpan={7} className="py-20 text-center text-muted-foreground/50">
        <div className="flex flex-col items-center justify-center gap-2">
          <span className="text-2xl opacity-50" aria-hidden="true">
            📡
          </span>
          <p>Listening for traffic on L3/L4…</p>
        </div>
      </td>
    </tr>
  );
}

interface PacketFiltersProps {
  packetCount: number;
}

function PacketFilters({ packetCount }: PacketFiltersProps) {
  return (
    <Badge
      variant="outline"
      className="font-mono text-[10px] tracking-wider border-cyan-glow/30 text-cyan-glow bg-cyan-glow/5"
    >
      {packetCount} PACKETS
    </Badge>
  );
}

interface AutoScrollBadgeProps {
  isPaused: boolean;
  onResume: () => void;
}

function AutoScrollBadge({ isPaused, onResume }: AutoScrollBadgeProps) {
  if (!isPaused) return null;

  return (
    <Badge
      variant="outline"
      className="text-[9px] border-amber-500/50 text-amber-500 bg-amber-500/10 uppercase cursor-pointer"
      onClick={onResume}
      onKeyDown={e => {
        if (e.key === "Enter" || e.key === " ") onResume();
      }}
      tabIndex={0}
      role="button"
    >
      Auto-Scroll Paused
    </Badge>
  );
}

interface UsePacketFiltersResult {
  autoScroll: boolean;
  setAutoScroll: (value: boolean) => void;
  handleScroll: () => void;
}

function usePacketFilters(
  containerRef: React.RefObject<HTMLDivElement | null>
): UsePacketFiltersResult {
  const [autoScroll, setAutoScroll] = useState(true);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < SCROLL_BOTTOM_THRESHOLD;
    setAutoScroll(isAtBottom);
  };

  return {
    autoScroll,
    setAutoScroll,
    handleScroll,
  };
}

function PacketTableHeader() {
  return (
    <thead className="sticky top-0 bg-[#161616] z-10 border-b border-white/10 shadow-md">
      <tr className="text-muted-foreground">
        <th className="py-2 px-3 font-semibold w-12 text-center border-r border-white/5">No.</th>
        <th className="py-2 px-3 font-semibold w-24 border-r border-white/5">Time</th>
        <th className="py-2 px-3 font-semibold w-32 border-r border-white/5">Source</th>
        <th className="py-2 px-3 font-semibold w-32 border-r border-white/5">Destination</th>
        <th className="py-2 px-3 font-semibold w-20 text-center border-r border-white/5">
          Protocol
        </th>
        <th className="py-2 px-3 font-semibold w-16 text-right border-r border-white/5">Length</th>
        <th className="py-2 px-3 font-semibold">Info</th>
      </tr>
    </thead>
  );
}

export function PacketAnalysisPanel({ packets }: { packets: WebSocketMessage[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { autoScroll, setAutoScroll, handleScroll } = usePacketFilters(containerRef);

  // Auto-scroll logic
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [packets, autoScroll]);

  return (
    <Card className="skeuo-panel border-cyan-glow/20 shadow-[0_4px_20px_rgba(0,0,0,0.5),inset_0_1px_rgba(255,255,255,0.05)] overflow-hidden flex flex-col h-[500px]">
      <CardHeader className="border-b border-border/30 bg-background/50 backdrop-blur-sm pb-4 flex-none">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg skeuo-inset flex items-center justify-center">
              <span className="text-cyan-glow animate-pulse" aria-hidden="true">
                📡
              </span>
            </div>
            <div>
              <CardTitle className="text-lg font-bold tracking-tight text-foreground shadow-black drop-shadow-md flex items-center gap-2">
                Live Packet Analysis
                <AutoScrollBadge isPaused={!autoScroll} onResume={() => setAutoScroll(true)} />
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-1">
                Real-time Wireshark-style capture events via Rust libpcap
              </p>
            </div>
          </div>
          <PacketFilters packetCount={packets.length} />
        </div>
      </CardHeader>

      <CardContent className="p-0 flex-1 overflow-hidden">
        <div
          ref={containerRef}
          onScroll={handleScroll}
          className="h-full overflow-y-auto bg-[#0a0a0a] font-mono text-[11px] leading-tight"
        >
          <table className="w-full text-left border-collapse">
            <PacketTableHeader />
            <PacketTable packets={packets} />
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
