"use client";

import { useEffect, useRef, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WebSocketMessage } from "@/hooks/useWebSocket";

export function PacketAnalysisPanel({ packets }: { packets: WebSocketMessage[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Auto-scroll logic
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [packets, autoScroll]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 10;
    setAutoScroll(isAtBottom);
  };

  return (
    <Card className="skeuo-panel border-cyan-glow/20 shadow-[0_4px_20px_rgba(0,0,0,0.5),inset_0_1px_rgba(255,255,255,0.05)] overflow-hidden flex flex-col h-[500px]">
      <CardHeader className="border-b border-border/30 bg-background/50 backdrop-blur-sm pb-4 flex-none">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg skeuo-inset flex items-center justify-center">
              <span className="text-cyan-glow animate-pulse">📡</span>
            </div>
            <div>
              <CardTitle className="text-lg font-bold tracking-tight text-foreground shadow-black drop-shadow-md flex items-center gap-2">
                Live Packet Analysis
                {!autoScroll && (
                  <Badge variant="outline" className="text-[9px] border-amber-500/50 text-amber-500 bg-amber-500/10 uppercase cursor-pointer" onClick={() => setAutoScroll(true)}>
                    Auto-Scroll Paused
                  </Badge>
                )}
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-1">
                Real-time Wireshark-style capture events via Rust libpcap
              </p>
            </div>
          </div>
          <Badge variant="outline" className="font-mono text-[10px] tracking-wider border-cyan-glow/30 text-cyan-glow bg-cyan-glow/5">
            {packets.length} PACKETS
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-0 flex-1 overflow-hidden">
        <div 
          ref={containerRef}
          onScroll={handleScroll}
          className="h-full overflow-y-auto bg-[#0a0a0a] font-mono text-[11px] leading-tight"
        >
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 bg-[#161616] z-10 border-b border-white/10 shadow-md">
              <tr className="text-muted-foreground">
                <th className="py-2 px-3 font-semibold w-12 text-center border-r border-white/5">No.</th>
                <th className="py-2 px-3 font-semibold w-24 border-r border-white/5">Time</th>
                <th className="py-2 px-3 font-semibold w-32 border-r border-white/5">Source</th>
                <th className="py-2 px-3 font-semibold w-32 border-r border-white/5">Destination</th>
                <th className="py-2 px-3 font-semibold w-20 text-center border-r border-white/5">Protocol</th>
                <th className="py-2 px-3 font-semibold w-16 text-right border-r border-white/5">Length</th>
                <th className="py-2 px-3 font-semibold">Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt, i) => {
                const isTCP = pkt.protocol === "TCP";
                const isUDP = pkt.protocol === "UDP";
                const isTLS = pkt.info?.includes("443") || pkt.info?.includes("8443");
                
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

                // Format timestamp
                const date = new Date(Number(pkt.timestamp));
                const timeStr = isNaN(date.getTime()) ? "0.000" : `${date.getSeconds()}.${date.getMilliseconds().toString().padStart(3, '0')}`;

                return (
                  <tr key={i} className={`border-b border-white/5 transition-colors ${bgColor} ${rowColor}`}>
                    <td className="py-1 px-3 whitespace-nowrap opacity-60 text-center border-r border-white/5">{i + 1}</td>
                    <td className="py-1 px-3 whitespace-nowrap opacity-60 border-r border-white/5">{timeStr}</td>
                    <td className="py-1 px-3 whitespace-nowrap border-r border-white/5 truncate max-w-[150px]" title={pkt.source_ip}>{pkt.source_ip}</td>
                    <td className="py-1 px-3 whitespace-nowrap border-r border-white/5 truncate max-w-[150px]" title={pkt.dest_ip}>{pkt.dest_ip}</td>
                    <td className="py-1 px-3 whitespace-nowrap font-bold text-center border-r border-white/5">{pkt.protocol}</td>
                    <td className="py-1 px-3 whitespace-nowrap text-right border-r border-white/5">{pkt.length}</td>
                    <td className="py-1 px-3 truncate max-w-[200px] sm:max-w-[300px] lg:max-w-[400px]" title={pkt.info}>{pkt.info}</td>
                  </tr>
                );
              })}
              {packets.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-20 text-center text-muted-foreground/50">
                    <div className="flex flex-col items-center justify-center gap-2">
                       <span className="text-2xl opacity-50">📡</span>
                       <p>Listening for traffic on L3/L4...</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
