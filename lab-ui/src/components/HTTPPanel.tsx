"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export function HTTPPanel() {
  const { fingerprint } = useFingerprint();
  const http = fingerprint?.http;
  const httpResp = fingerprint?.http_response;
  
  if (!http && !httpResp) {
    return (
      <Card className="skeuo-panel overflow-hidden">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <span className="led-red" />
            HTTP
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground italic">No HTTP data available</p>
        </CardContent>
      </Card>
    );
  }

  const reqHeaders = http?.headers?.filter(h => !h.is_pseudo) ?? [];
  const respHeaders = httpResp?.headers ?? [];

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-cyan-glow text-lg">🌐</span>
          HTTP
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Request Section */}
        {http && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className="led-green" />
              <h3 className="text-sm font-bold text-foreground">Request</h3>
            </div>
            
            <div className="grid grid-cols-3 gap-3">
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Method</div>
                <div className="font-mono text-sm font-bold text-emerald-glow">{http.method}</div>
              </div>
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Protocol</div>
                <div className="font-mono text-sm font-bold text-cyan-glow">{http.protocol}</div>
              </div>
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Headers</div>
                <div className="font-mono text-sm font-bold text-violet-glow">{reqHeaders.length}</div>
              </div>
            </div>

            {http.user_agent && (
              <div>
                <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">User-Agent</h4>
                <div className="skeuo-inset rounded-lg p-2">
                  <p className="font-mono text-xs text-foreground/70 break-all leading-relaxed">{http.user_agent}</p>
                </div>
              </div>
            )}

            {http.client_hints && (
              <div className="flex gap-2 flex-wrap">
                {http.client_hints.sec_ch_ua && (
                  <Badge variant="outline" className="text-[10px] font-mono text-emerald-glow/80 border-emerald-glow/20 bg-emerald-glow/5">
                    sec-ch-ua
                  </Badge>
                )}
                {http.client_hints.sec_ch_ua_mobile && (
                  <Badge variant="outline" className="text-[10px] font-mono text-cyan-glow/80 border-cyan-glow/20 bg-cyan-glow/5">
                    mobile: {http.client_hints.sec_ch_ua_mobile}
                  </Badge>
                )}
                {http.client_hints.sec_ch_ua_platform && (
                  <Badge variant="outline" className="text-[10px] font-mono text-violet-glow/80 border-violet-glow/20 bg-violet-glow/5">
                    platform: {http.client_hints.sec_ch_ua_platform}
                  </Badge>
                )}
              </div>
            )}

            {reqHeaders.length > 0 && (
              <div>
                <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">Request Headers</h4>
                <div className="skeuo-inset rounded-lg overflow-hidden max-h-[150px] overflow-y-auto">
                  <Table>
                    <TableBody>
                      {reqHeaders.map((h, i) => (
                        <TableRow key={i} className="border-border/10 hover:bg-white/[0.02]">
                          <TableCell className="font-mono text-xs py-1.5 text-cyan-glow/80 whitespace-nowrap pl-3 w-[120px]">{h.name}</TableCell>
                          <TableCell className="font-mono text-xs py-1.5 text-foreground/60 break-all pr-3">
                            {h.value || "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Separator */}
        {http && httpResp && <div className="h-px bg-border/20 w-full" />}

        {/* Response Section */}
        {httpResp && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className={httpResp.status_code >= 400 ? "led-red" : httpResp.status_code >= 300 ? "led-yellow" : "led-green"} />
              <h3 className="text-sm font-bold text-foreground">Response</h3>
            </div>
            
            <div className="grid grid-cols-3 gap-3">
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Status</div>
                <div className={`font-mono text-sm font-bold ${httpResp.status_code >= 400 ? "text-red-400" : httpResp.status_code >= 300 ? "text-yellow-400" : "text-emerald-400"}`}>{httpResp.status_code}</div>
              </div>
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Protocol</div>
                <div className="font-mono text-sm font-bold text-cyan-glow">{httpResp.protocol}</div>
              </div>
              <div className="skeuo-inset rounded-lg p-2 text-center">
                <div className="text-[10px] text-muted-foreground uppercase">Body Length</div>
                <div className="font-mono text-sm font-bold text-violet-glow">{httpResp.body_length}</div>
              </div>
            </div>

            {respHeaders.length > 0 && (
              <div>
                <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">Response Headers</h4>
                <div className="skeuo-inset rounded-lg overflow-hidden max-h-[250px] overflow-y-auto">
                  <Table>
                    <TableBody>
                      {respHeaders.map((h, i) => (
                        <TableRow key={i} className="border-border/10 hover:bg-white/[0.02]">
                          <TableCell className="font-mono text-xs py-1.5 text-cyan-glow/80 whitespace-nowrap pl-3 w-[120px]">{h.name}</TableCell>
                          <TableCell className="font-mono text-xs py-1.5 text-foreground/60 break-all pr-3">
                            {h.value || "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
