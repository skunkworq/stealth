"use client";

import { useFingerprint } from "@/components/FingerprintProvider";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Panel, PanelHeader, PanelContent, PanelEmpty } from "@/components/Panel";
// Types from FingerprintProvider
interface HeaderInfo {
  name: string;
  value: string;
  position: number;
  is_pseudo?: boolean;
}

interface ClientHints {
  sec_ch_ua?: string;
  sec_ch_ua_mobile?: string;
  sec_ch_ua_platform?: string;
}

interface HTTPInfo {
  method: string;
  path: string;
  protocol: string;
  headers: HeaderInfo[];
  user_agent: string;
  accept: string;
  accept_language: string;
  accept_encoding: string;
  client_hints?: ClientHints;
  cookie_count: number;
}

interface HTTPResponseInfo {
  status_code: number;
  status: string;
  protocol: string;
  headers: HeaderInfo[];
  body_length: number;
}

const STATUS_ERROR_THRESHOLD = 400;
const STATUS_REDIRECT_THRESHOLD = 300;

interface Header {
  name: string;
  value?: string;
  is_pseudo?: boolean;
}

interface RequestMetricsProps {
  http: HTTPInfo;
  reqHeaders: Header[];
}

function RequestMetrics({ http, reqHeaders }: RequestMetricsProps) {
  return (
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
  );
}

interface ResponseMetricsProps {
  httpResp: HTTPResponseInfo;
}

function ResponseMetrics({ httpResp }: ResponseMetricsProps) {
  return (
    <div className="grid grid-cols-3 gap-3">
      <div className="skeuo-inset rounded-lg p-2 text-center">
        <div className="text-[10px] text-muted-foreground uppercase">Status</div>
        <div
          className={`font-mono text-sm font-bold ${httpResp.status_code >= STATUS_ERROR_THRESHOLD ? "text-red-400" : httpResp.status_code >= STATUS_REDIRECT_THRESHOLD ? "text-yellow-400" : "text-emerald-400"}`}
        >
          {httpResp.status_code}
        </div>
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
  );
}

interface StatusBadgeProps {
  statusCode: number;
}

function StatusBadge({ statusCode }: StatusBadgeProps) {
  return (
    <span
      className={
        statusCode >= STATUS_ERROR_THRESHOLD
          ? "led-red"
          : statusCode >= STATUS_REDIRECT_THRESHOLD
            ? "led-yellow"
            : "led-green"
      }
    />
  );
}

interface HeaderRowProps {
  header: Header;
  prefix: string;
}

function HeaderRow({ header, prefix }: HeaderRowProps) {
  return (
    <TableRow
      key={`${prefix}-${header.name}-${header.value ?? "empty"}`}
      className="border-border/10 hover:bg-white/[0.02]"
    >
      <TableCell className="font-mono text-xs py-1.5 text-cyan-glow/80 whitespace-nowrap pl-3 w-[120px]">
        {header.name}
      </TableCell>
      <TableCell className="font-mono text-xs py-1.5 text-foreground/60 break-all pr-3">
        {header.value || "—"}
      </TableCell>
    </TableRow>
  );
}

interface HeaderTableProps {
  headers: Header[];
  prefix: string;
  maxHeight: string;
}

function HeaderTable({ headers, prefix, maxHeight }: HeaderTableProps) {
  return (
    <div className="skeuo-inset rounded-lg overflow-hidden overflow-y-auto" style={{ maxHeight }}>
      <Table>
        <TableBody>
          {headers.map(h => (
            <HeaderRow
              key={`${prefix}-${h.name}-${h.value ?? "empty"}`}
              header={h}
              prefix={prefix}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

interface ClientHintsProps {
  clientHints: NonNullable<HTTPInfo["client_hints"]>;
}

function ClientHints({ clientHints }: ClientHintsProps) {
  return (
    <div className="flex gap-2 flex-wrap">
      {clientHints.sec_ch_ua && (
        <Badge
          variant="outline"
          className="text-[10px] font-mono text-emerald-glow/80 border-emerald-glow/20 bg-emerald-glow/5"
        >
          sec-ch-ua
        </Badge>
      )}
      {clientHints.sec_ch_ua_mobile && (
        <Badge
          variant="outline"
          className="text-[10px] font-mono text-cyan-glow/80 border-cyan-glow/20 bg-cyan-glow/5"
        >
          mobile: {clientHints.sec_ch_ua_mobile}
        </Badge>
      )}
      {clientHints.sec_ch_ua_platform && (
        <Badge
          variant="outline"
          className="text-[10px] font-mono text-violet-glow/80 border-violet-glow/20 bg-violet-glow/5"
        >
          platform: {clientHints.sec_ch_ua_platform}
        </Badge>
      )}
    </div>
  );
}

interface RequestSectionProps {
  http: HTTPInfo;
  reqHeaders: Header[];
}

function RequestSection({ http, reqHeaders }: RequestSectionProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="led-green" />
        <h3 className="text-sm font-bold text-foreground">Request</h3>
      </div>

      <RequestMetrics http={http} reqHeaders={reqHeaders} />

      {http.user_agent && (
        <div>
          <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">
            User-Agent
          </h4>
          <div className="skeuo-inset rounded-lg p-2">
            <p className="font-mono text-xs text-foreground/70 break-all leading-relaxed">
              {http.user_agent}
            </p>
          </div>
        </div>
      )}

      {http.client_hints && <ClientHints clientHints={http.client_hints} />}

      {reqHeaders.length > 0 && (
        <div>
          <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">
            Request Headers
          </h4>
          <HeaderTable headers={reqHeaders} prefix="req" maxHeight="150px" />
        </div>
      )}
    </div>
  );
}

interface ResponseSectionProps {
  httpResp: HTTPResponseInfo;
  respHeaders: Header[];
}

function ResponseSection({ httpResp, respHeaders }: ResponseSectionProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <StatusBadge statusCode={httpResp.status_code} />
        <h3 className="text-sm font-bold text-foreground">Response</h3>
      </div>

      <ResponseMetrics httpResp={httpResp} />

      {respHeaders.length > 0 && (
        <div>
          <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1.5">
            Response Headers
          </h4>
          <HeaderTable headers={respHeaders} prefix="resp" maxHeight="250px" />
        </div>
      )}
    </div>
  );
}

function HTTPPanelEmptyState() {
  return (
    <Panel>
      <PanelEmpty message="HTTP — No HTTP data available" />
    </Panel>
  );
}

export function HTTPPanel() {
  const { fingerprint } = useFingerprint();
  const http = fingerprint?.http;
  const httpResp = fingerprint?.http_response;

  if (!http && !httpResp) {
    return <HTTPPanelEmptyState />;
  }

  const reqHeaders = http?.headers?.filter(h => !h.is_pseudo) ?? [];
  const respHeaders = httpResp?.headers ?? [];

  return (
    <Panel>
      <PanelHeader title="HTTP" icon={<span className="text-cyan-glow text-lg">🌐</span>} />
      <PanelContent className="space-y-6">
        {http && <RequestSection http={http} reqHeaders={reqHeaders} />}

        {http && httpResp && <div className="h-px bg-border/20 w-full" />}

        {httpResp && <ResponseSection httpResp={httpResp} respHeaders={respHeaders} />}
      </PanelContent>
    </Panel>
  );
}
