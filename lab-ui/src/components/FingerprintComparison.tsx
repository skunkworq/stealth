"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";

// Constants
const REFRESH_INTERVAL_MS = 5000;
const PERCENTAGE_MULTIPLIER = 100;
const ID_SLICE_LENGTH = 8;
const HIGH_SIMILARITY_THRESHOLD = 80;
const MEDIUM_SIMILARITY_THRESHOLD = 50;

interface CaptureListEntry {
  id: string;
  timestamp: string;
  source: string;
}

interface ComparisonField {
  name: string;
  value_a: string;
  value_b: string;
  match: boolean;
  severity: "critical" | "warning" | "info";
}

interface ComparisonResult {
  similarity: number;
  fields: ComparisonField[];
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function useFetchCaptures() {
  const [captures, setCaptures] = useState<CaptureListEntry[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const fetchCaptures = async () => {
      try {
        const res = await fetch("/api/captures");
        if (res.ok) {
          const data = await res.json();
          setCaptures(Array.isArray(data) ? data : []);
        }
      } catch {
        // silently fail - captures may not be available yet
      }
    };

    fetchCaptures();
    intervalRef.current = setInterval(fetchCaptures, REFRESH_INTERVAL_MS);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  return captures;
}

function useCompareAction() {
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const executeCompare = useCallback(async (captureA: string, captureB: string) => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/fingerprints/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_a: captureA, id_b: captureB }),
      });

      if (!res.ok) {
        throw new Error(`Comparison failed: HTTP ${res.status}`);
      }

      const data: ComparisonResult = await res.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Comparison failed");
    } finally {
      setLoading(false);
    }
  }, []);

  return { result, loading, error, executeCompare };
}

function useFingerprintComparison() {
  const captures = useFetchCaptures();
  const [captureA, setCaptureA] = useState<string>("");
  const [captureB, setCaptureB] = useState<string>("");
  const { result, loading, error, executeCompare } = useCompareAction();

  const handleCompare = useCallback(async () => {
    if (!captureA || !captureB) return;
    await executeCompare(captureA, captureB);
  }, [captureA, captureB, executeCompare]);

  return {
    captures,
    captureA,
    captureB,
    result,
    loading,
    error,
    setCaptureA,
    setCaptureB,
    handleCompare,
  };
}

interface CaptureSelectorProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  captures: CaptureListEntry[];
}

function CaptureSelector({ label, value, onChange, captures }: CaptureSelectorProps) {
  return (
    <div className="space-y-1.5">
      <label className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest">
        {label}
      </label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="skeuo-inset bg-black/20 border-0 h-9 text-xs font-mono w-full">
          <SelectValue placeholder="Select capture..." />
        </SelectTrigger>
        <SelectContent>
          {captures.map(c => (
            <SelectItem key={c.id} value={c.id} className="text-xs font-mono">
              {c.id.slice(0, ID_SLICE_LENGTH)} - {formatTimestamp(c.timestamp)} ({c.source})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

interface ComparisonHeaderProps {
  captureA: string;
  captureB: string;
  loading: boolean;
  captures: CaptureListEntry[];
  onCaptureAChange: (value: string) => void;
  onCaptureBChange: (value: string) => void;
  onCompare: () => void;
}

function ComparisonHeader({
  captureA,
  captureB,
  loading,
  captures,
  onCaptureAChange,
  onCaptureBChange,
  onCompare,
}: ComparisonHeaderProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-3 items-end">
      <CaptureSelector
        label="Capture A"
        value={captureA}
        onChange={onCaptureAChange}
        captures={captures}
      />

      <div className="flex items-center justify-center">
        <Button
          variant="outline"
          size="sm"
          onClick={onCompare}
          disabled={!captureA || !captureB || loading}
          className="text-[10px] uppercase font-bold tracking-wider border-cyan-glow/30 text-cyan-glow hover:bg-cyan-glow/10 disabled:opacity-30"
        >
          {loading ? "Comparing..." : "Compare"}
        </Button>
      </div>

      <CaptureSelector
        label="Capture B"
        value={captureB}
        onChange={onCaptureBChange}
        captures={captures}
      />
    </div>
  );
}

function SummaryBox({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-3 text-center">
      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-1">
        {label}
      </div>
      <div className={`text-lg font-bold font-mono ${color} glow-text`}>{value}</div>
    </div>
  );
}

function getSeverityBadge(severity: string) {
  switch (severity) {
    case "critical":
      return (
        <Badge
          variant="outline"
          className="text-[8px] px-1.5 py-0 h-4 font-bold uppercase border-red-glow/40 text-red-glow bg-red-glow/10"
        >
          Critical
        </Badge>
      );
    case "warning":
      return (
        <Badge
          variant="outline"
          className="text-[8px] px-1.5 py-0 h-4 font-bold uppercase border-amber-glow/40 text-amber-glow bg-amber-glow/10"
        >
          Warning
        </Badge>
      );
    default:
      return (
        <Badge
          variant="outline"
          className="text-[8px] px-1.5 py-0 h-4 font-bold uppercase border-cyan-glow/40 text-cyan-glow bg-cyan-glow/10"
        >
          Info
        </Badge>
      );
  }
}

interface DiffRowProps {
  field: ComparisonField;
}

function DiffRow({ field }: DiffRowProps) {
  return (
    <TableRow
      className={`border-white/5 transition-colors ${
        field.match
          ? "bg-emerald-glow/[0.03] hover:bg-emerald-glow/[0.06]"
          : "bg-red-glow/[0.03] hover:bg-red-glow/[0.06]"
      }`}
    >
      <TableCell className="py-2 text-[10px] font-bold text-foreground/80 uppercase tracking-wider">
        {field.name.replace(/_/g, " ")}
      </TableCell>
      <TableCell className="py-2 text-[10px] font-mono text-foreground/70 max-w-[200px] truncate">
        {field.value_a || "N/A"}
      </TableCell>
      <TableCell className="py-2 text-[10px] font-mono text-foreground/70 max-w-[200px] truncate">
        {field.value_b || "N/A"}
      </TableCell>
      <TableCell className="py-2 text-center">
        <span
          className={`inline-block w-2 h-2 rounded-full ${
            field.match
              ? "bg-emerald-glow shadow-[0_0_6px_rgba(16,185,129,0.6)]"
              : "bg-red-glow shadow-[0_0_6px_rgba(239,68,68,0.6)]"
          }`}
        />
      </TableCell>
      <TableCell className="py-2 text-center">{getSeverityBadge(field.severity)}</TableCell>
    </TableRow>
  );
}

interface DiffSectionProps {
  fields: ComparisonField[];
}

function DiffSection({ fields }: DiffSectionProps) {
  if (fields.length === 0) {
    return (
      <div className="p-8 text-center">
        <p className="text-xs text-muted-foreground italic font-mono">
          No comparison fields returned
        </p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow className="border-white/10 bg-white/5">
          <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
            Field
          </TableHead>
          <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
            Capture A
          </TableHead>
          <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8">
            Capture B
          </TableHead>
          <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 text-center">
            Match
          </TableHead>
          <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 text-center">
            Severity
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {fields.map(field => (
          <DiffRow key={`field-${field.name}`} field={field} />
        ))}
      </TableBody>
    </Table>
  );
}

function useSimilarityColors(similarityPct: string) {
  const num = Number(similarityPct);
  const isHigh = num > HIGH_SIMILARITY_THRESHOLD;
  const isMedium = num > MEDIUM_SIMILARITY_THRESHOLD;

  const color = isHigh ? "text-emerald-glow" : isMedium ? "text-amber-glow" : "text-red-glow";

  const barColor = isHigh
    ? "bg-emerald-glow shadow-[0_0_8px_rgba(16,185,129,0.5)]"
    : isMedium
      ? "bg-amber-glow shadow-[0_0_8px_rgba(245,158,11,0.5)]"
      : "bg-red-glow shadow-[0_0_8px_rgba(239,68,68,0.5)]";

  return { color, barColor };
}

interface SimilarityBarProps {
  similarityPct: string;
}

function SimilarityBar({ similarityPct }: SimilarityBarProps) {
  const { color, barColor } = useSimilarityColors(similarityPct);

  return (
    <div className="skeuo-inset rounded-lg p-3">
      <div className="flex items-center gap-3">
        <span className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest shrink-0">
          Match Score
        </span>
        <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${barColor}`}
            style={{ width: `${similarityPct}%` }}
          />
        </div>
        <span className={`text-xs font-mono font-bold ${color}`}>{similarityPct}%</span>
      </div>
    </div>
  );
}

interface SummaryStatsProps {
  similarityPct: string;
  totalFields: number;
  matchingCount: number;
  diffCount: number;
}

function SummaryStats({ similarityPct, totalFields, matchingCount, diffCount }: SummaryStatsProps) {
  const { color } = useSimilarityColors(similarityPct);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <SummaryBox label="Similarity" value={`${similarityPct}%`} color={color} />
      <SummaryBox label="Total Fields" value={String(totalFields)} color="text-cyan-glow" />
      <SummaryBox label="Matching" value={String(matchingCount)} color="text-emerald-glow" />
      <SummaryBox label="Differing" value={String(diffCount)} color="text-red-glow" />
    </div>
  );
}

interface ComparisonResultsProps {
  result: ComparisonResult;
}

function ComparisonResults({ result }: ComparisonResultsProps) {
  const matchingFields = result.fields.filter(f => f.match);
  const diffFields = result.fields.filter(f => !f.match);
  const totalFields = result.fields.length;
  const similarityPct = ((result.similarity ?? 0) * PERCENTAGE_MULTIPLIER).toFixed(1);

  return (
    <>
      <Separator className="bg-border/20" />

      <SummaryStats
        similarityPct={similarityPct}
        totalFields={totalFields}
        matchingCount={matchingFields.length}
        diffCount={diffFields.length}
      />

      <SimilarityBar similarityPct={similarityPct} />

      <Separator className="bg-border/20" />

      <div className="rounded-lg overflow-hidden border border-white/5">
        <DiffSection fields={result.fields} />
      </div>
    </>
  );
}

function ErrorDisplay({ error }: { error: string }) {
  return (
    <div className="skeuo-inset rounded-lg p-3 text-center">
      <p className="text-xs text-red-glow font-mono">{error}</p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="skeuo-inset rounded-lg p-8 text-center">
      <p className="text-xs text-muted-foreground/60 italic font-mono">
        Select two captures and click Compare to analyze differences
      </p>
    </div>
  );
}

export function FingerprintComparison() {
  const {
    captures,
    captureA,
    captureB,
    result,
    loading,
    error,
    setCaptureA,
    setCaptureB,
    handleCompare,
  } = useFingerprintComparison();

  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="relative pb-3">
        <div className="absolute top-3 right-3 flex gap-2">
          <div className="screw-hole" />
          <div className="screw-hole" />
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-lg">🔍</span>
          Fingerprint Comparison
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <ComparisonHeader
          captureA={captureA}
          captureB={captureB}
          loading={loading}
          captures={captures}
          onCaptureAChange={setCaptureA}
          onCaptureBChange={setCaptureB}
          onCompare={handleCompare}
        />

        {error && <ErrorDisplay error={error} />}

        {result && <ComparisonResults result={result} />}

        {!result && !error && !loading && <EmptyState />}
      </CardContent>
    </Card>
  );
}
