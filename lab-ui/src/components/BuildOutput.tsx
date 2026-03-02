"use client";

import { useState, useCallback } from "react";
import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface EmptyStateProps {
  title: string;
  message: string;
  ledClass: string;
}

function EmptyState({ title, message, ledClass }: EmptyStateProps) {
  return (
    <Card className="skeuo-panel overflow-hidden">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className={ledClass} />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="code-output rounded-lg p-4 h-[200px] flex items-center justify-center">
          <p className="text-muted-foreground text-sm italic">{message}</p>
        </div>
      </CardContent>
    </Card>
  );
}

interface CopyButtonProps {
  onCopy: () => void;
  copied: boolean;
}

function CopyButton({ onCopy, copied }: CopyButtonProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          onClick={onCopy}
          className="skeuo-button border-0 h-7 px-2.5 text-xs"
        >
          {copied ? (
            <span className="text-emerald-glow flex items-center gap-1">
              <CheckIcon />
              Copied
            </span>
          ) : (
            <span className="flex items-center gap-1">
              <CopyIcon />
              Copy
            </span>
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>Copy to clipboard</TooltipContent>
    </Tooltip>
  );
}

function DownloadButton({ onDownload, extension }: { onDownload: () => void; extension: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          onClick={onDownload}
          className="skeuo-button border-0 h-7 px-2.5 text-xs"
        >
          <DownloadIcon />
          <span className="hidden sm:inline ml-1">.{extension}</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent>Download file</TooltipContent>
    </Tooltip>
  );
}

function TabSwitcher() {
  return (
    <TabsList className="skeuo-inset border-0 h-8 p-0.5">
      <TabsTrigger
        value="yaml"
        className="text-xs font-mono h-7 px-3 data-[state=active]:skeuo-raised data-[state=active]:text-emerald-glow data-[state=active]:shadow-none"
      >
        YAML
      </TabsTrigger>
      <TabsTrigger
        value="json"
        className="text-xs font-mono h-7 px-3 data-[state=active]:skeuo-raised data-[state=active]:text-cyan-glow data-[state=active]:shadow-none"
      >
        JSON
      </TabsTrigger>
    </TabsList>
  );
}

function OutputDisplay({ yamlOutput, jsonOutput }: { yamlOutput: string; jsonOutput: string }) {
  return (
    <>
      <TabsContent value="yaml" className="mt-3">
        <CodeBlock content={yamlOutput} language="yaml" />
      </TabsContent>
      <TabsContent value="json" className="mt-3">
        <CodeBlock content={jsonOutput} language="json" />
      </TabsContent>
    </>
  );
}

function BuildOutputHeader() {
  return (
    <CardHeader className="relative pb-3">
      <div className="absolute top-3 right-3 flex gap-2">
        <div className="screw-hole" />
        <div className="screw-hole" />
      </div>
      <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="led-green" />
        Build Output
        <span className="text-[10px] text-muted-foreground/60 normal-case tracking-normal font-normal ml-1">
          real-time
        </span>
      </CardTitle>
    </CardHeader>
  );
}

interface BuildOutputContentProps {
  activeTab: string;
  onTabChange: (value: string) => void;
  copied: boolean;
  yamlOutput: string;
  jsonOutput: string;
  onCopy: () => void;
  onDownload: () => void;
}

function BuildOutputContent({
  activeTab,
  onTabChange,
  copied,
  yamlOutput,
  jsonOutput,
  onCopy,
  onDownload,
}: BuildOutputContentProps) {
  return (
    <CardContent className="space-y-3">
      <Tabs value={activeTab} onValueChange={onTabChange}>
        {/* Tab switcher + action buttons */}
        <div className="flex items-center justify-between gap-2">
          <TabSwitcher />

          <div className="flex gap-1.5">
            <CopyButton onCopy={onCopy} copied={copied} />
            <DownloadButton
              onDownload={onDownload}
              extension={activeTab === "yaml" ? "yaml" : "json"}
            />
          </div>
        </div>

        <OutputDisplay yamlOutput={yamlOutput} jsonOutput={jsonOutput} />
      </Tabs>
    </CardContent>
  );
}

const COPY_FEEDBACK_DURATION = 2000;

async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }
}

interface DownloadFileParams {
  content: string;
  filename: string;
  mimeType: string;
}

function downloadFile({ content, filename, mimeType }: DownloadFileParams): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

interface UseBuildOutputHandlersProps {
  currentOutput: string;
  activeTab: string;
  fingerprintId?: string;
}

function useBuildOutputHandlers({
  currentOutput,
  activeTab,
  fingerprintId,
}: UseBuildOutputHandlersProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    await copyToClipboard(currentOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), COPY_FEEDBACK_DURATION);
  }, [currentOutput]);

  const handleDownload = useCallback(() => {
    const ext = activeTab === "yaml" ? "yaml" : "json";
    const mime = activeTab === "yaml" ? "application/x-yaml" : "application/json";
    const filename = `fingerprint-${fingerprintId ?? "export"}.${ext}`;
    downloadFile({ content: currentOutput, filename, mimeType: mime });
  }, [currentOutput, activeTab, fingerprintId]);

  return { copied, handleCopy, handleDownload };
}

export function BuildOutput() {
  const { fingerprint, jsonOutput, yamlOutput } = useFingerprint();
  const [activeTab, setActiveTab] = useState<string>("yaml");
  const currentOutput = activeTab === "yaml" ? yamlOutput : jsonOutput;

  const { copied, handleCopy, handleDownload } = useBuildOutputHandlers({
    currentOutput,
    activeTab,
    fingerprintId: fingerprint?.id,
  });

  if (!fingerprint) {
    return (
      <EmptyState
        title="Build Output"
        message="Waiting for fingerprint data..."
        ledClass="led-amber"
      />
    );
  }

  return (
    <Card className="skeuo-panel overflow-hidden">
      <BuildOutputHeader />
      <BuildOutputContent
        activeTab={activeTab}
        onTabChange={setActiveTab}
        copied={copied}
        yamlOutput={yamlOutput}
        jsonOutput={jsonOutput}
        onCopy={handleCopy}
        onDownload={handleDownload}
      />
    </Card>
  );
}

interface LineNumberProps {
  index: number;
}

function LineNumber({ index }: LineNumberProps) {
  return (
    <div className="text-[10px] leading-[1.6] text-muted-foreground/30 text-right w-6">
      {index + 1}
    </div>
  );
}

interface LineContentProps {
  line: string;
  language: "yaml" | "json";
}

function LineContent({ line, language }: LineContentProps) {
  return (
    <div>
      <SyntaxLine line={line} language={language} />
    </div>
  );
}

function CodeBlock({ content, language }: { content: string; language: "yaml" | "json" }) {
  const lines = content.split("\n");

  return (
    <ScrollArea className="h-[400px]">
      <div className="code-output rounded-lg overflow-hidden">
        <div className="flex">
          {/* Line numbers gutter */}
          <div className="py-3 pl-3 pr-2 select-none shrink-0 border-r border-white/[0.04]">
            {lines.map((line, i) => (
              // eslint-disable-next-line react/no-array-index-key
              <LineNumber key={`line-num-${line}-${i}`} index={i} />
            ))}
          </div>
          {/* Code content */}
          <pre className="py-3 px-3 overflow-x-auto flex-1 min-w-0">
            <code className="text-xs leading-[1.6]">
              {lines.map((line, i) => (
                // eslint-disable-next-line react/no-array-index-key
                <LineContent key={`line-${line}-${i}`} line={line} language={language} />
              ))}
            </code>
          </pre>
        </div>
      </div>
    </ScrollArea>
  );
}

function SyntaxLine({ line, language }: { line: string; language: "yaml" | "json" }) {
  if (!line.trim()) return <span>&nbsp;</span>;

  if (language === "yaml") {
    // Key: value
    const keyMatch = line.match(/^(\s*)([\w_-]+)(:)(.*)/);
    if (keyMatch) {
      const [, indent, key, colon, value] = keyMatch;
      return (
        <>
          <span>{indent}</span>
          <span className="text-cyan-glow">{key}</span>
          <span className="text-muted-foreground">{colon}</span>
          <YAMLValue value={value} />
        </>
      );
    }
    // List item
    const listMatch = line.match(/^(\s*)(- )(.*)/);
    if (listMatch) {
      const [, indent, dash, value] = listMatch;
      return (
        <>
          <span>{indent}</span>
          <span className="text-amber-glow">{dash}</span>
          <YAMLValue value={value} />
        </>
      );
    }
    return <span className="text-foreground/70">{line}</span>;
  }

  /*
   * JSON
   * Key-value line
   */
  const jsonKvMatch = line.match(/^(\s*)"([^"]+)"(\s*:\s*)(.*)/);
  if (jsonKvMatch) {
    const [, indent, key, colon, value] = jsonKvMatch;
    return (
      <>
        <span>{indent}</span>
        <span className="text-cyan-glow">&quot;{key}&quot;</span>
        <span className="text-muted-foreground">{colon}</span>
        <JSONValue value={value} />
      </>
    );
  }

  // Braces/brackets
  if (/^\s*[\[\]{}],?\s*$/.test(line)) {
    return <span className="text-muted-foreground">{line}</span>;
  }

  return <span className="text-foreground/70">{line}</span>;
}

function YAMLValue({ value }: { value: string }) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (/^".*"$/.test(trimmed)) return <span className="text-emerald-glow"> {value}</span>;
  if (/^\d+$/.test(trimmed)) return <span className="text-violet-glow"> {value}</span>;
  if (/^(true|false|null)$/i.test(trimmed))
    return <span className="text-amber-glow"> {value}</span>;
  if (trimmed === "[]" || trimmed === "{}")
    return <span className="text-muted-foreground"> {value}</span>;
  return <span className="text-emerald-glow/80"> {value}</span>;
}

function JSONValue({ value }: { value: string }) {
  const trimmed = value.replace(/,\s*$/, "").trim();
  const trailing = value.endsWith(",") ? "," : "";
  if (/^".*"$/.test(trimmed))
    return (
      <>
        <span className="text-emerald-glow">{trimmed}</span>
        <span className="text-muted-foreground">{trailing}</span>
      </>
    );
  if (/^-?\d+\.?\d*$/.test(trimmed))
    return (
      <>
        <span className="text-violet-glow">{trimmed}</span>
        <span className="text-muted-foreground">{trailing}</span>
      </>
    );
  if (/^(true|false|null)$/.test(trimmed))
    return (
      <>
        <span className="text-amber-glow">{trimmed}</span>
        <span className="text-muted-foreground">{trailing}</span>
      </>
    );
  return <span className="text-foreground/70">{value}</span>;
}

// Inline SVG icons
function CopyIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}
