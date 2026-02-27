"use client";

import { useState, useCallback } from "react";
import { useFingerprint } from "@/components/FingerprintProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export function BuildOutput() {
  const { fingerprint, jsonOutput, yamlOutput } = useFingerprint();
  const [activeTab, setActiveTab] = useState<string>("yaml");
  const [copied, setCopied] = useState(false);

  const currentOutput = activeTab === "yaml" ? yamlOutput : jsonOutput;

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(currentOutput);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = currentOutput;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [currentOutput]);

  const handleDownload = useCallback(() => {
    const ext = activeTab === "yaml" ? "yaml" : "json";
    const mime = activeTab === "yaml" ? "application/x-yaml" : "application/json";
    const blob = new Blob([currentOutput], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fingerprint-${fingerprint?.id ?? "export"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [currentOutput, activeTab, fingerprint?.id]);

  if (!fingerprint) {
    return (
      <Card className="skeuo-panel overflow-hidden">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <span className="led-amber" />
            Build Output
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="code-output rounded-lg p-4 h-[200px] flex items-center justify-center">
            <p className="text-muted-foreground text-sm italic">Waiting for fingerprint data...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="skeuo-panel overflow-hidden">
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
      <CardContent className="space-y-3">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          {/* Tab switcher + action buttons */}
          <div className="flex items-center justify-between gap-2">
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

            <div className="flex gap-1.5">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleCopy}
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

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleDownload}
                    className="skeuo-button border-0 h-7 px-2.5 text-xs"
                  >
                    <DownloadIcon />
                    <span className="hidden sm:inline ml-1">.{activeTab === "yaml" ? "yaml" : "json"}</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download file</TooltipContent>
              </Tooltip>
            </div>
          </div>

          <TabsContent value="yaml" className="mt-3">
            <CodeBlock content={yamlOutput} language="yaml" />
          </TabsContent>
          <TabsContent value="json" className="mt-3">
            <CodeBlock content={jsonOutput} language="json" />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
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
            {lines.map((_, i) => (
              <div key={i} className="text-[10px] leading-[1.6] text-muted-foreground/30 text-right w-6">
                {i + 1}
              </div>
            ))}
          </div>
          {/* Code content */}
          <pre className="py-3 px-3 overflow-x-auto flex-1 min-w-0">
            <code className="text-xs leading-[1.6]">
              {lines.map((line, i) => (
                <div key={i}>
                  <SyntaxLine line={line} language={language} />
                </div>
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

  // JSON
  // Key-value line
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
  if (/^(true|false|null)$/i.test(trimmed)) return <span className="text-amber-glow"> {value}</span>;
  if (trimmed === "[]" || trimmed === "{}") return <span className="text-muted-foreground"> {value}</span>;
  return <span className="text-emerald-glow/80"> {value}</span>;
}

function JSONValue({ value }: { value: string }) {
  const trimmed = value.replace(/,\s*$/, "").trim();
  const trailing = value.endsWith(",") ? "," : "";
  if (/^".*"$/.test(trimmed)) return <><span className="text-emerald-glow">{trimmed}</span><span className="text-muted-foreground">{trailing}</span></>;
  if (/^-?\d+\.?\d*$/.test(trimmed)) return <><span className="text-violet-glow">{trimmed}</span><span className="text-muted-foreground">{trailing}</span></>;
  if (/^(true|false|null)$/.test(trimmed)) return <><span className="text-amber-glow">{trimmed}</span><span className="text-muted-foreground">{trailing}</span></>;
  return <span className="text-foreground/70">{value}</span>;
}

// Inline SVG icons
function CopyIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}
