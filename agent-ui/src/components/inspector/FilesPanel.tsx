"use client";

import { getFileUrl } from "@/lib/api";
import { escapeHtml } from "@/lib/utils";

interface FilesPanelProps {
  sessionId: string;
  files: Record<string, string[]>;
}

export function FilesPanel({ sessionId, files }: FilesPanelProps) {
  const agents = Object.keys(files);
  if (agents.length === 0) {
    return <div className="p-3 text-sm text-[#7a8194]">No files yet.</div>;
  }

  return (
    <div className="flex flex-col gap-3">
      {agents.map((agentId) => (
        <FileSection key={agentId} sessionId={sessionId} agentId={agentId} files={files[agentId]} />
      ))}
    </div>
  );
}

function FileSection({
  sessionId,
  agentId,
  files,
}: {
  sessionId: string;
  agentId: string;
  files: string[];
}) {
  return (
    <div>
      <div className="mb-1 rounded bg-[#1e212b] px-2 py-1 text-[12px] font-bold text-[#3bd0ee]">
        {agentId.slice(0, 8)}
      </div>
      <ul className="pl-2">
        {files.map((f) => {
          const url = getFileUrl(sessionId, f);
          const isImage = f.endsWith(".png") || f.endsWith(".jpg") || f.endsWith(".jpeg");
          return (
            <li key={f} className="py-0.5 text-[12px]">
              <a href={url} target="_blank" rel="noreferrer" className="text-[#c9cdd6] hover:text-[#4f8cf7] hover:underline">
                {isImage ? "🖼 " : "📄 "}{escapeHtml(f)}
              </a>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
