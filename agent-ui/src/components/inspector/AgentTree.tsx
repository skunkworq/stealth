"use client";

import { AgentBadge } from "@/components/common/AgentBadge";
import { escapeHtml } from "@/lib/utils";
import type { AgentInfo } from "@/lib/types";

function AgentNode({ node, isRoot = false }: { node: AgentInfo; isRoot?: boolean }) {
  return (
    <div className={`${isRoot ? "" : "ml-4 border-l-2 border-[#2a2e3b] pl-2.5"} mb-2`}>
      <div className="flex items-center gap-2 rounded-md bg-[#1e212b] px-2.5 py-1.5">
        <AgentBadge type={node.type} />
        <span className="text-[11px] text-[#7a8194]">{node.id.slice(0, 8)}</span>
        <span
          className={`ml-auto text-[11px] ${
            node.status === "running"
              ? "text-[#fbbf24]"
              : node.status === "completed"
                ? "text-[#4ade80]"
                : node.status === "error"
                  ? "text-[#f87171]"
                  : "text-[#7a8194]"
          }`}
        >
          {node.status}
        </span>
      </div>
      <div className="px-2.5 py-0.5 text-[12px] text-[#7a8194]">{escapeHtml(node.goal)}</div>
      {node.children.length > 0 && (
        <div className="mt-1">
          {node.children.map((child) => (
            <AgentNode key={child.id} node={child} />
          ))}
        </div>
      )}
    </div>
  );
}

export function AgentTree({ tree }: { tree: AgentInfo | null }) {
  if (!tree?.id) {
    return <div className="p-3 text-sm text-[#7a8194]">No agents running yet.</div>;
  }
  return <AgentNode node={tree} isRoot />;
}
