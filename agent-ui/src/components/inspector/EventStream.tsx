"use client";

import { useRef, useEffect } from "react";
import { EventBadge } from "@/components/common/EventBadge";
import { formatTime, escapeHtml } from "@/lib/utils";
import type { AgentEvent } from "@/lib/types";

export function EventStream({ events }: { events: AgentEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  return (
    <div className="flex flex-col gap-1">
      {events.map((ev, i) => (
        <EventRow key={i} ev={ev} />
      ))}
      <div ref={bottomRef} />
    </div>
  );
}

function EventRow({ ev }: { ev: AgentEvent }) {
  const agentLabel = ev.agent_id
    ? `${"└ ".repeat(ev.depth ?? 0)}${ev.agent_id.slice(0, 8)}`
    : "";

  let content = "";
  if (ev.type === "thought") {
    content = `[${escapeHtml(ev.step || "think")}] ${escapeHtml(ev.content || "")}`;
  } else if (ev.type === "tool_call") {
    content = `${escapeHtml(ev.tool_name || "")}(${JSON.stringify(ev.arguments || {})})`;
  } else if (ev.type === "tool_result") {
    content = `${escapeHtml(ev.tool_name || "")} → <pre class="mt-1 rounded bg-[#0f1117] p-1.5 text-[11px]">${escapeHtml(JSON.stringify(ev.result, null, 2))}</pre>`;
  } else if (ev.type === "agent_spawned") {
    content = `Spawned ${escapeHtml(ev.agent_type || "")}: ${escapeHtml(ev.goal || "")}`;
  } else if (ev.type === "agent_completed") {
    content = `Completed with status: ${escapeHtml(ev.status || "")}`;
  } else if (ev.type === "file_created") {
    content = `Created ${escapeHtml(ev.tool_name || "file")}: ${escapeHtml(ev.content || "")}`;
  } else if (ev.type === "error") {
    content = escapeHtml(ev.error || "");
  } else if (ev.type === "stream") {
    content = escapeHtml(ev.content || "");
  } else {
    content = escapeHtml(ev.content || JSON.stringify(ev));
  }

  return (
    <div className="flex gap-2.5 rounded px-2 py-1.5 text-[12px] hover:bg-[#1e212b]">
      <span className="min-w-[60px] text-[#7a8194]">{formatTime(ev.timestamp)}</span>
      <EventBadge type={ev.type} />
      <span className="min-w-[90px] text-[#3bd0ee]">{agentLabel}</span>
      <span className="flex-1 break-words" dangerouslySetInnerHTML={{ __html: content }} />
    </div>
  );
}
