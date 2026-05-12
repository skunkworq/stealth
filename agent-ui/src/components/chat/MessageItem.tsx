"use client";

import { escapeHtml } from "@/lib/utils";
import type { Message } from "@/lib/types";

export function MessageItem({ msg }: { msg: Message }) {
  const isUser = msg.role === "user";
  const isSystem = msg.role === "system";

  let meta = "You";
  if (isSystem) meta = "System";
  else if (msg.agent_id) meta = `Assistant (${msg.agent_id.slice(0, 8)})`;
  else meta = "Assistant";

  return (
    <div
      className={`max-w-[85%] rounded-xl px-4 py-3 leading-relaxed ${
        isUser
          ? "self-end rounded-br-sm bg-[#1e3a5f]"
          : "self-start rounded-bl-sm bg-[#1e2736]"
      }`}
    >
      <div className="mb-1 text-[11px] text-[#7a8194]">{meta}</div>
      <div className="whitespace-pre-wrap break-words" dangerouslySetInnerHTML={{ __html: escapeHtml(msg.content) }} />
    </div>
  );
}
