import type { EventType } from "@/lib/types";

const EVENT_STYLES: Record<string, string> = {
  thought: "bg-[#4f46e5] text-white",
  tool_call: "bg-[#fbbf24] text-black",
  tool_result: "bg-[#4ade80] text-black",
  agent_spawned: "bg-[#4f8cf7] text-white",
  agent_completed: "bg-[#64748b] text-white",
  stream: "bg-[#3bd0ee] text-black",
  error: "bg-[#f87171] text-white",
  message: "bg-[#8b5cf6] text-white",
  file_created: "bg-[#10b981] text-white",
};

export function EventBadge({ type }: { type: EventType }) {
  const label = type.replace(/_/g, " ");
  const style = EVENT_STYLES[type] ?? "bg-[#64748b] text-white";
  return (
    <span className={`min-w-[70px] rounded px-1 py-0.5 text-center text-[10px] font-bold uppercase ${style}`}>
      {label}
    </span>
  );
}
