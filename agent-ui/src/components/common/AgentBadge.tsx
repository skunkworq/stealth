const TYPE_STYLES: Record<string, string> = {
  root: "bg-[#4f8cf7] text-white",
  research: "bg-[#7c3aed] text-white",
  browser: "bg-[#0ea5e9] text-white",
  analysis: "bg-[#10b981] text-white",
};

export function AgentBadge({ type }: { type: string }) {
  const style = TYPE_STYLES[type] ?? "bg-[#64748b] text-white";
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${style}`}>
      {type}
    </span>
  );
}
