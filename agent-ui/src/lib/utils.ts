export function escapeHtml(text: unknown): string {
  if (text == null) return "";
  if (typeof document === "undefined") return String(text);
  const div = document.createElement("div");
  div.textContent = String(text);
  return div.innerHTML;
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

export function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max) + "…";
}
