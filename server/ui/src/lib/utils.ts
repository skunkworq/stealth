import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';

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

/**
 * Parse markdown to HTML and sanitize the output.
 * Returns empty string for null/undefined input.
 */
export async function renderMarkdown(text: unknown): Promise<string> {
  if (text == null) return "";
  const raw = String(text);
  if (!raw.trim()) return "";

  const html = await marked.parse(raw, {
    gfm: true,
    breaks: true,
  });

  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      'p', 'br', 'hr',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'strong', 'b', 'em', 'i', 'del', 's',
      'a',
      'ul', 'ol', 'li',
      'blockquote',
      'pre', 'code',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'img',
    ],
    ALLOWED_ATTR: ['href', 'title', 'src', 'alt', 'class'],
  });
}
