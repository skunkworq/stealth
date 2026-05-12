import type { Session, AgentInfo, CreateSessionRequest, SendMessageRequest } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, init);
  if (!res.ok) {
    const text = await res.text().catch(() => "Unknown error");
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function listSessions(): Promise<Session[]> {
  const data = await fetchJSON<{ sessions: Session[] }>("/api/sessions");
  return data.sessions;
}

export async function createSession(req: CreateSessionRequest): Promise<Session> {
  const data = await fetchJSON<{ session: Session }>("/api/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  return data.session;
}

export async function getSession(id: string): Promise<Session> {
  const data = await fetchJSON<{ session: Session }>(`/api/sessions/${id}`);
  return data.session;
}

export async function sendMessage(sessionId: string, req: SendMessageRequest): Promise<void> {
  await fetchJSON<unknown>(`/api/sessions/${sessionId}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export async function getAgentTree(sessionId: string): Promise<AgentInfo | null> {
  const data = await fetchJSON<{ session_id: string; tree: AgentInfo | null }>(
    `/api/agents/tree/${sessionId}`
  );
  return data.tree;
}

export async function listFiles(sessionId: string): Promise<Record<string, string[]>> {
  const data = await fetchJSON<{ session_id: string; files: Record<string, string[]> }>(
    `/api/files/${sessionId}`
  );
  return data.files;
}

export function getFileUrl(sessionId: string, refPath: string): string {
  return `${API_BASE}/api/files/${sessionId}/${refPath}`;
}
