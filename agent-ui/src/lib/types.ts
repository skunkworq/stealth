export interface Session {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  messages: Message[];
  root_agent?: string;
  status: SessionStatus;
}

export type SessionStatus = "idle" | "running" | "completed" | "error";

export interface Message {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  agent_id?: string;
  timestamp: string;
}

export type EventType =
  | "session_created"
  | "session_updated"
  | "message"
  | "agent_spawned"
  | "agent_completed"
  | "thought"
  | "tool_call"
  | "tool_result"
  | "stream"
  | "file_created"
  | "error";

export interface AgentEvent {
  type: EventType;
  session_id: string;
  agent_id?: string;
  parent_id?: string;
  depth?: number;
  timestamp: number;
  content?: string;
  role?: string;
  tool_name?: string;
  arguments?: Record<string, unknown>;
  result?: unknown;
  goal?: string;
  agent_type?: string;
  status?: string;
  error?: string;
  step?: string;
  duration_ms?: number;
}

export interface AgentInfo {
  id: string;
  parent_id?: string;
  depth: number;
  type: string;
  goal: string;
  status: string;
  created_at: string;
  children: AgentInfo[];
}

export interface CreateSessionRequest {
  title: string;
}

export interface SendMessageRequest {
  content: string;
  provider?: string;
  model?: string;
  api_key?: string;
}
