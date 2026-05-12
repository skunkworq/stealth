"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { SessionSidebar } from "@/components/session/SessionSidebar";
import { ChatPanel } from "@/components/chat/ChatPanel";
import { InspectorPanel } from "@/components/inspector/InspectorPanel";
import { useSessions } from "@/hooks/useSessions";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useAgentTree } from "@/hooks/useAgentTree";
import { useFiles } from "@/hooks/useFiles";
import { sendMessage } from "@/lib/api";
import type { AgentEvent, Message, Session } from "@/lib/types";

export default function HomePage() {
  const { sessions, refresh, create, loadOne } = useSessions();
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [sending, setSending] = useState(false);

  const { tree, refresh: refreshTree } = useAgentTree();
  const { files, refresh: refreshFiles } = useFiles();

  const eventsRef = useRef<AgentEvent[]>([]);
  eventsRef.current = events;

  const sessionId = currentSession?.id;

  const handleEvent = useCallback(
    (ev: AgentEvent) => {
      if (ev.session_id !== sessionId) return;

      setEvents((prev) => [...prev, ev]);

      switch (ev.type) {
        case "message": {
          const role = ev.role;
          const content = ev.content;
          if (role && content) {
            setMessages((prev) => [
              ...prev,
              {
                id: `${Date.now()}-${Math.random()}`,
                role: role as "user" | "assistant" | "system",
                content: content,
                agent_id: ev.agent_id,
                timestamp: new Date().toISOString(),
              },
            ]);
          }
          break;
        }
          break;
        case "agent_spawned":
        case "agent_completed":
          refreshTree(sessionId);
          break;
        case "file_created":
          refreshFiles(sessionId);
          break;
        case "session_updated":
          if (ev.status) {
            setCurrentSession((prev) => (prev ? { ...prev, status: ev.status as Session["status"] } : prev));
          }
          break;
      }
    },
    [sessionId, refreshTree, refreshFiles]
  );

  const { subscribe } = useWebSocket(handleEvent);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (sessionId) {
      subscribe(sessionId);
      loadOne(sessionId).then((s) => {
        if (s) {
          setCurrentSession(s);
          setMessages(s.messages || []);
        }
      });
      refreshTree(sessionId);
      refreshFiles(sessionId);
      setEvents([]);
    }
  }, [sessionId, subscribe, loadOne, refreshTree, refreshFiles]);

  const handleSelectSession = useCallback((id: string) => {
    const s = sessions.find((x) => x.id === id);
    if (s) {
      setCurrentSession(s);
      setMessages(s.messages || []);
      setEvents([]);
    }
  }, [sessions]);

  const handleCreateSession = useCallback(
    async (title: string) => {
      const s = await create(title);
      setCurrentSession(s);
      setMessages([]);
      setEvents([]);
    },
    [create]
  );

  const handleSend = useCallback(
    async (text: string) => {
      if (!sessionId) return;
      setSending(true);
      setMessages((prev) => [
        ...prev,
        {
          id: `${Date.now()}-${Math.random()}`,
          role: "user",
          content: text,
          timestamp: new Date().toISOString(),
        },
      ]);
      try {
        await sendMessage(sessionId, { content: text });
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          {
            id: `${Date.now()}-${Math.random()}`,
            role: "system",
            content: err instanceof Error ? err.message : "Failed to send",
            timestamp: new Date().toISOString(),
          },
        ]);
      } finally {
        setSending(false);
      }
    },
    [sessionId]
  );

  return (
    <div className="flex h-full">
      <SessionSidebar
        sessions={sessions}
        activeId={sessionId}
        onSelect={handleSelectSession}
        onCreate={handleCreateSession}
      />

      <main className="flex min-w-0 flex-1 flex-col">
        <ChatPanel messages={messages} onSend={handleSend} disabled={sending || !sessionId} />

        <div className="h-[320px] shrink-0">
          <InspectorPanel
            tree={tree}
            events={events}
            sessionId={sessionId ?? ""}
            files={files}
          />
        </div>
      </main>
    </div>
  );
}
