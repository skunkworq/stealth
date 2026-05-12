"use client";

import { SessionItem } from "./SessionItem";
import type { Session } from "@/lib/types";

interface SessionListProps {
  sessions: Session[];
  activeId?: string;
  onSelect: (id: string) => void;
}

export function SessionList({ sessions, activeId, onSelect }: SessionListProps) {
  return (
    <ul className="flex flex-col gap-1 overflow-y-auto p-2">
      {sessions.map((s) => (
        <SessionItem
          key={s.id}
          session={s}
          isActive={s.id === activeId}
          onClick={() => onSelect(s.id)}
        />
      ))}
    </ul>
  );
}
