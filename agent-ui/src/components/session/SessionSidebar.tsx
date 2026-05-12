"use client";

import { useState, useCallback } from "react";
import { Plus } from "lucide-react";
import { SessionList } from "./SessionList";
import type { Session } from "@/lib/types";

interface SessionSidebarProps {
  sessions: Session[];
  activeId?: string;
  onSelect: (id: string) => void;
  onCreate: (title: string) => Promise<void>;
}

export function SessionSidebar({ sessions, activeId, onSelect, onCreate }: SessionSidebarProps) {
  const [showModal, setShowModal] = useState(false);
  const [title, setTitle] = useState("New Session");
  const [creating, setCreating] = useState(false);

  const handleCreate = useCallback(async () => {
    setCreating(true);
    try {
      await onCreate(title.trim() || "New Session");
      setShowModal(false);
      setTitle("New Session");
    } finally {
      setCreating(false);
    }
  }, [title, onCreate]);

  return (
    <aside className="flex w-[260px] flex-col border-r border-[#2a2e3b] bg-[#161922]">
      <div className="border-b border-[#2a2e3b] p-4">
        <h1 className="mb-3 text-lg font-bold tracking-wide text-[#4f8cf7]">brws</h1>
        <button
          onClick={() => setShowModal(true)}
          className="flex w-full items-center justify-center gap-1.5 rounded-md bg-[#4f8cf7] px-3 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90"
        >
          <Plus size={14} />
          New Session
        </button>
      </div>

      <SessionList sessions={sessions} activeId={activeId} onSelect={onSelect} />

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60" onClick={() => setShowModal(false)} />
          <div className="relative z-10 w-[360px] rounded-xl border border-[#2a2e3b] bg-[#161922] p-6">
            <h2 className="mb-4 text-base font-semibold">New Session</h2>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              className="mb-4 w-full rounded-md border border-[#2a2e3b] bg-[#1e212b] px-3 py-2 text-sm text-[#c9cdd6] outline-none focus:border-[#4f8cf7]"
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowModal(false)}
                className="rounded-md bg-[#1e212b] px-3.5 py-2 text-sm text-[#c9cdd6]"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={creating}
                className="rounded-md bg-[#4f8cf7] px-3.5 py-2 text-sm font-semibold text-white disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
