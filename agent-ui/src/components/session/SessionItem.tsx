"use client";

import { StatusBadge } from "@/components/common/StatusBadge";
import { escapeHtml } from "@/lib/utils";
import type { Session } from "@/lib/types";

interface SessionItemProps {
  session: Session;
  isActive: boolean;
  onClick: () => void;
}

export function SessionItem({ session, isActive, onClick }: SessionItemProps) {
  return (
    <li
      onClick={onClick}
      className={`flex cursor-pointer items-center gap-2 rounded-md px-3 py-2.5 text-sm transition-colors ${
        isActive
          ? "border-l-[3px] border-[#3bd0ee] bg-[#1e212b] text-[#3bd0ee]"
          : "text-[#7a8194] hover:bg-[#1e212b] hover:text-[#c9cdd6]"
      }`}
    >
      <StatusBadge status={session.status} />
      <span className="truncate">{escapeHtml(session.title)}</span>
    </li>
  );
}
