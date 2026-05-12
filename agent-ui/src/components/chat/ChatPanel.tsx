"use client";

import { MessageList } from "./MessageList";
import { InputArea } from "./InputArea";
import type { Message } from "@/lib/types";

interface ChatPanelProps {
  messages: Message[];
  onSend: (text: string) => void;
  disabled?: boolean;
}

export function ChatPanel({ messages, onSend, disabled }: ChatPanelProps) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <MessageList messages={messages} />
      <InputArea onSend={onSend} disabled={disabled} />
    </div>
  );
}
