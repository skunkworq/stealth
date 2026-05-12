"use client";

import { useRef, useEffect } from "react";
import { MessageItem } from "./MessageItem";
import type { Message } from "@/lib/types";

export function MessageList({ messages }: { messages: Message[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className="flex flex-1 flex-col gap-3 overflow-y-auto p-5">
      {messages.map((msg) => (
        <MessageItem key={msg.id} msg={msg} />
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
