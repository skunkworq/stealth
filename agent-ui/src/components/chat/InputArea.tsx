"use client";

import { useState, useCallback } from "react";
import { Send } from "lucide-react";

interface InputAreaProps {
  onSend: (text: string) => void;
  disabled?: boolean;
}

export function InputArea({ onSend, disabled }: InputAreaProps) {
  const [text, setText] = useState("");

  const handleSend = useCallback(() => {
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setText("");
  }, [text, onSend]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend]
  );

  return (
    <div className="flex gap-2 border-t border-[#2a2e3b] bg-[#161922] p-3">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        placeholder="Ask the research agent..."
        rows={1}
        className="max-h-32 min-h-[44px] flex-1 resize-none rounded-lg border border-[#2a2e3b] bg-[#1e212b] px-3 py-2.5 text-sm text-[#c9cdd6] outline-none transition-colors focus:border-[#4f8cf7] disabled:opacity-50"
      />
      <button
        onClick={handleSend}
        disabled={disabled || !text.trim()}
        className="flex items-center gap-1.5 rounded-lg bg-[#4f8cf7] px-4 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:bg-[#7a8194]"
      >
        <Send size={14} />
      </button>
    </div>
  );
}
