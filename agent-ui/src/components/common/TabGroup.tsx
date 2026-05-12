"use client";

import { useState, type ReactNode } from "react";

interface Tab {
  id: string;
  label: string;
  content: ReactNode;
}

export function TabGroup({ tabs }: { tabs: Tab[] }) {
  const [active, setActive] = useState(tabs[0]?.id);

  return (
    <div className="flex h-full flex-col">
      <div className="flex gap-0.5 border-b border-[#2a2e3b] px-3 pt-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={`border-b-2 px-3.5 py-2 text-[13px] transition-colors ${
              active === tab.id
                ? "border-[#3bd0ee] text-[#3bd0ee]"
                : "border-transparent text-[#7a8194] hover:text-[#c9cdd6]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto p-3">
        {tabs.map((tab) => (
          <div key={tab.id} className={active === tab.id ? "block" : "hidden"}>
            {tab.content}
          </div>
        ))}
      </div>
    </div>
  );
}
