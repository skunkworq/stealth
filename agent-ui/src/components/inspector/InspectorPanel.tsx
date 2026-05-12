"use client";

import { TabGroup } from "@/components/common/TabGroup";
import { AgentTree } from "./AgentTree";
import { EventStream } from "./EventStream";
import { FilesPanel } from "./FilesPanel";
import type { AgentEvent, AgentInfo } from "@/lib/types";

interface InspectorPanelProps {
  tree: AgentInfo | null;
  events: AgentEvent[];
  sessionId: string;
  files: Record<string, string[]>;
}

export function InspectorPanel({ tree, events, sessionId, files }: InspectorPanelProps) {
  return (
    <div className="flex h-full flex-col border-t border-[#2a2e3b] bg-[#161922]">
      <TabGroup
        tabs={[
          { id: "tree", label: "Agent Tree", content: <AgentTree tree={tree} /> },
          { id: "events", label: "Event Stream", content: <EventStream events={events} /> },
          { id: "files", label: "Files", content: <FilesPanel sessionId={sessionId} files={files} /> },
        ]}
      />
    </div>
  );
}
