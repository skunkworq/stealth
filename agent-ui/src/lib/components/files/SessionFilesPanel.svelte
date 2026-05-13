<script lang="ts">
  import type { FileMeta } from "$lib/types";
  import FilePreview from "./FilePreview.svelte";

  interface Props {
    sessionId: string;
    files: FileMeta[];
    visible: boolean;
    onToggle: () => void;
  }

  let { sessionId, files, visible, onToggle }: Props = $props();

  let selectedFile = $state<FileMeta | null>(null);
  let searchQuery = $state("");
  let expandedAgents = $state<Set<string>>(new Set());

  const grouped = $derived(() => {
    const map = new Map<string, FileMeta[]>();
    for (const f of files) {
      if (!map.has(f.agent_id)) map.set(f.agent_id, []);
      map.get(f.agent_id)!.push(f);
    }
    // sort each group by name
    for (const [, list] of map) {
      list.sort((a, b) => a.name.localeCompare(b.name));
    }
    return map;
  });

  const filtered = $derived(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return grouped();
    const map = new Map<string, FileMeta[]>();
    for (const [agentId, list] of grouped()) {
      const filteredList = list.filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          f.agent_id.toLowerCase().includes(q)
      );
      if (filteredList.length) map.set(agentId, filteredList);
    }
    return map;
  });

  const agentIds = $derived(() => {
    const ids = Array.from(filtered().keys());
    ids.sort();
    return ids;
  });

  function toggleAgent(agentId: string) {
    const next = new Set(expandedAgents);
    if (next.has(agentId)) {
      next.delete(agentId);
    } else {
      next.add(agentId);
    }
    expandedAgents = next;
  }

  function selectFile(file: FileMeta) {
    selectedFile = file;
  }

  function closePreview() {
    selectedFile = null;
  }

  function fileIcon(mime: string): string {
    if (mime.startsWith("image/")) return "🖼";
    if (mime.startsWith("text/") || mime === "application/json" || mime === "application/javascript" || mime === "application/typescript" || mime === "text/x-go" || mime === "text/x-python" || mime === "application/xml" || mime === "application/yaml" || mime === "text/csv") return "📄";
    return "📦";
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
</script>

<div class="sfp-wrapper" class:sfp-visible={visible} class:sfp-preview={selectedFile !== null}>
  <div class="sfp-sidebar">
    <div class="sfp-header">
      <h3 class="sfp-title">📁 Files</h3>
      <button class="sfp-toggle" onclick={onToggle} aria-label="Toggle files panel">×</button>
    </div>

    <div class="sfp-search">
      <input
        type="text"
        placeholder="Search files…"
        bind:value={searchQuery}
        class="sfp-search-input"
      />
    </div>

    <div class="sfp-count">
      {files.length} file{files.length === 1 ? "" : "s"}
      {#if searchQuery.trim()}
        · {Array.from(filtered().values()).reduce((a, b) => a + b.length, 0)} match{Array.from(filtered().values()).reduce((a, b) => a + b.length, 0) === 1 ? "" : "es"}
      {/if}
    </div>

    <div class="sfp-tree">
      {#if files.length === 0}
        <div class="sfp-empty">No files yet</div>
      {:else}
        {#each agentIds() as agentId}
          {@const isExpanded = expandedAgents.has(agentId)}
          <div class="sfp-agent">
            <button
              class="sfp-agent-header"
              onclick={() => toggleAgent(agentId)}
              aria-expanded={isExpanded}
            >
              <span class="sfp-chevron" class:sfp-chevron-open={isExpanded}>▸</span>
              <span class="sfp-agent-id">{agentId.slice(0, 8)}</span>
              <span class="sfp-agent-count">{filtered().get(agentId)?.length ?? 0}</span>
            </button>

            {#if isExpanded}
              <ul class="sfp-file-list">
                {#each filtered().get(agentId) ?? [] as file}
                  <li>
                    <button
                      class="sfp-file"
                      class:sfp-file-selected={selectedFile?.name === file.name && selectedFile?.agent_id === file.agent_id}
                      onclick={() => selectFile(file)}
                    >
                      <span class="sfp-file-icon">{fileIcon(file.mime_type)}</span>
                      <span class="sfp-file-name" title={file.name}>{file.name}</span>
                      <span class="sfp-file-size">{formatSize(file.size)}</span>
                    </button>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/each}
      {/if}
    </div>
  </div>

  {#if selectedFile}
    <div class="sfp-preview-pane">
      <FilePreview {sessionId} file={selectedFile} onClose={closePreview} />
    </div>
  {/if}
</div>

{#if !visible}
  <button class="sfp-fab" onclick={onToggle} aria-label="Show files panel" title="Files">
    📁
    {#if files.length > 0}
      <span class="sfp-fab-badge">{files.length}</span>
    {/if}
  </button>
{/if}

<style>
  .sfp-wrapper {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    display: flex;
    transform: translateX(100%);
    transition: transform 0.2s ease;
    z-index: 40;
    height: 100vh;
  }

  .sfp-visible {
    transform: translateX(0);
  }

  .sfp-sidebar {
    width: 260px;
    display: flex;
    flex-direction: column;
    background: var(--panel-bg, #1a1a1a);
    border-left: 1px solid var(--border, #2a2a2a);
    overflow: hidden;
  }

  .sfp-preview-pane {
    width: 420px;
    height: 100%;
    background: var(--panel-bg, #1a1a1a);
  }

  .sfp-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border, #2a2a2a);
    flex-shrink: 0;
  }

  .sfp-title {
    margin: 0;
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text, #e0e0e0);
  }

  .sfp-toggle {
    background: none;
    border: none;
    color: var(--muted, #888);
    font-size: 1.1rem;
    cursor: pointer;
    line-height: 1;
  }
  .sfp-toggle:hover {
    color: var(--text, #e0e0e0);
  }

  .sfp-search {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border, #2a2a2a);
    flex-shrink: 0;
  }

  .sfp-search-input {
    width: 100%;
    padding: 0.35rem 0.5rem;
    background: var(--input-bg, #222);
    border: 1px solid var(--border, #2a2a2a);
    border-radius: 4px;
    color: var(--text, #e0e0e0);
    font-size: 0.75rem;
    outline: none;
  }
  .sfp-search-input::placeholder {
    color: var(--muted, #666);
  }
  .sfp-search-input:focus {
    border-color: var(--accent, #3b82f6);
  }

  .sfp-count {
    padding: 0.3rem 0.75rem;
    font-size: 0.7rem;
    color: var(--muted, #888);
    border-bottom: 1px solid var(--border, #2a2a2a);
    flex-shrink: 0;
  }

  .sfp-tree {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 0.25rem 0;
  }

  .sfp-empty {
    padding: 2rem 0.75rem;
    text-align: center;
    font-size: 0.75rem;
    color: var(--muted, #888);
  }

  .sfp-agent {
    margin-bottom: 0.1rem;
  }

  .sfp-agent-header {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.4rem 0.75rem;
    background: none;
    border: none;
    color: var(--muted, #888);
    font-size: 0.75rem;
    cursor: pointer;
    text-align: left;
    transition: background 0.1s;
  }
  .sfp-agent-header:hover {
    background: var(--hover, #252525);
    color: var(--text, #e0e0e0);
  }

  .sfp-chevron {
    font-size: 0.65rem;
    transition: transform 0.15s;
    display: inline-block;
    width: 0.7rem;
    flex-shrink: 0;
  }
  .sfp-chevron-open {
    transform: rotate(90deg);
  }

  .sfp-agent-id {
    font-family: monospace;
    font-size: 0.7rem;
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sfp-agent-count {
    font-size: 0.65rem;
    background: var(--badge-bg, #333);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    flex-shrink: 0;
  }

  .sfp-file-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .sfp-file {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.35rem 0.75rem 0.35rem 1.5rem;
    background: none;
    border: none;
    color: var(--text, #e0e0e0);
    font-size: 0.75rem;
    cursor: pointer;
    text-align: left;
    transition: background 0.1s;
  }
  .sfp-file:hover {
    background: var(--hover, #252525);
  }
  .sfp-file-selected {
    background: var(--accent-bg, rgba(59, 130, 246, 0.15)) !important;
    color: var(--accent, #3b82f6);
  }

  .sfp-file-icon {
    flex-shrink: 0;
    font-size: 0.8rem;
  }

  .sfp-file-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sfp-file-size {
    flex-shrink: 0;
    font-size: 0.65rem;
    color: var(--muted, #888);
    font-family: monospace;
  }

  .sfp-fab {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    width: 2.75rem;
    height: 2.75rem;
    border-radius: 50%;
    background: var(--accent, #3b82f6);
    color: #fff;
    border: none;
    font-size: 1.1rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    z-index: 40;
    transition: transform 0.15s, opacity 0.15s;
  }
  .sfp-fab:hover {
    transform: scale(1.05);
    opacity: 0.9;
  }

  .sfp-fab-badge {
    position: absolute;
    top: -0.3rem;
    right: -0.3rem;
    min-width: 1.1rem;
    height: 1.1rem;
    border-radius: 50%;
    background: #ef4444;
    color: #fff;
    font-size: 0.6rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0 0.2rem;
  }
</style>
