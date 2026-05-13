<script lang="ts">
  import type { FileMeta } from "$lib/types";
  import { getFileUrl } from "$lib/api";

  interface Props {
    sessionId: string;
    file: FileMeta | null;
    onClose: () => void;
  }

  let { sessionId, file, onClose }: Props = $props();

  let content = $state("");
  let loading = $state(false);
  let error = $state("");

  const isImage = $derived(file?.mime_type.startsWith("image/") ?? false);
  const isText = $derived(
    file
      ? [
          "text/",
          "application/json",
          "application/javascript",
          "application/typescript",
          "text/x-go",
          "text/x-python",
          "application/xml",
          "application/yaml",
          "text/csv",
        ].some((t) => file.mime_type.startsWith(t) || file.mime_type === t)
      : false
  );

  $effect(() => {
    if (!file || isImage) {
      content = "";
      loading = false;
      error = "";
      return;
    }
    if (!isText) {
      content = "";
      loading = false;
      error = "";
      return;
    }
    loading = true;
    error = "";
    const url = getFileUrl(sessionId, `${file.agent_id}/${file.name}`);
    fetch(url)
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        content = text;
      })
      .catch((err) => {
        error = err.message;
      })
      .finally(() => {
        loading = false;
      });
  });

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function formatTime(iso: string): string {
    return new Date(iso).toLocaleString();
  }

  function fileIcon(mime: string): string {
    if (mime.startsWith("image/")) return "🖼";
    if (mime.startsWith("text/") || mime === "application/json" || mime === "application/javascript" || mime === "application/typescript" || mime === "text/x-go" || mime === "text/x-python" || mime === "application/xml" || mime === "application/yaml" || mime === "text/csv") return "📄";
    return "📦";
  }
</script>

{#if file}
  <div class="file-preview">
    <div class="file-preview-header">
      <div class="file-preview-title">
        <span class="file-preview-icon">{fileIcon(file.mime_type)}</span>
        <span class="file-preview-name" title={file.name}>{file.name}</span>
      </div>
      <button class="file-preview-close" onclick={onClose} aria-label="Close preview">×</button>
    </div>

    <div class="file-preview-meta">
      <span class="file-preview-badge">{file.agent_id.slice(0, 8)}</span>
      <span class="file-preview-size">{formatSize(file.size)}</span>
      <span class="file-preview-time">{formatTime(file.mod_time)}</span>
    </div>

    <div class="file-preview-body">
      {#if isImage}
        <img
          src={getFileUrl(sessionId, `${file.agent_id}/${file.name}`)}
          alt={file.name}
          class="file-preview-image"
        />
      {:else if isText}
        {#if loading}
          <div class="file-preview-loading">Loading…</div>
        {:else if error}
          <div class="file-preview-error">{error}</div>
        {:else}
          <pre class="file-preview-text"><code>{content}</code></pre>
        {/if}
      {:else}
        <div class="file-preview-unsupported">
          <p>Binary file — preview not available</p>
          <a
            href={getFileUrl(sessionId, `${file.agent_id}/${file.name}`)}
            target="_blank"
            class="file-preview-download"
            download={file.name}
          >
            Download ({formatSize(file.size)})
          </a>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .file-preview {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--panel-bg, #1a1a1a);
    border-left: 1px solid var(--border, #2a2a2a);
    overflow: hidden;
  }

  .file-preview-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border, #2a2a2a);
    background: var(--header-bg, #222);
    flex-shrink: 0;
  }

  .file-preview-title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
  }

  .file-preview-icon {
    font-size: 1rem;
    flex-shrink: 0;
  }

  .file-preview-name {
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--text, #e0e0e0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .file-preview-close {
    background: none;
    border: none;
    color: var(--muted, #888);
    font-size: 1.25rem;
    cursor: pointer;
    line-height: 1;
    padding: 0 0.25rem;
    flex-shrink: 0;
  }
  .file-preview-close:hover {
    color: var(--text, #e0e0e0);
  }

  .file-preview-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid var(--border, #2a2a2a);
    font-size: 0.7rem;
    color: var(--muted, #888);
    flex-shrink: 0;
  }

  .file-preview-badge {
    background: var(--accent, #3b82f6);
    color: #fff;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-family: monospace;
  }

  .file-preview-body {
    flex: 1;
    overflow: auto;
    padding: 0.5rem;
  }

  .file-preview-image {
    max-width: 100%;
    max-height: 100%;
    display: block;
    margin: 0 auto;
    border-radius: 4px;
  }

  .file-preview-text {
    margin: 0;
    padding: 0.5rem;
    background: var(--code-bg, #111);
    border-radius: 4px;
    font-size: 0.78rem;
    line-height: 1.5;
    color: var(--text, #e0e0e0);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .file-preview-text code {
    font-family: "SF Mono", "Fira Code", "JetBrains Mono", monospace;
    background: none;
    padding: 0;
  }

  .file-preview-loading,
  .file-preview-error,
  .file-preview-unsupported {
    padding: 1rem;
    text-align: center;
    font-size: 0.8rem;
    color: var(--muted, #888);
  }

  .file-preview-error {
    color: #ef4444;
  }

  .file-preview-download {
    display: inline-block;
    margin-top: 0.5rem;
    padding: 0.35rem 0.75rem;
    background: var(--accent, #3b82f6);
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
    font-size: 0.75rem;
  }
  .file-preview-download:hover {
    opacity: 0.9;
  }
</style>
