<script lang="ts">
	import { getFileUrl } from '$lib/api';
	import { escapeHtml } from '$lib/utils';

	interface Props {
		sessionId: string;
		files: Record<string, string[]>;
	}

	let { sessionId, files }: Props = $props();

	const agents = $derived(Object.keys(files));
</script>

{#if agents.length === 0}
	<div class="p-3 text-sm text-[#7a8194]">No files yet.</div>
{:else}
	<div class="flex flex-col gap-3">
		{#each agents as agentId}
			<div>
				<div class="mb-1 rounded bg-[#1e212b] px-2 py-1 text-[12px] font-bold text-[#3bd0ee]">
					{agentId.slice(0, 8)}
				</div>
				<ul class="pl-2">
					{#each files[agentId] as f}
						{@const url = getFileUrl(sessionId, f)}
						{@const isImage = f.endsWith('.png') || f.endsWith('.jpg') || f.endsWith('.jpeg')}
						<li class="py-0.5 text-[12px]">
							<a
								href={url}
								target="_blank"
								rel="noreferrer"
								class="text-[#c9cdd6] hover:text-[#4f8cf7] hover:underline"
							>
								{isImage ? '🖼 ' : '📄 '}{escapeHtml(f)}
							</a>
						</li>
					{/each}
				</ul>
			</div>
		{/each}
	</div>
{/if}
