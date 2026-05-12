<script lang="ts">
	import AgentBadge from '$lib/components/common/AgentBadge.svelte';
	import { escapeHtml } from '$lib/utils';
	import type { AgentInfo } from '$lib/types';

	interface Props {
		tree: AgentInfo | null;
	}

	let { tree }: Props = $props();
</script>

{#if !tree?.id}
	<div class="p-3 text-sm text-[#7a8194]">No agents running yet.</div>
{:else}
	{@render AgentNode(tree, true)}
{/if}

{#snippet AgentNode(node: AgentInfo, isRoot = false)}
	<div class="{isRoot ? '' : 'ml-4 border-l-2 border-[#2a2e3b] pl-2.5'} mb-2">
		<div class="flex items-center gap-2 rounded-md bg-[#1e212b] px-2.5 py-1.5">
			<AgentBadge type={node.type} />
			<span class="text-[11px] text-[#7a8194]">{node.id.slice(0, 8)}</span>
			<span
				class="ml-auto text-[11px] {node.status === 'running'
					? 'text-[#fbbf24]'
					: node.status === 'completed'
						? 'text-[#4ade80]'
						: node.status === 'error'
							? 'text-[#f87171]'
							: 'text-[#7a8194]'}"
			>
				{node.status}
			</span>
		</div>
		<div class="px-2.5 py-0.5 text-[12px] text-[#7a8194]">{escapeHtml(node.goal)}</div>
		{#if node.children.length > 0}
			<div class="mt-1">
				{#each node.children as child}
					{@render AgentNode(child)}
				{/each}
			</div>
		{/if}
	</div>
{/snippet}
