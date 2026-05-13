<script lang="ts">
	import EventBadge from '$lib/components/common/EventBadge.svelte';
	import { formatTime, escapeHtml } from '$lib/utils';
	import type { AgentEvent } from '$lib/types';

	interface Props {
		events: AgentEvent[];
	}

	let { events }: Props = $props();
	let bottomEl = $state<HTMLDivElement | null>(null);

	$effect(() => {
		events;
		bottomEl?.scrollIntoView({ behavior: 'smooth' });
	});

	function renderContent(ev: AgentEvent): string {
		if (ev.type === 'thought') {
			return `[${escapeHtml(ev.step || 'think')}] ${escapeHtml(ev.content || '')}`;
		} else if (ev.type === 'tool_call') {
			return `${escapeHtml(ev.tool_name || '')}(${JSON.stringify(ev.arguments || {})})`;
		} else if (ev.type === 'tool_result') {
			return `${escapeHtml(ev.tool_name || '')} → <pre class="mt-1 rounded bg-[#0f1117] p-1.5 text-[11px]">${escapeHtml(JSON.stringify(ev.result, null, 2))}</pre>`;
		} else if (ev.type === 'agent_spawned') {
			return `Spawned ${escapeHtml(ev.agent_type || '')}: ${escapeHtml(ev.goal || '')}`;
		} else if (ev.type === 'agent_completed') {
			return `Completed with status: ${escapeHtml(ev.status || '')}`;
		} else if (ev.type === 'file_created') {
			return `Created ${escapeHtml(ev.tool_name || 'file')}: ${escapeHtml(ev.content || '')}`;
		} else if (ev.type === 'error') {
			return escapeHtml(ev.error || '');
		} else if (ev.type === 'stream') {
			return escapeHtml(ev.content || '');
		} else {
			return escapeHtml(ev.content || JSON.stringify(ev));
		}
	}
</script>

<div class="flex flex-col gap-1">
	{#each events as ev, i (i)}
		{@const agentLabel = ev.agent_id
			? `${'└ '.repeat(ev.depth ?? 0)}${ev.agent_id.slice(0, 8)}`
			: ''}
		<div class="flex gap-2.5 rounded px-2 py-1.5 text-[12px] hover:bg-[#1e212b]">
			<span class="min-w-[60px] text-[#7a8194]">{formatTime(ev.timestamp)}</span>
			<EventBadge type={ev.type} />
			<span class="min-w-[90px] text-[#3bd0ee]">{agentLabel}</span>
			<span class="flex-1 break-words">{@html renderContent(ev)}</span>
		</div>
	{/each}
	<div bind:this={bottomEl}></div>
</div>
