<script lang="ts">
	import TabGroup from '$lib/components/common/TabGroup.svelte';
	import AgentTree from './AgentTree.svelte';
	import EventStream from './EventStream.svelte';
	import FilesPanel from './FilesPanel.svelte';
	import type { AgentEvent, AgentInfo } from '$lib/types';

	interface Props {
		tree: AgentInfo | null;
		events: AgentEvent[];
		sessionId: string;
		files: Record<string, string[]>;
	}

	let { tree, events, sessionId, files }: Props = $props();
	let activeTab = $state('tree');
</script>

<div class="flex h-full flex-col border-t border-[#2a2e3b] bg-[#161922]">
	<TabGroup
		tabs={[
			{ id: 'tree', label: 'Agent Tree' },
			{ id: 'events', label: 'Event Stream' },
			{ id: 'files', label: 'Files' }
		]}
		bind:activeTab
	>
		{#if activeTab === 'tree'}
			<AgentTree {tree} />
		{:else if activeTab === 'events'}
			<EventStream {events} />
		{:else if activeTab === 'files'}
			<FilesPanel {sessionId} {files} />
		{/if}
	</TabGroup>
</div>
