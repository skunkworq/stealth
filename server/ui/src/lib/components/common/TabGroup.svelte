<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Tab {
		id: string;
		label: string;
	}

	interface Props {
		tabs: Tab[];
		activeTab?: string;
		onTabChange?: (id: string) => void;
		children: Snippet;
	}

	let { tabs, activeTab = $bindable(tabs[0]?.id ?? ''), onTabChange, children }: Props = $props();

	function select(id: string) {
		activeTab = id;
		onTabChange?.(id);
	}
</script>

<div class="flex h-full flex-col">
	<div class="flex gap-0.5 border-b border-[#2a2e3b] px-3 pt-2">
		{#each tabs as tab}
			<button
				onclick={() => select(tab.id)}
				class="border-b-2 px-3.5 py-2 text-[13px] transition-colors {activeTab === tab.id
					? 'border-[#3bd0ee] text-[#3bd0ee]'
					: 'border-transparent text-[#7a8194] hover:text-[#c9cdd6]'}"
			>
				{tab.label}
			</button>
		{/each}
	</div>
	<div class="flex-1 overflow-y-auto p-3">
		{@render children()}
	</div>
</div>
