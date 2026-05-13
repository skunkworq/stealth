<script lang="ts">
	import { Plus } from 'lucide-svelte';
	import SessionList from './SessionList.svelte';
	import type { Session } from '$lib/types';

	interface Props {
		sessions: Session[];
		activeId?: string;
		onSelect: (id: string) => void;
		onCreate: (title: string) => Promise<void>;
	}

	let { sessions, activeId, onSelect, onCreate }: Props = $props();

	let showModal = $state(false);
	let title = $state('New Session');
	let creating = $state(false);

	async function handleCreate() {
		creating = true;
		try {
			await onCreate(title.trim() || 'New Session');
			showModal = false;
			title = 'New Session';
		} finally {
			creating = false;
		}
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === 'Enter') handleCreate();
	}
</script>

<aside class="flex w-[260px] flex-col border-r border-[#2a2e3b] bg-[#161922]">
	<div class="border-b border-[#2a2e3b] p-4">
		<h1 class="mb-3 text-lg font-bold tracking-wide text-[#4f8cf7]">brws</h1>
		<button
			onclick={() => (showModal = true)}
			class="flex w-full items-center justify-center gap-1.5 rounded-md bg-[#4f8cf7] px-3 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90"
		>
			<Plus size={14} />
			New Session
		</button>
	</div>

	<SessionList {sessions} {activeId} {onSelect} />

	{#if showModal}
		<div class="fixed inset-0 z-50 flex items-center justify-center">
			<div class="absolute inset-0 bg-black/60" onclick={() => (showModal = false)} role="presentation"></div>
			<div class="relative z-10 w-[360px] rounded-xl border border-[#2a2e3b] bg-[#161922] p-6">
				<h2 class="mb-4 text-base font-semibold">New Session</h2>
				<input
					bind:value={title}
					onkeydown={handleKeyDown}
					class="mb-4 w-full rounded-md border border-[#2a2e3b] bg-[#1e212b] px-3 py-2 text-sm text-[#c9cdd6] outline-none focus:border-[#4f8cf7]"

				/>
				<div class="flex justify-end gap-2">
					<button
						onclick={() => (showModal = false)}
						class="rounded-md bg-[#1e212b] px-3.5 py-2 text-sm text-[#c9cdd6]"
					>
						Cancel
					</button>
					<button
						onclick={handleCreate}
						disabled={creating}
						class="rounded-md bg-[#4f8cf7] px-3.5 py-2 text-sm font-semibold text-white disabled:opacity-50"
					>
						Create
					</button>
				</div>
			</div>
		</div>
	{/if}
</aside>
