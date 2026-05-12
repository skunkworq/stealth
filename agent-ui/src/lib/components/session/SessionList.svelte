<script lang="ts">
	import SessionItem from './SessionItem.svelte';
	import type { Session } from '$lib/types';

	interface Props {
		sessions: Session[];
		activeId?: string;
		onSelect: (id: string) => void;
	}

	let { sessions, activeId, onSelect }: Props = $props();
</script>

<ul class="flex flex-col gap-1 overflow-y-auto p-2">
	{#each sessions as s (s.id)}
		<SessionItem session={s} isActive={s.id === activeId} onClick={() => onSelect(s.id)} />
	{/each}
</ul>
