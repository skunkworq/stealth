<script lang="ts">
	import MessageItem from './MessageItem.svelte';
	import type { Message } from '$lib/types';

	interface Props {
		messages: Message[];
	}

	let { messages }: Props = $props();
	let bottomEl = $state<HTMLDivElement | null>(null);

	$effect(() => {
		// Track messages to auto-scroll
		messages;
		bottomEl?.scrollIntoView({ behavior: 'smooth' });
	});
</script>

<div class="flex flex-1 flex-col gap-3 overflow-y-auto p-5">
	{#each messages as msg (msg.id)}
		<MessageItem {msg} />
	{/each}
	<div bind:this={bottomEl}></div>
</div>
