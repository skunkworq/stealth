<script lang="ts">
	import MessageList from './MessageList.svelte';
	import InputArea from './InputArea.svelte';
	import type { Message } from '$lib/types';

	interface Props {
		messages: Message[];
		onSend: (text: string) => void;
		disabled?: boolean;
	}

	let { messages, onSend, disabled = false }: Props = $props();
</script>

<div class="flex min-h-0 flex-1 flex-col">
	<MessageList {messages} />
	<InputArea {onSend} {disabled} />
</div>
