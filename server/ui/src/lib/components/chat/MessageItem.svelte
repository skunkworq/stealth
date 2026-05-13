<script lang="ts">
	import { renderMarkdown } from '$lib/utils';
	import type { Message } from '$lib/types';

	interface Props {
		msg: Message;
	}

	let { msg }: Props = $props();

	let isUser = $derived(msg.role === 'user');
	let isSystem = $derived(msg.role === 'system');

	let meta = $derived(
		isSystem ? 'System' : msg.agent_id ? `Assistant (${msg.agent_id.slice(0, 8)})` : 'Assistant'
	);

	let renderedContent = $state('');

	$effect(() => {
		renderMarkdown(msg.content).then((html) => {
			renderedContent = html;
		});
	});
</script>

<div
	class="max-w-[85%] rounded-xl px-4 py-3 leading-relaxed {isUser
		? 'self-end rounded-br-sm bg-[#1e3a5f]'
		: 'self-start rounded-bl-sm bg-[#1e2736]'}"
>
	<div class="mb-1 text-[11px] text-[#7a8194]">{meta}</div>
	<div class="markdown-content whitespace-normal break-words">{@html renderedContent}</div>
</div>
