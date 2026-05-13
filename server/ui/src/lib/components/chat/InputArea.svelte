<script lang="ts">
	import { Send } from 'lucide-svelte';

	interface Props {
		onSend: (text: string) => void;
		disabled?: boolean;
	}

	let { onSend, disabled = false }: Props = $props();
	let text = $state('');

	function handleSend() {
		const trimmed = text.trim();
		if (!trimmed) return;
		onSend(trimmed);
		text = '';
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			handleSend();
		}
	}
</script>

<div class="flex gap-2 border-t border-[#2a2e3b] bg-[#161922] p-3">
	<textarea
		bind:value={text}
		onkeydown={handleKeyDown}
		{disabled}
		placeholder="Ask the research agent..."
		rows={1}
		class="max-h-32 min-h-[44px] flex-1 resize-none rounded-lg border border-[#2a2e3b] bg-[#1e212b] px-3 py-2.5 text-sm text-[#c9cdd6] outline-none transition-colors focus:border-[#4f8cf7] disabled:opacity-50"
	></textarea>
	<button
		onclick={handleSend}
		disabled={disabled || !text.trim()}
		class="flex items-center gap-1.5 rounded-lg bg-[#4f8cf7] px-4 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:bg-[#7a8194]"
	>
		<Send size={14} />
	</button>
</div>
