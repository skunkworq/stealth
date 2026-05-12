<script lang="ts">
	import StatusBadge from '$lib/components/common/StatusBadge.svelte';
	import { escapeHtml } from '$lib/utils';
	import type { Session } from '$lib/types';

	interface Props {
		session: Session;
		isActive: boolean;
		onClick: () => void;
	}

	let { session, isActive, onClick }: Props = $props();
</script>

<button
	onclick={onClick}
	class="flex w-full cursor-pointer items-center gap-2 rounded-md px-3 py-2.5 text-left text-sm transition-colors {isActive
		? 'border-l-[3px] border-[#3bd0ee] bg-[#1e212b] text-[#3bd0ee]'
		: 'text-[#7a8194] hover:bg-[#1e212b] hover:text-[#c9cdd6]'}"
>
	<StatusBadge status={session.status} />
	<span class="truncate">{escapeHtml(session.title)}</span>
</button>
