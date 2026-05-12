<script lang="ts">
	import type { SessionStatus } from '$lib/types';

	interface Props {
		status: SessionStatus;
	}

	let { status }: Props = $props();

	const STATUS_STYLES: Record<SessionStatus, string> = {
		idle: 'bg-[#7a8194]',
		running: 'bg-[#fbbf24] animate-pulse',
		completed: 'bg-[#4ade80]',
		error: 'bg-[#f87171]'
	};
</script>

<span
	class="inline-block h-[7px] w-[7px] rounded-full {STATUS_STYLES[status] ?? STATUS_STYLES.idle}"
	title={status}
></span>
