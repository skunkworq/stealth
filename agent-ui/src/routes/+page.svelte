<script lang="ts">
	import { onMount } from 'svelte';
	import type { AgentEvent, Message, Session, AgentInfo } from '$lib/types';
	import { listSessions, createSession, getSession, sendMessage, getAgentTree, listFiles } from '$lib/api';
	import { WSClient } from '$lib/websocket';
	import SessionSidebar from '$lib/components/session/SessionSidebar.svelte';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import InspectorPanel from '$lib/components/inspector/InspectorPanel.svelte';

	/* ── state ── */
	let sessions = $state<Session[]>([]);
	let currentSession = $state<Session | null>(null);
	let messages = $state<Message[]>([]);
	let events = $state<AgentEvent[]>([]);
	let sending = $state(false);
	let tree = $state<AgentInfo | null>(null);
	let files = $state<Record<string, string[]>>({});

	let sessionId = $derived(currentSession?.id);
	let wsClient = $state<WSClient | null>(null);

	/* ── ws setup (runs once) ── */
	$effect(() => {
		const client = new WSClient();
		client.connect(handleEvent);
		wsClient = client;
		return () => client.disconnect();
	});

	/* ── session change side-effects ── */
	$effect(() => {
		const id = sessionId;
		if (id && wsClient) {
			wsClient.subscribe(id);
			loadSession(id);
			refreshTree(id);
			refreshFiles(id);
			events = [];
		}
	});

	onMount(() => {
		refreshSessions();
	});

	/* ── event handler ── */
	function handleEvent(ev: AgentEvent) {
		if (ev.session_id !== sessionId) return;

		events = [...events, ev];

		switch (ev.type) {
			case 'message': {
				const role = ev.role;
				const content = ev.content;
				if (role && content) {
					messages = [
						...messages,
						{
							id: `${Date.now()}-${Math.random()}`,
							role: role as 'user' | 'assistant' | 'system',
							content,
							agent_id: ev.agent_id,
							timestamp: new Date().toISOString()
						}
					];
				}
				break;
			}
			case 'agent_spawned':
			case 'agent_completed': {
				const id = sessionId;
				if (id) refreshTree(id);
				break;
			}
			case 'file_created': {
				const id = sessionId;
				if (id) refreshFiles(id);
				break;
			}
			case 'session_updated': {
				if (ev.status && currentSession) {
					currentSession = { ...currentSession, status: ev.status as Session['status'] };
				}
				break;
			}
		}
	}

	/* ── data helpers ── */
	async function refreshSessions() {
		sessions = await listSessions();
	}

	async function refreshTree(id: string) {
		tree = await getAgentTree(id);
	}

	async function refreshFiles(id: string) {
		files = await listFiles(id);
	}

	async function loadSession(id: string) {
		const s = await getSession(id);
		if (s) {
			currentSession = s;
			messages = s.messages || [];
		}
	}

	/* ── user actions ── */
	function handleSelectSession(id: string) {
		const s = sessions.find((x) => x.id === id);
		if (s) {
			currentSession = s;
			messages = s.messages || [];
			events = [];
		}
	}

	async function handleCreateSession(title: string) {
		const s = await createSession({ title });
		sessions = [...sessions, s];
		currentSession = s;
		messages = [];
		events = [];
	}

	async function handleSend(text: string) {
		if (!sessionId) return;
		sending = true;
		messages = [
			...messages,
			{
				id: `${Date.now()}-${Math.random()}`,
				role: 'user',
				content: text,
				timestamp: new Date().toISOString()
			}
		];
		try {
			await sendMessage(sessionId, { content: text });
		} catch (err) {
			messages = [
				...messages,
				{
					id: `${Date.now()}-${Math.random()}`,
					role: 'system',
					content: err instanceof Error ? err.message : 'Failed to send',
					timestamp: new Date().toISOString()
				}
			];
		} finally {
			sending = false;
		}
	}
</script>

<div class="flex h-full">
	<SessionSidebar
		{sessions}
		activeId={sessionId}
		onSelect={handleSelectSession}
		onCreate={handleCreateSession}
	/>

	<main class="flex min-w-0 flex-1 flex-col">
		<ChatPanel {messages} onSend={handleSend} disabled={sending || !sessionId} />

		<div class="h-[320px] shrink-0">
			<InspectorPanel {tree} {events} sessionId={sessionId ?? ''} {files} />
		</div>
	</main>
</div>
