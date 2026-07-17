<script lang="ts">
	import * as Table from '$lib/components/ui/table/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Spinner } from '$lib/components/ui/spinner/index.js';
	import type { RouterOutput } from '$lib/trpc';
	import { APP_DOMAIN } from '$app/env/public';
	import trpc from '$lib/trpc';
	import { getUserContext } from '$lib/user';
	import authClient from '$lib/auth';
	import { invalidateAll } from '$app/navigation';

	type Container = RouterOutput['user']['container'];

	let { container }: { container: Container } = $props();

	let buttonState = $state<{
		stop: boolean;
		start: boolean;
		reboot: boolean;
		delete: boolean;
	}>({
		stop: false,
		start: false,
		reboot: false,
		delete: false
	});

	const session = getUserContext()();

	const deleteContainer = async () => {
		if (!session.session.sudo) {
			authClient.signIn.oauth2({
				providerId: 'hackclub',
				errorCallbackURL: '/dashboard',
				callbackURL: '/dashboard',
				additionalData: {
					sudo: true
				}
			});
			return;
		}

		buttonState.delete = true;
		await trpc.user.delete.mutate();
		await invalidateAll();
		buttonState.delete = false;
	};

	const stopContainer = async () => {
		buttonState.stop = true;
		await trpc.user.stop.mutate();
		await invalidateAll();
		buttonState.stop = false;
	};

	const startContainer = async () => {
		buttonState.start = true;
		await trpc.user.start.mutate();
		await invalidateAll();
		buttonState.start = false;
	};

	const rebootContainer = async () => {
		buttonState.reboot = true;
		await trpc.user.reboot.mutate();
		await invalidateAll();
		buttonState.reboot = false;
	};
</script>

<div class="flex flex-1 flex-col gap-4">
	<h2 class="text-2xl font-bold tracking-tight">Your Nest container</h2>
	<p class="text-muted-foreground mt-1">From here you may check on the status of your container.</p>
	<Separator class="my-4" />
	<Table.Root class="border-border border rounded-lg overflow-hidden shadow-sm bg-muted/25">
		<Table.Body>
			<Table.Row>
				<Table.Cell class="font-medium">Username</Table.Cell>
				<Table.Cell>{container?.username}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">VMID</Table.Cell>
				<Table.Cell>{container?.vmid}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">Private IPv4</Table.Cell>
				<Table.Cell>{container?.ip}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">IPv6</Table.Cell>
				<Table.Cell>{container?.ipv6}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">Status</Table.Cell>
				<Table.Cell>{container?.status?.status}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">Hostname</Table.Cell>
				<Table.Cell>{container?.status?.name}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">CPU</Table.Cell>
				<Table.Cell>{container?.status?.cpus}</Table.Cell>
			</Table.Row>
			<Table.Row>
				<Table.Cell class="font-medium">Memory</Table.Cell>
				<Table.Cell
					>{Math.floor((container?.status?.mem || 0) / 1048576)} / {(container?.status?.maxmem ||
						0) / 1048576} MB</Table.Cell
				>
			</Table.Row>
		</Table.Body>
	</Table.Root>

	<div class="p-5 border bg-muted/25 rounded-xl flex items-center justify-between shadow-sm">
		<div>
			<span class="font-medium">SSH Access:</span>
			<code class="text-sm font-mono border border-border px-2.5 py-1.5 rounded-md"
				>ssh {container?.username}@{APP_DOMAIN}</code
			>
		</div>
	</div>
	<div class="flex gap-x-3 mt-4 pt-6 border-t border-border">
		{#if container?.status?.status === 'running'}
			<Button
				size="lg"
				variant="secondary"
				class="cursor-pointer"
				disabled={buttonState.stop}
				onclick={() => stopContainer()}
				>{#if buttonState.stop}<Spinner />{/if}Stop Container</Button
			>
			<Button
				size="lg"
				class="cursor-pointer"
				disabled={buttonState.reboot}
				onclick={() => rebootContainer()}
				>{#if buttonState.reboot}<Spinner />{/if}Restart Container</Button
			>
		{:else}
			<Button
				size="lg"
				class="cursor-pointer"
				disabled={buttonState.start}
				onclick={() => startContainer()}
				>{#if buttonState.start}<Spinner />{/if}Start Container</Button
			>
		{/if}
		<div class="flex-1"></div>
		<Button
			size="lg"
			variant="destructive"
			class="cursor-pointer"
			disabled={buttonState.delete}
			onclick={() => deleteContainer()}
			>{#if buttonState.delete}<Spinner />{/if}Delete Container</Button
		>
	</div>
</div>
