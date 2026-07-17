<script lang="ts">
	import * as Table from '$lib/components/ui/table/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import type { RouterOutput } from '$lib/trpc';
	import { APP_DOMAIN } from '$app/env/public';
	import trpc from '$lib/trpc';
	import { getUserContext } from '$lib/user';
	import authClient from '$lib/auth';

	type Container = RouterOutput['user']['container'];

	let { container }: { container: Container } = $props();

	const session = getUserContext()();

	const deleteContainer = async () => {
		if (!session.session.sudo) {
			authClient.signIn.oauth2({
				providerId: 'hackclub',
				callbackURL: '/dashboard',
				additionalData: {
					sudo: true
				}
			});
		}

		await trpc.user.delete.mutate();
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
				onclick={() => trpc.user.stop.mutate()}>Stop Container</Button
			>
			<Button size="lg" class="cursor-pointer" onclick={() => trpc.user.reboot.mutate()}
				>Restart Container</Button
			>
		{:else}
			<Button size="lg" class="cursor-pointer" onclick={() => trpc.user.start.mutate()}
				>Start Container</Button
			>
		{/if}
		<div class="flex-1"></div>
		<Button size="lg" variant="destructive" class="cursor-pointer" onclick={() => deleteContainer()}
			>Delete Container</Button
		>
	</div>
</div>
