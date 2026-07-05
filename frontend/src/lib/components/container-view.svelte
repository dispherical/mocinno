<script lang="ts">
	import * as Table from '$lib/components/ui/table/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import type { RouterOutput } from '$lib/trpc';

	type Container = RouterOutput['user']['container'];

	let { container }: { container: Container } = $props();
</script>

<div class="flex flex-1 flex-col gap-4">
	<h2 class="text-2xl font-bold tracking-tight">Your Nest container</h2>
	<p class="text-muted-foreground mt-1">From here you may check on the status of your container.</p>
	<Separator class="my-4" />
	<Table.Root class="border-border border rounded-xl overflow-hidden shadow-sm">
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
</div>
