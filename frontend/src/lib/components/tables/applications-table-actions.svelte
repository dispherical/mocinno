<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { Spinner } from '$lib/components/ui/spinner/index.js';
	import { invalidateAll } from '$app/navigation';
	import trpc from '$lib/trpc';

	let { status, id }: { status: 'pending' | 'approved' | 'rejected'; id: number } = $props();

	let processWorking = $state(false);

	const processApplication = async (action: 'approve' | 'reject') => {
		processWorking = true;
		await trpc.admin.processApplication.mutate({
			id,
			action
		});
		await invalidateAll();
		processWorking = false;
	};
</script>

{#if status === 'pending'}
	<Button
		onclick={() => {
			processApplication('approve');
		}}
		disabled={processWorking}
	>
		{#if processWorking}<Spinner />{/if}
		Approve
	</Button>
	<Button
		onclick={() => {
			processApplication('reject');
		}}
		variant="destructive"
		disabled={processWorking}
	>
		{#if processWorking}<Spinner />{/if}
		Reject
	</Button>
{:else if status === 'approved'}
	<span class="text-primary">Approved</span>
{:else if status === 'rejected'}
	<span class="text-destructive">Rejected</span>
{/if}
