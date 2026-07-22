<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { Spinner } from '$lib/components/ui/spinner/index.js';
	import { invalidateAll } from '$app/navigation';
	import { APP_DOMAIN, APP_SECURE } from '$app/env/public';
	import trpc from '$lib/trpc';

	let { code }: { code: string } = $props();

	let deleteWorking = $state(false);

	const deleteInvite = async () => {
		deleteWorking = true;
		await trpc.admin.deleteInvite.mutate({
			code
		});
		await invalidateAll();
		deleteWorking = false;
	};

	const copyInviteCode = async () => {
		await navigator.clipboard.writeText(
			`${APP_SECURE ? 'https' : 'http'}://${APP_DOMAIN}?invite=${code}`
		);
	};
</script>

<Button onclick={deleteInvite} variant="destructive" disabled={deleteWorking}>
	{#if deleteWorking}<Spinner />{/if}
	Revoke
</Button>
<Button onclick={copyInviteCode} variant="outline">Copy Code</Button>
