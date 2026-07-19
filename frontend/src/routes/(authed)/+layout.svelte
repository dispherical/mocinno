<script lang="ts">
	import SiteHeader from '$lib/components/site-header.svelte';
	import * as Sentry from '@sentry/sveltekit';
	import { setUserContext, setContainerContext } from '$lib/user';
	import * as Alert from '$lib/components/ui/alert/index.js';
	import AlertCircleIcon from '@lucide/svelte/icons/alert-circle';
	import CheckCircle2Icon from '@lucide/svelte/icons/check-circle-2';
	import { getFlash } from 'sveltekit-flash-message';
	import { page } from '$app/state';

	import type { LayoutProps } from './$types';

	let { children, data }: LayoutProps = $props();

	const flash = getFlash(page);

	setUserContext(() => data.session);

	setContainerContext(() => data.container);

	$effect(() => {
		Sentry.setUser({
			id: data.session.user.id,
			email: data.session.user.email
		});
	});
</script>

<div class="[--header-height:calc(--spacing(14))]">
	<SiteHeader admin={data.admin} />
	<div class="flex flex-1 flex-col max-w-4xl w-full mx-auto py-4 md:px-0">
		{#if $flash}
			{@const message = $flash.message}
			{@const status = $flash.type}
			<Alert.Root
				class={[
					status === 'success'
						? 'bg-primary/10 border-primary/40'
						: 'bg-destructive/10 border-destructive/40',
					'self-start border rounded-xl mb-4 shadow-sm'
				]}
			>
				<Alert.Description
					class={[
						status === 'error' && 'text-destructive',
						'font-medium',
						'flex flex-row gap-2 items-center'
					]}
					>{#if status === 'success'}
						<CheckCircle2Icon />
					{:else}
						<AlertCircleIcon />
					{/if}
					{message}</Alert.Description
				>
			</Alert.Root>
		{/if}
		{@render children?.()}
	</div>
</div>
