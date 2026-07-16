<script lang="ts">
	import SiteHeader from '$lib/components/site-header.svelte';
	import { setUserContext, setContainerContext } from '$lib/user';
	import type { LayoutProps } from './$types';

	let { children, data }: LayoutProps = $props();

	setUserContext(() => data.session);

	setContainerContext(() => data.container);
</script>

<div class="[--header-height:calc(--spacing(14))]">
	<SiteHeader user={data.session.user} />
	<div class="flex flex-1 max-w-4xl w-full mx-auto py-4 md:px-0">
		{@render children?.()}
	</div>
</div>
