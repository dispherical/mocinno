<script lang="ts">
	import SiteHeader from '$lib/components/site-header.svelte';
	import { setUserContext } from '$lib/user';
	import type { LayoutProps } from './$types';

	let { children, data }: LayoutProps = $props();

	setUserContext(() => data.user);
</script>

<div class="[--header-height:calc(--spacing(14))]">
	<SiteHeader user={data.user} />
	<div class="flex flex-1">
		{@render children?.()}
	</div>
</div>
