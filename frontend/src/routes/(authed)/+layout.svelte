<script lang="ts">
	import SiteHeader from '$lib/components/site-header.svelte';

	let { children } = $props();
</script>

<div class="[--header-height:calc(--spacing(14))]">
	<SiteHeader />
	<div class="flex flex-1">
		{@render children?.()}
	</div>
</div>
