<script lang="ts">
	import type { PageProps } from './$types';
	import Head from '$lib/components/Head.svelte';

	let { data }: PageProps = $props();
</script>

<Head title="Dashboard" />

{#await data.authTest}
	Loading auth test...
{:then auth}
	{auth}
{/await}
