<script lang="ts">
	import Head from '$lib/components/head.svelte';
	import DomainsView from './domains-view.svelte';

	let { data } = $props();
</script>

<Head title="Domains" />

<DomainsView domains={data.domains} container={data.container} form={data.form} />
