<script lang="ts">
	interface HeadProps {
		title: string;
		ogDescription?: string;
		ogImage?: string;
		ogUrl?: string;
		articleAuthor?: string;
	}

	let { title, ogDescription, ogImage, ogUrl, articleAuthor }: HeadProps = $props();

	let titleDerived = $derived(`${title} | Nest`);
</script>

<svelte:head>
	<meta property="og:title" content={titleDerived} />
	{#if ogDescription}
		<meta property="og:description" content={ogDescription} />
	{/if}
	{#if ogImage}
		<meta property="og:image" content={ogImage} />
	{/if}
	{#if ogUrl}
		<meta property="og:url" content={ogUrl} />
	{/if}
	{#if articleAuthor}
		<meta property="article:author" content={articleAuthor} />
	{/if}
	<title>{titleDerived}</title>
</svelte:head>
