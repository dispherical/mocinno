<script lang="ts">
	import './layout.css';
	import '$lib/theme.scss';
	import { ModeWatcher } from 'mode-watcher';
	import favicon from '$lib/assets/favicon.png';

	let { children } = $props();
</script>

<svelte:head><link rel="icon" type="image/png" href={favicon} /></svelte:head>

<ModeWatcher />

{@render children?.()}
