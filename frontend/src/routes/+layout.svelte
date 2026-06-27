<script lang="ts">
	import './layout.css';
	import { ModeWatcher } from 'mode-watcher';

	let { children } = $props();
</script>

<svelte:head
	><link
		rel="icon"
		type="image/svg+xml"
		href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>📦</text></svg>"
	/></svelte:head
>

<ModeWatcher />

{@render children?.()}
