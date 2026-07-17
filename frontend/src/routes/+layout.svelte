<script lang="ts">
	import './layout.css';
	import '$lib/theme.css';
	import { ModeWatcher } from 'mode-watcher';

	let { children } = $props();
</script>

<svelte:head
	><link
		rel="icon"
		type="image/svg+xml"
		href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>📦</text></svg>"
	/>
	<script>
		(function () {
			const root = document.documentElement;
			const storageKey = 'mode-watcher-theme';

			const applyThemeClass = (theme) => {
				if (theme) {
					root.classList.add(theme);
				}
			};

			applyThemeClass(localStorage.getItem(storageKey));

			new MutationObserver(() => {
				applyThemeClass(root.getAttribute('data-theme'));
			}).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
		})();
	</script></svelte:head
>

<ModeWatcher defaultTheme="catppuccin-macchiato" />

{@render children?.()}
