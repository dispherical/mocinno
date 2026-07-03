<script lang="ts">
	import { resolve } from '$app/paths';
	import * as NavigationMenu from '$lib/components/ui/navigation-menu/index.js';
	import { navigationMenuTriggerStyle } from '$lib/components/ui/navigation-menu/navigation-menu-trigger.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
</script>

<header class="bg-background sticky top-0 z-50 flex w-full items-center border-b">
	<div class="flex h-(--header-height) w-full items-center gap-2 px-4">
		<span class="font-bold">Nest</span>
		<NavigationMenu.Root>
			<NavigationMenu.List>
				<NavigationMenu.Item>
					<NavigationMenu.Link>
						{#snippet child()}
							<a href={resolve('/(authed)/dashboard')} class={navigationMenuTriggerStyle()}
								>Dashboard</a
							>
						{/snippet}
					</NavigationMenu.Link>
				</NavigationMenu.Item>
			</NavigationMenu.List>
		</NavigationMenu.Root>
		<div class="w-full sm:ms-auto sm:w-auto">
			<Button href={resolve('/(authed)/admin')}>Admin Panel</Button>
		</div>
	</div>
</header>
