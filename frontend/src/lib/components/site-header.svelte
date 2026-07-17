<script lang="ts">
	import { resolve } from '$app/paths';
	import * as NavigationMenu from '$lib/components/ui/navigation-menu/index.js';
	import { navigationMenuTriggerStyle } from '$lib/components/ui/navigation-menu/navigation-menu-trigger.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import { getContainerContext } from '$lib/user';
	import { setTheme } from 'mode-watcher';

	let { admin }: { admin: boolean } = $props();

	const container = getContainerContext()();
</script>

<header class="bg-background sticky top-0 z-50 flex w-full items-center border-b">
	<div class="flex h-(--header-height) w-full items-center gap-2 px-4">
		<span class="font-bold">Nest</span>
		<NavigationMenu.Root>
			<NavigationMenu.List>
				{#if container}
					<NavigationMenu.Item>
						<NavigationMenu.Link>
							{#snippet child()}
								<a href={resolve('/(authed)/dashboard')} class={navigationMenuTriggerStyle()}
									>Dashboard</a
								>
							{/snippet}
						</NavigationMenu.Link>
					</NavigationMenu.Item>
					<NavigationMenu.Item>
						<NavigationMenu.Link>
							{#snippet child()}
								<a
									href={resolve('/(authed)/dashboard/domains')}
									class={navigationMenuTriggerStyle()}>Domains</a
								>
							{/snippet}
						</NavigationMenu.Link>
					</NavigationMenu.Item>
					<NavigationMenu.Item>
						<NavigationMenu.Link>
							{#snippet child()}
								<a href={resolve('/(authed)/dashboard/keys')} class={navigationMenuTriggerStyle()}
									>Keys</a
								>
							{/snippet}
						</NavigationMenu.Link>
					</NavigationMenu.Item>
					<NavigationMenu.Item>
						<NavigationMenu.Link>
							{#snippet child()}
								<a
									href={resolve('/(authed)/dashboard/backups')}
									class={navigationMenuTriggerStyle()}>Backups</a
								>
							{/snippet}
						</NavigationMenu.Link>
					</NavigationMenu.Item>
				{:else}
					<NavigationMenu.Item>
						<NavigationMenu.Link>
							{#snippet child()}
								<a href={resolve('/(authed)/application')} class={navigationMenuTriggerStyle()}
									>Apply</a
								>
							{/snippet}
						</NavigationMenu.Link>
					</NavigationMenu.Item>
				{/if}
			</NavigationMenu.List>
		</NavigationMenu.Root>
		<div class="w-full sm:ms-auto sm:w-auto">
			<Button onclick={() => setTheme('catppuccin-macchiato')} class="cursor-pointer"
				>Set theme to Catppuccin Macchiato</Button
			>
			{#if admin}
				<Button href={resolve('/(authed)/admin')}>Admin Panel</Button>
			{/if}
		</div>
	</div>
</header>
