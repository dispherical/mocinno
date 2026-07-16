<script lang="ts">
	import { resolve } from '$app/paths';
	import * as NavigationMenu from '$lib/components/ui/navigation-menu/index.js';
	import { navigationMenuTriggerStyle } from '$lib/components/ui/navigation-menu/navigation-menu-trigger.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import authClient from '$lib/auth';
	import { getContainerContext } from '$lib/user';
	import { setTheme } from 'mode-watcher';

	let { user }: { user: typeof authClient.$Infer.Session.user } = $props();

	const container = getContainerContext()();
</script>

<header class="bg-background sticky top-0 z-50 flex w-full items-center border-b">
	<div class="flex h-(--header-height) w-full items-center gap-2 px-4">
		<span class="font-bold">Nest</span>
		{#if container}
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
				</NavigationMenu.List>
			</NavigationMenu.Root>
		{/if}
		<div class="w-full sm:ms-auto sm:w-auto">
			<span>{user.name}</span>
			<Button onclick={() => setTheme('catppuccin-macchiato')} class="cursor-pointer"
				>Set theme to Catppuccin Macchiato</Button
			>
			<Button href={resolve('/(authed)/admin')}>Admin Panel</Button>
		</div>
	</div>
</header>
