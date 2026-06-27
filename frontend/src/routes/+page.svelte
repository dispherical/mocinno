<script lang="ts">
	import Head from '$lib/components/Head.svelte';
	import { Button } from '$lib/components/ui/button/index.js';

	import authClient from '$lib/auth';
</script>

<Head title="Home" />

<div class="p-6 lg:p-10 max-w-3xl mx-auto">
	<div class="space-y-4">
		<h1 class="text-2xl font-bold tracking-tight">Nest</h1>
		<p class="text-muted-foreground">
			Hack Club Nest is a free Linux server from Hack Club. You can host Discord bots, apps,
			websites, try out basic computer networking, chat with others and more!
		</p>
		<p class="text-muted-foreground">
			From here you may register for an account on Hack Club Nest.
		</p>
		<div class="pt-2">
			<Button
				size="lg"
				onclick={() => {
					authClient.signIn.oauth2({
						providerId: 'hackclub',
						callbackURL: '/dashboard'
					});
				}}>Go to login</Button
			>
		</div>
	</div>
</div>
