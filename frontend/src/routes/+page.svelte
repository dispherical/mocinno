<script lang="ts">
	import { browser } from '$app/env';
	import { page } from '$app/state';
	import authClient from '$lib/auth';

	import Head from '$lib/components/head.svelte';

	if (browser) {
		authClient.signIn.oauth2({
			providerId: 'hackclub',
			callbackURL: '/dashboard',
			additionalData: {
				invite_code: page.url.searchParams.get('invite')
			}
		});
	}
</script>

<Head title="Login" />
