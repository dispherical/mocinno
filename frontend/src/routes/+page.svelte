<script lang="ts">
	import { browser } from '$app/env';
	import authClient from '$lib/auth';

	import Head from '$lib/components/Head.svelte';

	if (browser) {
		authClient.signIn.oauth2({
			providerId: 'hackclub',
			callbackURL: '/dashboard',
			additionalData: {
				invite: null
			}
		});
	}
</script>

<Head title="Login" />
