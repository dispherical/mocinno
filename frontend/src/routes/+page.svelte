<script lang="ts">
	import { browser } from '$app/env';
	import authClient from '$lib/auth';

	if (browser) {
		authClient.signIn.oauth2({
			providerId: 'hackclub',
			callbackURL: '/dashboard'
		});
	}
</script>
