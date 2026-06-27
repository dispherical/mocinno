import { createAuthClient } from 'better-auth/svelte';
import { genericOAuthClient } from 'better-auth/client/plugins';

const authClient = createAuthClient({
	plugins: [genericOAuthClient()]
});

export default authClient;
