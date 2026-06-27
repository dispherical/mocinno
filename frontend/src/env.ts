import { defineEnvVars } from '@sveltejs/kit/hooks';

export const variables = defineEnvVars({
	APP_DOMAIN: {
		public: true
	},
	APP_SECURE: {
		public: true
	}
});
