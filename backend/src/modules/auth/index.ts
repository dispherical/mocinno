import { betterAuth } from 'better-auth/minimal';
import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { bearer, genericOAuth } from 'better-auth/plugins';
import { db, schema } from '@/db';

import {
	ENCRYPTION_KEY,
	APP_DOMAIN,
	APP_SECURE,
	OAUTH_CLIENT_ID,
	OAUTH_CLIENT_SECRET
} from '@/env';

export const auth = betterAuth({
	secret: ENCRYPTION_KEY,
	baseURL: {
		allowedHosts: ['dashboard.hackclub.app', 'dashboard.nest.hackclub.com', APP_DOMAIN || ''],
		protocol: APP_SECURE ? 'https' : 'http'
	},
	database: drizzleAdapter(db, {
		provider: 'pg',
		schema
	}),
	plugins: [
		bearer(),
		genericOAuth({
			config: [
				{
					providerId: 'hackclub',
					clientId: OAUTH_CLIENT_ID,
					clientSecret: OAUTH_CLIENT_SECRET,
					discoveryUrl: 'https://auth.hackclub.com/.well-known/openid-configuration'
				}
			]
		})
	],
	experimental: {
		joins: true
	},
	advanced: {
		cookiePrefix: 'mocinno',
		useSecureCookies: APP_SECURE
	},
	emailAndPassword: {
		enabled: false
	}
});
