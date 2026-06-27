import { betterAuth } from 'better-auth/minimal';
import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { bearer, genericOAuth } from 'better-auth/plugins';
import { createAuthMiddleware } from 'better-auth/api';
import { db, schema } from '@/db';
import { eq } from 'drizzle-orm';

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
					discoveryUrl: 'https://auth.hackclub.com/.well-known/openid-configuration',
					scopes: ['openid', 'profile', 'email', 'verification_status', 'slack_id']
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
	hooks: {
		after: createAuthMiddleware(async (ctx) => {
			switch (true) {
				case ctx.path.startsWith('/oauth2/callback'): {
					if (!ctx.context.newSession) {
						break;
					}

					if (!ctx.request) {
						break;
					}

					const accounts = await ctx.context.internalAdapter.findAccountByUserId(
						ctx.context.newSession.user.id
					);

					const hca = accounts.find((account) => account.providerId === 'hackclub');

					if (!hca) {
						break;
					}

					const container = await db.query.containersTable.findFirst({
						where: (containersTable, { eq }) => eq(containersTable.sub, hca.accountId)
					});

					if (container) {
						await db
							.update(schema.containersTable)
							.set({
								user_id: ctx.context.newSession.user.id,
								sub: null
							})
							.where(eq(schema.containersTable.id, container.id));
					}

					const applications = await db.query.applicationsTable.findMany({
						where: (applicationsTable, { eq }) => eq(applicationsTable.sub, hca.accountId)
					});

					for (const application of applications) {
						await db
							.update(schema.applicationsTable)
							.set({
								user_id: ctx.context.newSession.user.id,
								sub: null,
								email: null
							})
							.where(eq(schema.applicationsTable.id, application.id));
					}

					break;
				}
			}
		})
	}
});
