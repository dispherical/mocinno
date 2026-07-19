import type { LayoutServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { loadFlash } from 'sveltekit-flash-message/server';
import { setFlash } from 'sveltekit-flash-message/server';
import * as Sentry from '@sentry/sveltekit';

import trpc from '$lib/server/trpc';

export const load: LayoutServerLoad = loadFlash(async ({ locals, cookies }) => {
	if (!locals.session || !locals.user) {
		redirect(303, '/');
	}

	Sentry.setUser({
		id: locals.user.id,
		email: locals.user.email
	});

	const container = await trpc.user.container.query();

	if (locals.session?.sudo && !container?.suspended) {
		setFlash(
			{
				type: 'error',
				message:
					"You are currently in sudo mode. It allows one action, to confirm deletion press 'Delete Container' again."
			},
			cookies
		);
	}

	return {
		session: {
			user: locals.user,
			session: locals.session
		},
		container,
		admin: await trpc.isAdmin.query()
	};
});
