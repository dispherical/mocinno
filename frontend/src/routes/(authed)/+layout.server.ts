import type { LayoutServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';

import trpc from '$lib/server/trpc';

export const load: LayoutServerLoad = async ({ locals }) => {
	if (!locals.session || !locals.user) {
		redirect(303, '/');
	}

	const container = await trpc.user.container.query();

	return {
		session: {
			user: locals.user,
			session: locals.session
		},
		container
	};
};
