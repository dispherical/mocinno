import type { PageServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';

import trpc from '$lib/server/trpc';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.session) {
		redirect(303, '/');
	}

	const container = await trpc.user.container.query();

	if (!container) {
		redirect(303, '/application');
	}

	return {
		authTest: trpc.authTest.query(),
		container
	};
};
