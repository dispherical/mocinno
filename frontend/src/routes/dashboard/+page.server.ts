import type { PageServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';

import trpc from '$lib/server/trpc';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.session) {
		redirect(303, '/');
	}

	return {
		authTest: await trpc.authTest.query()
	};
};
