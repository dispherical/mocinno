import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, url }) => {
	if (locals.session && !url.searchParams.get('invite')) {
		redirect(302, '/dashboard');
	}
};
