import type { PageServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { setFlash } from 'sveltekit-flash-message/server';

export const load: PageServerLoad = async ({ parent, locals, cookies }) => {
	const { container } = await parent();

	if (!container) {
		redirect(303, '/application');
	}

	if (locals.session?.sudo) {
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
		container
	};
};
