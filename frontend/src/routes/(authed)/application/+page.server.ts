import type { PageServerLoad, Actions } from './$types.js';
import { fail } from '@sveltejs/kit';
import { superValidate, message, setError } from 'sveltekit-superforms';
import { formSchema } from './schema';
import trpc from '$lib/server/trpc';
import { zod4 } from 'sveltekit-superforms/adapters';

export const load: PageServerLoad = async () => {
	const templates = await trpc.application.getTemplates.query();

	return {
		form: await superValidate({ template: templates[0] }, zod4(formSchema), { errors: false }),
		eligible: await trpc.application.checkEligible.query(),
		templates,
		application: await trpc.application.getApplication.query()
	};
};

export const actions: Actions = {
	default: async (event) => {
		const form = await superValidate(event, zod4(formSchema));
		if (!form.valid) {
			return fail(400, {
				form
			});
		}

		try {
			const updateResult = await trpc.application.submitApplication.mutate({
				username: form.data.username,
				sshKey: form.data.sshKey,
				reason: form.data.reason,
				template: form.data.template
			});

			if (!updateResult.success) {
				return setError(form, updateResult.message || 'Failed to submit application.');
			}
			return message(form, updateResult.message);
		} catch (err) {
			console.error('Error submitting applitcation:', err);
			return fail(500, {
				form,
				message: 'An error occurred while submitting application.'
			});
		}
	}
};
