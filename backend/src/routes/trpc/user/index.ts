import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';
import { z } from 'zod';

import { db } from '@/db';
import { auth } from '@/modules/auth';

import * as dbHelpers from '@/db-helpers';
import { checkUsername } from '@/utils';

const userRouter = router({
	container: authedProcedure.query(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return null;
		}

		return container;
	}),
	submitApplication: authedProcedure
		.input(
			z.object({
				username: z.string(),
				sshKey: z.string(),
				reason: z.string().min(10, 'Reason must be at least 10 characters long.'),
				template: z.string()
			})
		)
		.mutation(async ({ ctx, input }) => {
			const container = await db.query.containersTable.findFirst({
				where: (container, { eq }) => eq(container.user_id, ctx.user.id)
			});

			if (container) {
				return {
					success: false,
					message: 'You already have an account'
				};
			}

			const pendingApp = await dbHelpers.getApplicationByUserId(ctx.user.id);
			if (pendingApp?.status === 'pending') {
				return {
					success: false,
					message: 'You already have a pending application'
				};
			}

			let eligible = ctx.user.verification_status === 'verified';

			const inviteCode = ctx.session.invite_code;
			if (inviteCode && !eligible) {
				const invite = await dbHelpers.getInvite(inviteCode);
				if (
					invite &&
					(!invite.max_uses || invite.uses < invite.max_uses) &&
					(!invite.expires_at || new Date() <= new Date(invite.expires_at))
				) {
					eligible = true;
				}
			}

			if (!eligible) {
				return {
					success: false,
					message:
						'You are not eligible. You must be verified on auth.hackclub.com or have a valid invite code.'
				};
			}

			try {
				const result = await fetch(
					`https://hackatime.hackclub.com/api/v1/users/${ctx.user.slack_id}/trust_factor`,
					{
						headers: {
							'User-Agent': 'Nest/1.0 (+https://hackclub.app)'
						}
					}
				);

				if (!result.ok && result.status != 404) {
					console.error(
						`Failed to check hackatime ban status: ${result.status} - ${await result.text()}`
					);

					return {
						success: false,
						message: 'Failed to check hackatime ban status.'
					};
				}

				const data = (await result.json()) as {
					trust_level: string;
					trust_value: number;
				};

				if (data.trust_level === 'red') {
					return {
						success: false,
						message: 'You are not eligible for nest as you currently have a fraud ban.'
					};
				}
			} catch (e) {
				console.error('Error checking hackatime ban status:', e);

				return {
					success: false,
					message: 'Failed to check hackatime ban status.'
				};
			}

			if (input.sshKey.includes('PRIVATE KEY')) {
				return {
					success: false,
					message: 'SSH key cannot contain a private key.'
				};
			}

			const valid = await checkUsername(input.username);

			if (valid.allowed === false) {
				let message = 'Username is not allowed.';

				switch (valid.error) {
					case 'reserved':
						message = 'Username is reserved.';
						break;
					case 'invalid':
						message = 'Username is invalid.';
						break;
					case 'taken':
						message = 'Username is already taken.';
						break;
				}

				return {
					success: false,
					message
				};
			}

			const app = await dbHelpers.createApplication({
				user_id: ctx.user.id,
				username: input.username,
				sshKey: input.sshKey,
				reason: input.reason,
				template: input.template
			});

			if (inviteCode && ctx.user.verification_status !== 'verified') {
				await dbHelpers.incrementInvite(inviteCode);
				auth.api.updateSession({
					body: {
						invite_code: null
					},
					headers: ctx.headers
				});
			}

			return {
				success: true,
				message: 'Application submitted successfully.',
				application: app
			};
		})
});

export default userRouter;
