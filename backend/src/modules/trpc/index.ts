import { initTRPC, TRPCError } from '@trpc/server';

import { auth } from '@/modules/auth';
import superjson from 'superjson';

interface TRPCContext {
	session: typeof auth.$Infer.Session.session | null;
	user: typeof auth.$Infer.Session.user | null;
}

/**
 * Initialization of tRPC backend
 * Should be done only once per backend!
 */
const t = initTRPC.context<TRPCContext>().create({
	transformer: superjson
});

/**
 * Export reusable router and procedure helpers
 * that can be used throughout the router
 */
export const router = t.router;
export const publicProcedure = t.procedure;

export const authedProcedure = publicProcedure.use(async (opts) => {
	const { ctx } = opts;

	if (!ctx.session || !ctx.user) {
		throw new TRPCError({
			code: 'UNAUTHORIZED',
			message: 'You must be logged in to access this resource.'
		});
	}

	return opts.next({
		ctx: {
			...ctx,
			user: ctx.user,
			session: ctx.session
		}
	});
});
