import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';
import { z } from 'zod';

import userRouter from './user';
import adminRouter from './admin';
import { checkUsername } from '@/utils';

export const appRouter = router({
	authTest: authedProcedure.query(async ({ ctx }) => {
		return `You are authenticated as ${ctx.user.name}`;
	}),
	checkUsername: authedProcedure.input(z.string()).query(async ({ input }) => {
		return await checkUsername(input);
	}),
	user: userRouter,
	admin: adminRouter
});

export type AppRouter = typeof appRouter;
