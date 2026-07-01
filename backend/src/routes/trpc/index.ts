import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';

import userRouter from './user';
import adminRouter from './admin';
import applicationRouter from './application';

export const appRouter = router({
	authTest: authedProcedure.query(async ({ ctx }) => {
		return `You are authenticated as ${ctx.user.name}`;
	}),
	user: userRouter,
	admin: adminRouter,
	application: applicationRouter
});

export type AppRouter = typeof appRouter;
