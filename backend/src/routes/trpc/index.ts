import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';
import * as dbHelpers from '@/db-helpers';

import userRouter from './user';
import adminRouter from './admin';
import applicationRouter from './application';

export const appRouter = router({
	isAdmin: authedProcedure.query(async ({ ctx }) => {
		return dbHelpers.isAdmin(ctx.user.email);
	}),
	user: userRouter,
	admin: adminRouter,
	application: applicationRouter
});

export type AppRouter = typeof appRouter;
