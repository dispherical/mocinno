import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';

export const appRouter = router({
	authTest: authedProcedure.query(async ({ ctx }) => {
		return `You are authenticated as ${ctx.user.name}`;
	})
});

export type AppRouter = typeof appRouter;
