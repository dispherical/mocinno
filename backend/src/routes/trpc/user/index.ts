import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';

import { db } from '@/db';
import { getContainerStatus } from '@/pve-utils';

const userRouter = router({
	container: authedProcedure.query(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return null;
		}

		const status = await getContainerStatus(container);

		return { ...container, status };
	})
});

export default userRouter;
