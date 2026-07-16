import { router } from '@/modules/trpc';
import { authedProcedure } from '@/modules/trpc';

import { db, schema } from '@/db';
import { eq } from 'drizzle-orm';
import * as dbHelpers from '@/db-helpers';
import { getContainerStatus, isContainerSuspended, pveFetch, waitForTask } from '@/pve-utils';
import { auth } from '@/modules/auth';

import type {
	Backup,
	NodeLXCDelete,
	NodeLXCPost,
	NodeLXCStatusReboot,
	NodeLXCStatusStart,
	NodeLXCStatusStop
} from '@/types/pve';

const userRouter = router({
	container: authedProcedure.query(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return null;
		}

		const status = await getContainerStatus(container);

		const suspended = await isContainerSuspended(container);

		return { ...container, status, suspended };
	}),
	start: authedProcedure.mutation(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return {
				success: false,
				message: 'No container found'
			};
		}

		if (await isContainerSuspended(container)) {
			return {
				success: false,
				message: 'Your container is suspended. Contact an admin.'
			};
		}

		const result = await pveFetch<{ data: NodeLXCStatusStart }>(
			`/nodes/${container.node}/lxc/${container.vmid}/status/start`,
			'POST'
		);
		await waitForTask(container.node, result.data);

		return {
			success: true,
			message: 'Container started'
		};
	}),
	stop: authedProcedure.mutation(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return {
				success: false,
				message: 'No container found'
			};
		}

		if (await isContainerSuspended(container)) {
			return {
				success: false,
				message: 'Your container is suspended. Contact an admin.'
			};
		}

		const result = await pveFetch<{ data: NodeLXCStatusStart }>(
			`/nodes/${container.node}/lxc/${container.vmid}/status/stop`,
			'POST'
		);
		await waitForTask(container.node, result.data);

		return {
			success: true,
			message: 'Container stopped'
		};
	}),
	reboot: authedProcedure.mutation(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return {
				success: false,
				message: 'No container found'
			};
		}

		if (await isContainerSuspended(container)) {
			return {
				success: false,
				message: 'Your container is suspended. Contact an admin.'
			};
		}

		const result = await pveFetch<{ data: NodeLXCStatusStart }>(
			`/nodes/${container.node}/lxc/${container.vmid}/status/reboot`,
			'POST'
		);
		await waitForTask(container.node, result.data);

		return {
			success: true,
			message: 'Container rebooted'
		};
	}),
	delete: authedProcedure.mutation(async ({ ctx }) => {
		const container = await db.query.containersTable.findFirst({
			where: (container, { eq }) => eq(container.user_id, ctx.user.id)
		});

		if (!container) {
			return {
				success: false,
				message: 'No container found'
			};
		}

		if (await isContainerSuspended(container)) {
			return {
				success: false,
				message: 'Your container is suspended. Contact an admin.'
			};
		}

		if (!ctx.session.sudo) {
			return {
				success: false,
				message: 'Sudo mode required'
			};
		}

		const status = await getContainerStatus(container);

		if (status?.status === 'running') {
			const stopResult = await pveFetch<{ data: NodeLXCStatusStop }>(
				`/nodes/${container.node}/lxc/${container.vmid}/status/stop`,
				'POST'
			);
			await waitForTask(container.node, stopResult.data);
		}

		const backups = await pveFetch<{ data: Backup[] }>(
			`/nodes/${container.node}/storage/pbs/content?vmid=${container.vmid}`,
			'GET'
		);

		await Promise.all(
			backups.data
				.filter((b) => b.content === 'backup')
				.map((b) =>
					pveFetch(
						`/nodes/${container.node}/storage/pbs/content/${encodeURIComponent(b.volid)}`,
						'DELETE'
					)
				)
		);

		const deleteResult = await pveFetch<{ data: NodeLXCDelete }>(
			`/nodes/${container.node}/lxc/${container.vmid}`,
			'DELETE'
		);

		await waitForTask(container.node, deleteResult.data);

		if (container.sub) {
			await dbHelpers.deleteUser(container.sub);
		} else {
			await db
				.delete(schema.containersTable)
				.where(eq(schema.containersTable.user_id, container.user_id!));
			await db
				.delete(schema.applicationsTable)
				.where(eq(schema.applicationsTable.user_id, ctx.user.id));
		}

		auth.api.updateSession({
			body: {
				sudo: false
			},
			headers: ctx.headers
		});

		return {
			success: true,
			message: 'Container deleted'
		};
	})
});

export default userRouter;
