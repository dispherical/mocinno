import { router } from '@/modules/trpc';
import { adminProcedure } from '@/modules/trpc';

import { z } from 'zod';
import { db, schema } from '@/db';
import { desc, eq, or, inArray, sql, ilike, count } from 'drizzle-orm';
import { CONFIG } from '@/env';
import {
	disableStartOnBoot,
	enableStartOnBoot,
	getContainerStatus,
	getNodeStats,
	isContainerSuspended,
	pveFetch,
	setContainerDescription,
	waitForTask
} from '@/pve-utils';
import type { NodeLXCStatusStop } from '@/types';

let nodeStats:
	| {
			name: string;
			stats: Awaited<ReturnType<typeof getNodeStats>>;
	  }[]
	| null = null;

async function requestNodeStats() {
	try {
		const nodes = CONFIG.servers.map((s) => s.node);

		const stats = await Promise.all(
			nodes.map(async (node) => {
				const stats = await getNodeStats(node);
				return { name: node, stats };
			})
		);

		nodeStats = stats;
	} catch (err) {
		if (err instanceof Error) {
			console.error('Failed to update admin node stats:', err.message);
			return;
		}
		console.error('Failed to update admin node stats:', err);
	}
}

// Every min
Bun.cron('* * * * *', requestNodeStats);

const adminRouter = router({
	getStats: adminProcedure.query(async () => {
		if (!nodeStats) {
			await requestNodeStats();
		}

		return nodeStats;
	}),
	getContainers: adminProcedure
		.input(
			z.object({
				query: z.string().optional(),
				page: z.number().min(1).optional().default(1),
				limit: z.number().optional().default(10)
			})
		)
		.query(async ({ input }) => {
			const offset = (input.page - 1) * input.limit;

			const queryLike = `%${input.query || ''}%`;

			const containers = await db.query.containersTable.findMany({
				limit: input.limit,
				offset,
				where: or(
					ilike(schema.containersTable.username, queryLike),
					ilike(schema.containersTable.ip, queryLike),
					ilike(sql`CAST(${schema.containersTable.vmid} AS TEXT)`, queryLike),
					inArray(
						schema.containersTable.user_id,
						db
							.select({ id: schema.user.id })
							.from(schema.user)
							.where(ilike(schema.user.email, queryLike))
					)
				),
				orderBy: [desc(schema.containersTable.created_at)]
			});

			const usersWithStatus: Array<
				(typeof containers)[number] & {
					status: Awaited<ReturnType<typeof getContainerStatus>>;
					suspended: boolean;
				}
			> = [];

			for (const container of containers) {
				let status = null;
				let suspended = false;
				if (container.vmid) {
					status = await getContainerStatus(container);
					suspended = await isContainerSuspended(container);
				}
				usersWithStatus.push({ ...container, status, suspended });
			}

			const rowQuery = await db
				.select({ value: count() })
				.from(schema.containersTable)
				.where(
					or(
						ilike(schema.containersTable.username, queryLike),
						ilike(schema.containersTable.ip, queryLike),
						ilike(sql`CAST(${schema.containersTable.vmid} AS TEXT)`, queryLike),
						inArray(
							schema.containersTable.user_id,
							db
								.select({ id: schema.user.id })
								.from(schema.user)
								.where(ilike(schema.user.email, queryLike))
						)
					)
				);

			let totalContainers = 0;

			if (rowQuery[0]) {
				totalContainers = Number(rowQuery[0].value);
			}

			const pageCount = Math.max(1, Math.ceil(totalContainers / input.limit));

			if (input.page > pageCount) {
				input.page = pageCount;
			}

			return { data: usersWithStatus, count: totalContainers, pageCount };
		}),
	getApplications: adminProcedure
		.input(
			z.object({
				query: z.string().optional(),
				page: z.number().min(1).optional().default(1),
				limit: z.number().optional().default(50)
			})
		)
		.query(async ({ input }) => {
			const offset = (input.page - 1) * input.limit;

			const applications = await db.query.applicationsTable.findMany({
				limit: input.limit,
				offset,
				orderBy: [desc(schema.applicationsTable.created_at)]
			});

			const pendingApplications = await db.query.applicationsTable.findMany({
				where: eq(schema.applicationsTable.status, 'pending'),
				orderBy: [desc(schema.applicationsTable.created_at)]
			});

			return { applications, pendingApplications };
		}),
	getInvites: adminProcedure
		.input(
			z.object({
				query: z.string().optional(),
				page: z.number().min(1).optional().default(1),
				limit: z.number().optional().default(50)
			})
		)
		.query(async ({ input }) => {
			const offset = (input.page - 1) * input.limit;

			const invites = await db.query.invitesTable.findMany({
				limit: input.limit,
				offset,
				orderBy: [desc(schema.invitesTable.code)]
			});

			return invites;
		}),
	toggleSuspend: adminProcedure
		.input(z.object({ id: z.int(), reason: z.string().optional().default('Suspended by admin') }))
		.mutation(async ({ input }) => {
			const container = await db.query.containersTable.findFirst({
				where: eq(schema.containersTable.id, input.id)
			});

			if (!container || !container.vmid) {
				return { success: false, message: 'Container not found' };
			}

			const suspended = await isContainerSuspended(container);

			setTimeout(requestNodeStats, 0);
			if (!suspended) {
				await setContainerDescription(container, `suspend: ${input.reason}`);
				await disableStartOnBoot(container);

				try {
					const status = await getContainerStatus(container);
					if (status?.status === 'running') {
						const stopResult = await pveFetch<{ data: NodeLXCStatusStop }>(
							`/nodes/${container.node}/lxc/${container.vmid}/status/stop`,
							'POST'
						);
						await waitForTask(container.node, stopResult.data);
					}
				} catch {
					// Ignore
				}

				return { success: true, message: `Container ${container.vmid} suspended` };
			} else {
				await setContainerDescription(container, '');
				await enableStartOnBoot(container);

				return { success: true, message: `Container ${container.vmid} unsuspended` };
			}
		})
});

export default adminRouter;
