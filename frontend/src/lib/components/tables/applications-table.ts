import type { ColumnDef } from '@tanstack/table-core';
import { renderComponent } from '$lib/components/ui/data-table/index.js';
import ApplicationsTableActions from './applications-table-actions.svelte';
import { type RouterOutput } from '$lib/trpc';

export const columns: ColumnDef<RouterOutput['admin']['getApplications']['all'][number]>[] = [
	{
		accessorFn: (row) => row.user?.email ?? row.email,
		header: 'Email'
	},
	{
		accessorKey: 'username',
		header: 'Username'
	},
	{
		accessorKey: 'reason',
		header: 'Reason'
	},
	{
		accessorFn: (row) => row.created_at?.toDateString(),
		header: 'Submitted'
	},
	{
		id: 'actions',
		cell: ({ row }) => {
			return renderComponent(ApplicationsTableActions, {
				id: row.original.id,
				status: row.original.status as 'pending' | 'approved' | 'rejected'
			});
		},
		header: 'Actions'
	}
];
