import { z } from 'zod';

export const formSchema = z.object({
	username: z.string(),
	sshKey: z.string(),
	reason: z.string().min(10, 'Reason must be at least 10 characters long.'),
	template: z.string()
});

export type FormSchema = typeof formSchema;
