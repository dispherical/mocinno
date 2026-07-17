<script lang="ts">
	import * as Table from '$lib/components/ui/table/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Spinner } from '$lib/components/ui/spinner/index.js';
	import type { RouterOutput } from '$lib/trpc';
	import trpc from '$lib/trpc';
	import { invalidateAll } from '$app/navigation';
	import * as Form from '$lib/components/ui/form/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import * as Alert from '$lib/components/ui/alert/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import AlertCircleIcon from '@lucide/svelte/icons/alert-circle';
	import CheckCircle2Icon from '@lucide/svelte/icons/check-circle-2';
	import { formSchema, type FormSchema } from './schema';
	import { type SuperValidated, type Infer, superForm } from 'sveltekit-superforms';
	import { zod4Client } from 'sveltekit-superforms/adapters';

	type Domains = RouterOutput['user']['domains'];
	type Container = RouterOutput['user']['container'];

	let {
		domains,
		container,
		form: initialForm
	}: { domains: Domains; container: Container; form: SuperValidated<Infer<FormSchema>> } = $props();

	const removeDomain = async (domain: string) => {
		await trpc.user.removeDomain.mutate({ domain });
		await invalidateAll();
	};

	const form = $derived.by(() =>
		superForm(initialForm, {
			validators: zod4Client(formSchema)
		})
	);

	// svelte-ignore state_referenced_locally
	const { form: formData, enhance, message, errors, submitting } = form;
</script>

<div class="flex flex-1 flex-col gap-4">
	<h2 class="text-2xl font-bold tracking-tight">Domains</h2>
	<p class="text-muted-foreground mt-1">
		From here you may configure custom domains to point towards your container.
	</p>
	<Separator class="my-4" />
	<Table.Root class="border-border border rounded-lg overflow-hidden shadow-sm bg-muted/25">
		<Table.Header>
			<Table.Row>
				<Table.Head>Domain</Table.Head>
				<Table.Head class="text-end">Target Port</Table.Head>
				<Table.Head class="text-end">Actions</Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each domains as domain (domain.id)}
				<Table.Row>
					<Table.Cell class="font-medium">{domain.domain}</Table.Cell>
					<Table.Cell class="text-right">{domain.proxy}</Table.Cell>
					<Table.Cell class="text-end">
						<Button variant="outline" size="sm" onclick={() => removeDomain(domain.domain)}>
							Remove
						</Button>
					</Table.Cell>
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={3} class="text-center text-muted-foreground">
						No domains found.
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>

	<Card.Root class="container w-full flex-1 flex-col my-4">
		<form use:enhance method="POST">
			<Card.Content>
				{#if $errors._errors || $message}
					<Alert.Root variant={$errors._errors ? 'destructive' : 'default'} class="mb-4">
						{#if $errors._errors}<AlertCircleIcon />
						{:else}
							<CheckCircle2Icon />
						{/if}
						<Alert.Description>
							<ul class="list-inside list-disc text-sm">
								{#each $errors._errors as error (error)}
									<li>{error}</li>
								{/each}
								{#if $message}
									<li>{$message}</li>
								{/if}
							</ul>
						</Alert.Description>
					</Alert.Root>
				{/if}
				<div class="flex items-start gap-x-4">
					<div class="grid gap-3 space-y-1 w-64 mb-2">
						<Form.Field {form} name="domain">
							<Form.Control>
								{#snippet children({ props })}
									<Form.Label>Domain</Form.Label>
									<Input {...props} bind:value={$formData.domain} />
								{/snippet}
							</Form.Control>
							<Form.FieldErrors />
						</Form.Field>
					</div>
					<div class="grid gap-3 space-y-1 flex-1 mb-2">
						<Form.Field {form} name="proxy">
							<Form.Control>
								{#snippet children({ props })}
									<Form.Label>Target Port</Form.Label>
									<Input type="number" {...props} bind:value={$formData.proxy} />
								{/snippet}
							</Form.Control>
							<Form.Description
								>Must be 3-32 characters: letters, numbers, hyphens.</Form.Description
							>
							<Form.FieldErrors />
						</Form.Field>
					</div>
				</div></Card.Content
			>
			<Card.Footer class="flex w-full items-center gap-2">
				<span
					>You'll need to point your domain to {container?.username}.hackclub.app to use this!</span
				>
				<Form.Button class="w-full sm:ms-auto sm:w-auto" disabled={$submitting}
					>{#if $submitting}<Spinner />
					{/if} Add Domain</Form.Button
				>
			</Card.Footer>
		</form>
	</Card.Root>
</div>
