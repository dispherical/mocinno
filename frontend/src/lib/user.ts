import { createContext } from 'svelte';
import authClient from './auth';

export const [getUserContext, setUserContext] =
	createContext<() => typeof authClient.$Infer.Session.user>();
