import { CookieStore, sessionMiddleware } from 'hono-sessions';
import * as env from './env';
import { serveStatic } from 'hono/bun';
import { route } from './middleware';
import { Liquid } from 'liquidjs';

import '@/proxy/index.ts';

import webRoutes from '@/routes/web';
import routes from '@/routes';
import type { Serve } from 'bun';

const app = route.createApp();

app.get('/privacy.pdf', serveStatic({ path: './src/public/privacy.pdf' }));

const store = new CookieStore();

app.use(
	'*',
	sessionMiddleware({
		store,
		encryptionKey: env.ENCRYPTION_KEY,
		expireAfterSeconds: 900,
		autoExtendExpiration: true,
		cookieOptions: {
			sameSite: 'Lax',
			path: '/',
			httpOnly: true
		}
	})
);

const engine = new Liquid({
	root: './views',
	extname: '.liquid',
	outputEscape: 'escape',
	cache: process.env.NODE_ENV == 'production'
});

app.use('*', async (c, next) => {
	c.set('engine', engine);
	const session = c.get('session');

	// allowing sudo mode in development without 2fa
	if (process.env.NODE_ENV !== 'production') session.flash('sudo', true);
	await next();
});

app.route('', webRoutes);
app.route('', routes);

process.on('uncaughtException', (error) => {
	console.error(error);
});

process.on('unhandledRejection', (error) => {
	console.error(error);
});

export default {
	...app,
	port: env.MOCINNO_PORT,
	maxRequestBodySize: env.MOCINNO_MAX_BODY_REQUEST_SIZE,
	hostname: env.MOCINNO_HOSTNAME,
	idleTimeout: 30
};
