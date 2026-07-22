import { route } from '@/middleware';
import { auth } from '@/modules/auth';
import { trpcServer } from '@hono/trpc-server';

//import adminRoutes from './admin';
//import authRoutes from './auth';
//import userRoutes from './user';
import publicRoutes from './public';
//import applicationRoutes from './application';
import internalRoutes from './internal';

import { appRouter } from './trpc';

const app = route.createApp().basePath('/api');

app.use('*', async (c, next) => {
	try {
		const session = await auth.api.getSession({ headers: c.req.raw.headers });
		if (!session) {
			c.set('user', null);
			c.set('sessionNew', null);
			await next();
			return;
		}
		c.set('user', session.user);
		c.set('sessionNew', session.session);
		await next();
	} catch (error) {
		console.error(error);
		await next();
	}
});

app.on(['POST', 'GET'], '/auth/*', (c) => {
	return auth.handler(c.req.raw);
});

// The hackclub OAuth callback is exposed at /api/authorization/goalpost (see
// OAUTH_REDIRECT_URI in modules/auth). Forward it to better-auth's internal
// callback handler at /api/auth/oauth2/callback/hackclub.
app.get('/authorization/goalpost', (c) => {
	const url = new URL(c.req.raw.url);
	url.pathname = '/api/auth/oauth2/callback/hackclub';
	return auth.handler(new Request(url, c.req.raw));
});

app.use(
	'/trpc/*',
	trpcServer({
		endpoint: '/api/trpc',
		router: appRouter,
		createContext: (opts, c) => ({
			session: c.get('sessionNew'),
			user: c.get('user'),
			headers: c.req.raw.headers
		})
	})
);

//app.route('/admin', adminRoutes);
//app.route('/authorization', authRoutes);
//app.route('/user', userRoutes);
app.route('/public', publicRoutes);
//app.route('/application', applicationRoutes);
app.route('/internal', internalRoutes);

export default app;
