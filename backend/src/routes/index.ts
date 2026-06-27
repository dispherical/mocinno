import { route } from '@/middleware';
import { auth } from '@/modules/auth';

import adminRoutes from './admin';
import authRoutes from './auth';
import userRoutes from './user';
import publicRoutes from './public';
import applicationRoutes from './application';
import internalRoutes from './internal';

const app = route.createApp().basePath('/api');

app.use('*', async (c, next) => {
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
});

app.on(['POST', 'GET'], '/auth/*', (c) => {
	return auth.handler(c.req.raw);
});

app.route('/admin', adminRoutes);
app.route('/authorization', authRoutes);
app.route('/user', userRoutes);
app.route('/public', publicRoutes);
app.route('/application', applicationRoutes);
app.route('/internal', internalRoutes);

export default app;
