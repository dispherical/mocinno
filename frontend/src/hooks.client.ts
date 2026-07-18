import * as Sentry from '@sentry/sveltekit';
import { SENTRY_DSN } from '$app/env/public';

Sentry.init({
	dsn: SENTRY_DSN,
	dataCollection: {
		// To disable sending user data and HTTP bodies, uncomment the lines below. For more info visit:
		// https://docs.sentry.io/platforms/javascript/guides/sveltekit/configuration/options/#dataCollection
		// userInfo: false,
		// httpBodies: [],
	},

	// Set tracesSampleRate to 1.0 to capture 100%
	// of transactions for tracing.
	// We recommend adjusting this value in production
	// Learn more at
	// https://docs.sentry.io/platforms/javascript/configuration/options/#traces-sample-rate
	tracesSampleRate: 1.0,
	integrations: [Sentry.replayIntegration(), Sentry.browserProfilingIntegration()],

	// Capture Replay for 10% of all sessions,
	// plus for 100% of sessions with an error
	// Learn more at
	// https://docs.sentry.io/platforms/javascript/session-replay/configuration/#general-integration-configuration
	replaysSessionSampleRate: 0.1,
	replaysOnErrorSampleRate: 1.0
});

export const handleError = Sentry.handleErrorWithSentry();
