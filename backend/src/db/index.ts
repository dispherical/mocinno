//import { drizzle } from "drizzle-orm/bun-sql";
import { drizzle } from 'drizzle-orm/node-postgres';
//import { sql } from "bun";
import * as schema from './schema';

export const db = drizzle({ schema });
//export const db = drizzle({ client: sql, schema });

export { schema };
