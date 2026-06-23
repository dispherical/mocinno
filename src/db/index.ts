import { drizzle } from "drizzle-orm/bun-sql";
import { sql } from "bun";
import * as schema from "./schema";

export const db = drizzle({ client: sql, schema });

export { schema };
