import { route } from "@/middleware";
import { getNodeStats } from "@/pve-utils";
import { db, schema } from "@/db/index";
import { count } from "drizzle-orm";

type NodeStats = Awaited<ReturnType<typeof getNodeStats>>;

interface StatStructure {
  users: number;
  nodes: Record<string, NodeStats>;
}

// I'm not requesting stats on startup, while I could I feel that's not a good idea - Laura
let nodeStats: StatStructure | null = null;

// requests every 3 minutes, clarification because cron expressions can be confusing
Bun.cron("*/3 * * * *", async () => {
  try {
    const config = await import("config");

    const nodes = config.default.servers.map((s) => s.node);

    const stats = await Promise.all(
      nodes.map(async (node) => {
        const stats = await getNodeStats(node);
        return { name: node, stats };
      }),
    );

    const rowCount = await db
      .select({ count: count() })
      .from(schema.usersTable);

    nodeStats = {
      users: rowCount[0]?.count ?? 271, // user count captured on 27/04/2026 at 23:33 EEST
      nodes: Object.fromEntries(stats.map(({ name, stats }) => [name, stats])),
    };
  } catch (err) {
    if (err instanceof Error) {
      console.error("Failed to update node stats:", err.message);
      return;
    }
    console.error("Failed to update node stats:", err);
  }
});

const app = route.createApp();

app.get("/api/stats", async (c) => {
  if (!nodeStats) {
    c.status(404);
    return c.json({
      error: "Stats not available yet, please try again later.",
    });
  }

  return c.json(nodeStats);
});

export default app;
