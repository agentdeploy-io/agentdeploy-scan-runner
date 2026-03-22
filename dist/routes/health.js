import { Hono } from "hono";
export const healthRoute = new Hono();
healthRoute.get("/health", (c) => {
    return c.json({
        status: "ok",
        timestamp: new Date().toISOString(),
        version: "1.0.0",
    });
});
