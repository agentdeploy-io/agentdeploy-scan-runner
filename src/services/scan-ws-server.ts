import type { Server as HttpServer, IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket, type RawData } from "ws";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { resolveScanWsSecret, verifyScanWsToken } from "../lib/scan-ws-token.js";
import { getScanJob } from "./directus.js";
import { getScanState, getSubscriptionManager } from "./redis.js";

type WsMessage =
  | { type: "subscribe"; jobIds: string[] }
  | { type: "unsubscribe"; jobIds: string[] }
  | { type: "ping" };

interface WsContext {
  userId: string;
  subscriptions: Map<string, () => void>;
}

type AuthedWebSocket = WebSocket & { __scanCtx?: WsContext };
type TrackedWebSocket = AuthedWebSocket & { __isAlive?: boolean };

type OwnershipResult = "ok" | "forbidden" | "not_found";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sendJson(ws: WebSocket, payload: unknown): void {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function rejectUpgrade(socket: Duplex, status: number, message: string): void {
  socket.write(
    `HTTP/1.1 ${status} ${message}\r\n` +
      "Connection: close\r\n" +
      "Content-Type: text/plain\r\n" +
      `Content-Length: ${Buffer.byteLength(message)}\r\n\r\n` +
      message
  );
  socket.destroy();
}

async function validateOwnership(jobId: string, userId: string): Promise<OwnershipResult> {
  const job = await getScanJob(jobId).catch(() => null);
  if (!job) return "not_found";
  return String(job.seller_id) === userId ? "ok" : "forbidden";
}

async function validateOwnershipWithRetry(
  jobId: string,
  userId: string
): Promise<OwnershipResult> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const result = await validateOwnership(jobId, userId);
    if (result !== "not_found") {
      return result;
    }
    if (attempt < 3) {
      await sleep(150 * (attempt + 1));
    }
  }
  return "not_found";
}

export function attachScanWebSocketServer(server: HttpServer): void {
  const env = getEnv();
  const wsSecret = resolveScanWsSecret(env.SCAN_WS_TOKEN_SECRET, env.SCANNER_API_KEY);
  const wss = new WebSocketServer({ noServer: true });

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    const authedWs = ws as TrackedWebSocket;
    const ctx = authedWs.__scanCtx;
    if (!ctx) {
      sendJson(ws, { type: "error", code: "MISSING_CONTEXT", message: "Websocket context missing" });
      ws.close();
      return;
    }

    authedWs.__isAlive = true;
    const heartbeat = setInterval(() => {
      if (authedWs.readyState !== authedWs.OPEN) return;

      if (authedWs.__isAlive === false) {
        logger.warn({ userId: ctx.userId }, "Terminating stale scan websocket");
        authedWs.terminate();
        return;
      }

      authedWs.__isAlive = false;
      try {
        authedWs.ping();
      } catch {
        authedWs.terminate();
      }
    }, 25_000);

    authedWs.on("pong", () => {
      authedWs.__isAlive = true;
    });

    ws.on("message", async (raw: RawData) => {
      authedWs.__isAlive = true;
      let msg: WsMessage | null = null;
      try {
        msg = JSON.parse(raw.toString("utf8")) as WsMessage;
      } catch {
        sendJson(ws, { type: "error", code: "INVALID_MESSAGE", message: "Invalid JSON message" });
        return;
      }

      if (!msg) return;

      if (msg.type === "ping") {
        sendJson(ws, { type: "pong", ts: new Date().toISOString() });
        return;
      }

      if (msg.type === "unsubscribe") {
        const removed: string[] = [];
        for (const jobId of msg.jobIds ?? []) {
          const unsub = ctx.subscriptions.get(jobId);
          if (unsub) {
            unsub();
            ctx.subscriptions.delete(jobId);
            removed.push(jobId);
          }
        }
        sendJson(ws, { type: "ack", action: "unsubscribe", jobIds: removed });
        return;
      }

      if (msg.type === "subscribe") {
        const subscribed: string[] = [];
        const rejected: Array<{ jobId: string; code: string }> = [];

        for (const rawJobId of msg.jobIds ?? []) {
          const jobId = String(rawJobId);
          if (!jobId) continue;
          if (ctx.subscriptions.has(jobId)) {
            subscribed.push(jobId);
            continue;
          }

          const ownership = await validateOwnershipWithRetry(jobId, ctx.userId);
          if (ownership !== "ok") {
            rejected.push({
              jobId,
              code: ownership === "not_found" ? "JOB_NOT_FOUND" : "FORBIDDEN_JOB_ACCESS",
            });
            continue;
          }

          const channel = `scan:progress:${jobId}`;
          const unsubscribe = getSubscriptionManager().subscribe(channel, (data) => {
            sendJson(ws, { type: "scan_event", jobId, event: data });
          });
          ctx.subscriptions.set(jobId, unsubscribe);
          subscribed.push(jobId);

          const latest = await getScanState(jobId);
          if (latest) {
            sendJson(ws, { type: "scan_event", jobId, event: latest, replay: true });
          }
        }

        sendJson(ws, { type: "ack", action: "subscribe", jobIds: subscribed, rejected });
      }
    });

    ws.on("close", () => {
      clearInterval(heartbeat);
      for (const unsubscribe of ctx.subscriptions.values()) {
        unsubscribe();
      }
      ctx.subscriptions.clear();
    });

    sendJson(ws, { type: "ready", userId: ctx.userId });
  });

  server.on("upgrade", (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const requestUrl = new URL(req.url || "/", "http://localhost");
    if (requestUrl.pathname !== "/ws/scan") {
      return;
    }

    if (!wsSecret) {
      rejectUpgrade(socket, 503, "WebSocket auth secret not configured");
      return;
    }

    const token = requestUrl.searchParams.get("token") || "";
    const payload = verifyScanWsToken(token, wsSecret);
    if (!payload) {
      rejectUpgrade(socket, 401, "Invalid or expired token");
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
      const context: WsContext = {
        userId: payload.userId,
        subscriptions: new Map(),
      };
      (ws as AuthedWebSocket).__scanCtx = context;
      wss.emit("connection", ws, req);
      logger.info({ userId: payload.userId }, "Scan websocket connected");
    });
  });
}
