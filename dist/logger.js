import pino from "pino";
export const logger = pino({
    level: process.env.LOG_LEVEL || "info",
    transport: process.env.NODE_ENV !== "production"
        ? { target: "pino-pretty", options: { colorize: true } }
        : undefined,
    redact: {
        paths: [
            "apiKey",
            "token",
            "authorization",
            "password",
            "secret",
            "*.apiKey",
            "*.token",
        ],
        censor: "[REDACTED]",
    },
});
