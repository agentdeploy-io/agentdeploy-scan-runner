import crypto from "node:crypto";

interface ScanWsTokenPayload {
  userId: string;
  iat: number;
  exp: number;
}

function normalizeSecret(input: string | undefined | null): string {
  return (input || "").trim();
}

function toBase64Url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "===".slice((normalized.length + 3) % 4);
  return Buffer.from(padded, "base64");
}

function signPart(part: string, secret: string): string {
  return toBase64Url(crypto.createHmac("sha256", secret).update(part).digest());
}

function deriveScanWsSecret(scannerApiKey: string): string {
  return crypto
    .createHash("sha256")
    .update(`scan-ws-v1:${scannerApiKey}`)
    .digest("hex");
}

export function resolveScanWsSecret(
  explicitSecret: string | undefined | null,
  scannerApiKey: string | undefined | null
): string | null {
  const explicit = normalizeSecret(explicitSecret);
  if (explicit) return explicit;

  const apiKey = normalizeSecret(scannerApiKey);
  if (!apiKey) return null;

  // Deterministic local fallback: keeps scanner/frontend in sync without extra setup.
  return deriveScanWsSecret(apiKey);
}

export function verifyScanWsToken(token: string, secret: string): ScanWsTokenPayload | null {
  if (!token || !secret) return null;

  const [payloadPart, signaturePart] = token.split(".");
  if (!payloadPart || !signaturePart) return null;

  const expectedSig = signPart(payloadPart, secret);
  if (signaturePart !== expectedSig) return null;

  try {
    const payload = JSON.parse(fromBase64Url(payloadPart).toString("utf8")) as ScanWsTokenPayload;
    const now = Math.floor(Date.now() / 1000);

    if (!payload?.userId || !payload?.exp || payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
