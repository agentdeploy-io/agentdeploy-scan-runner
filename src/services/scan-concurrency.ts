import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { getRedisClient } from "./redis.js";

const RESERVATION_TTL_SECONDS = 60 * 60 * 24;
const ACTIVE_SET_KEY = (userId: string) => `scan:user:active_templates:${userId}`;
const TEMPLATE_JOB_KEY = (userId: string, templateId: string) =>
  `scan:user:template_job:${userId}:${templateId}`;

type AdmissionState = "acquired" | "existing" | "limit";

interface AdmissionPayload {
  state: AdmissionState;
  jobId?: string;
  templates?: string[];
}

export type AdmissionResult =
  | { state: "acquired" }
  | { state: "existing"; jobId: string }
  | { state: "limit"; templateIds: string[] };

const ADMISSION_LUA = `
local templateJobKey = KEYS[1]
local activeSetKey = KEYS[2]
local templateId = ARGV[1]
local maxActive = tonumber(ARGV[2])
local ttlSec = tonumber(ARGV[3])
local reservationId = ARGV[4]

local existing = redis.call('GET', templateJobKey)
if existing then
  return cjson.encode({ state = 'existing', jobId = existing })
end

local count = redis.call('SCARD', activeSetKey)
if count >= maxActive then
  local templates = redis.call('SMEMBERS', activeSetKey)
  return cjson.encode({ state = 'limit', templates = templates })
end

redis.call('SADD', activeSetKey, templateId)
redis.call('EXPIRE', activeSetKey, ttlSec)
redis.call('SET', templateJobKey, reservationId, 'EX', ttlSec)
return cjson.encode({ state = 'acquired' })
`;

export async function admitTemplateScan(
  userId: string,
  templateId: string,
  reservationId: string
): Promise<AdmissionResult> {
  const env = getEnv();
  const redis = await getRedisClient();

  const raw = await redis.eval(ADMISSION_LUA, {
    keys: [TEMPLATE_JOB_KEY(userId, templateId), ACTIVE_SET_KEY(userId)],
    arguments: [
      templateId,
      String(env.SCAN_MAX_ACTIVE_TEMPLATES_PER_USER),
      String(RESERVATION_TTL_SECONDS),
      reservationId,
    ],
  });

  const parsed = JSON.parse(String(raw)) as AdmissionPayload;

  if (parsed.state === "existing" && parsed.jobId) {
    return { state: "existing", jobId: parsed.jobId };
  }

  if (parsed.state === "limit") {
    return { state: "limit", templateIds: parsed.templates ?? [] };
  }

  return { state: "acquired" };
}

export async function bindTemplateScanJob(
  userId: string,
  templateId: string,
  jobId: string
): Promise<void> {
  const redis = await getRedisClient();
  await redis.set(TEMPLATE_JOB_KEY(userId, templateId), jobId, {
    EX: RESERVATION_TTL_SECONDS,
  });
  await redis.expire(ACTIVE_SET_KEY(userId), RESERVATION_TTL_SECONDS);
}

export async function releaseTemplateScanSlot(
  userId: string,
  templateId: string
): Promise<void> {
  const redis = await getRedisClient();
  await redis.sRem(ACTIVE_SET_KEY(userId), templateId);
  await redis.del(TEMPLATE_JOB_KEY(userId, templateId));
}

export async function clearTemplateBindingIfMatches(
  userId: string,
  templateId: string,
  jobId: string
): Promise<void> {
  const redis = await getRedisClient();
  const key = TEMPLATE_JOB_KEY(userId, templateId);
  const existing = await redis.get(key);
  if (existing === jobId) {
    await redis.del(key);
    await redis.sRem(ACTIVE_SET_KEY(userId), templateId);
  }
}

export async function getActiveTemplateIds(userId: string): Promise<string[]> {
  try {
    const redis = await getRedisClient();
    return await redis.sMembers(ACTIVE_SET_KEY(userId));
  } catch (err) {
    logger.warn({ err, userId }, "Failed to load active template ids");
    return [];
  }
}
