import { createClient, type RedisClientType } from 'redis'
import { logger } from '../logger.js'
import { getEnv } from '../env.js'
import { RedisSubscriptionManager } from '../lib/redis-subscription-manager.js'

let publisher: RedisClientType | null = null
let subscriber: RedisClientType | null = null

async function getPublisher(): Promise<RedisClientType> {
  if (publisher?.isReady) return publisher

  const env = getEnv()
  const REDIS_URL = process.env.REDIS_URL || ''

  if (!REDIS_URL) {
    logger.warn('REDIS_URL not configured - progress events will not be published')
    throw new Error('REDIS_URL not configured')
  }

  publisher = createClient({ url: REDIS_URL })
  publisher.on('error', (err) => {
    logger.error({ err }, 'Redis publisher error')
    publisher = null
  })

  await publisher.connect()
  logger.info('Redis publisher connected')
  return publisher
}

/**
 * Get a Redis client for general use (e.g., rate limiting)
 * This returns a shared subscriber client to avoid creating too many connections
 */
export async function getRedisClient(): Promise<RedisClientType> {
  if (subscriber?.isReady) return subscriber

  const REDIS_URL = process.env.REDIS_URL || ''

  if (!REDIS_URL) {
    logger.warn('REDIS_URL not configured')
    throw new Error('REDIS_URL not configured')
  }

  subscriber = createClient({ url: REDIS_URL })
  subscriber.on('error', (err) => {
    logger.error({ err }, 'Redis client error')
    subscriber = null
  })

  await subscriber.connect()
  logger.info('Redis client connected')
  return subscriber
}

export interface ScanProgressEvent {
  jobId: string
  event_type: 'stage' | 'progress' | 'finding' | 'llm_chunk' | 'llm_thinking' | 'complete' | 'error'
  stage?: string
  message: string
  progress?: number
  timestamp: string
  data?: Record<string, unknown>
}

/**
 * Publish a message to Redis with retry logic and exponential backoff
 * @param channel The Redis channel to publish to
 * @param message The message object to publish
 * @param maxRetries Maximum number of retry attempts (default: 3)
 * @returns true if publish succeeded, false otherwise
 */
export async function publishWithRetry(
  channel: string,
  message: object,
  maxRetries = 3
): Promise<boolean> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const pub = await getPublisher()
      await pub.publish(channel, JSON.stringify(message))
      return true
    } catch (err) {
      if (attempt === maxRetries - 1) {
        logger.error({ err, channel, attempts: maxRetries }, 'Redis publish failed after all retries')
        return false
      }
      const delay = Math.pow(2, attempt) * 100 // 100ms, 200ms, 400ms
      logger.warn({ err, channel, attempt: attempt + 1, maxRetries, delayMs: delay }, 'Redis publish failed, retrying...')
      await new Promise(r => setTimeout(r, delay))
    }
  }
  return false
}

export async function publishScanProgress(
  jobId: string,
  event: Omit<ScanProgressEvent, 'timestamp'>
): Promise<void> {
  const channel = `scan:progress:${jobId}`
  const stateKey = `scan:state:${jobId}`
  const fullEvent: ScanProgressEvent = {
    ...event,
    timestamp: new Date().toISOString(),
  }

  try {
    const pub = await getPublisher()
    await pub.set(stateKey, JSON.stringify(fullEvent), { EX: 60 * 60 * 24 })
  } catch (err) {
    logger.warn({ err, jobId }, 'Failed to persist latest scan state in Redis')
  }

  const success = await publishWithRetry(channel, fullEvent)
  if (success) {
    logger.info({ jobId, event_type: event.event_type, stage: event.stage }, 'Published scan progress')
  } else {
    logger.error({ jobId, event_type: event.event_type, stage: event.stage }, 'Failed to publish scan progress after retries')
  }
}

export async function getScanState(jobId: string): Promise<ScanProgressEvent | null> {
  try {
    const client = await getRedisClient()
    const raw = await client.get(`scan:state:${jobId}`)
    if (!raw) return null
    return JSON.parse(raw) as ScanProgressEvent
  } catch (err) {
    logger.warn({ err, jobId }, 'Failed to read scan state from Redis')
    return null
  }
}

/**
 * Get the subscription manager instance
 */
export function getSubscriptionManager(): RedisSubscriptionManager {
  return RedisSubscriptionManager.getInstance()
}

export async function closeRedisConnections(): Promise<void> {
  try {
    if (publisher?.isReady) await publisher.disconnect()
  } catch {
    // Ignore cleanup errors
  }
  publisher = null
  
  // Shutdown subscription manager
  try {
    await RedisSubscriptionManager.getInstance().shutdown()
  } catch {
    // Ignore cleanup errors
  }
  RedisSubscriptionManager.resetInstance()
}
