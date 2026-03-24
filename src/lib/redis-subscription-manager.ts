/**
 * Redis Subscription Manager
 *
 * Manages Redis subscriptions with reference counting to prevent memory leaks
 * and duplicate subscriptions. Used for SSE event streaming.
 *
 * Architecture:
 * - Maintains a map of channel → { subscriber, refCount, publishers }
 * - Increments refCount when a new SSE client subscribes
 * - Decrements refCount when SSE client disconnects
 * - Automatically unsubscribes and cleans up when refCount reaches 0
 * - Prevents duplicate subscriptions to the same channel
 * - Handles reconnection gracefully
 */

import { createClient } from 'redis'
import { logger } from '../logger.js'
import { getEnv } from '../env.js'

// Use ReturnType to get the actual client type from createClient
type RedisClient = ReturnType<typeof createClient>

interface SubscriptionEntry {
  subscriber: RedisClient
  refCount: number
  publishers: Set<(data: unknown) => void>
}

interface SubscriptionManagerOptions {
  /** Maximum number of retries for reconnection (default: 5) */
  maxRetries?: number
  /** Initial retry delay in ms (default: 1000) */
  initialRetryDelay?: number
  /** Maximum retry delay in ms (default: 30000) */
  maxRetryDelay?: number
}

export class RedisSubscriptionManager {
  private static instance: RedisSubscriptionManager | null = null
  private subscriptions: Map<string, SubscriptionEntry>
  private redisUrl: string
  private maxRetries: number
  private initialRetryDelay: number
  private maxRetryDelay: number
  private isShuttingDown: boolean

  private constructor(options: SubscriptionManagerOptions = {}) {
    this.subscriptions = new Map()
    const env = getEnv()
    this.redisUrl = process.env.REDIS_URL || ''
    this.maxRetries = options.maxRetries ?? 5
    this.initialRetryDelay = options.initialRetryDelay ?? 1000
    this.maxRetryDelay = options.maxRetryDelay ?? 30000
    this.isShuttingDown = false

    if (!this.redisUrl) {
      logger.warn('REDIS_URL not configured - subscription manager will not function')
    }
  }

  /**
   * Get singleton instance
   */
  public static getInstance(options?: SubscriptionManagerOptions): RedisSubscriptionManager {
    if (!RedisSubscriptionManager.instance) {
      RedisSubscriptionManager.instance = new RedisSubscriptionManager(options)
    }
    return RedisSubscriptionManager.instance
  }

  /**
   * Subscribe to a channel with reference counting
   * Returns an unsubscribe function
   */
  public subscribe(
    channel: string,
    onMessage: (data: unknown) => void
  ): () => void {
    if (this.isShuttingDown) {
      logger.warn({ channel }, 'Cannot subscribe - manager is shutting down')
      return () => {}
    }

    if (!this.redisUrl) {
      logger.error({ channel }, 'Cannot subscribe - REDIS_URL not configured')
      return () => {}
    }

    logger.info({ channel }, 'Subscribing to Redis channel')

    let entry = this.subscriptions.get(channel)

    // Create new subscription if none exists
    if (!entry) {
      const subscriber = createClient({ url: this.redisUrl })

      // Handle connection errors with reconnection
      this.setupReconnection(subscriber, channel)

      subscriber.connect().catch((err) => {
        logger.error({ err, channel }, 'Failed to connect Redis subscriber')
      })

      entry = {
        subscriber,
        refCount: 0,
        publishers: new Set(),
      }

      // Subscribe to channel
      subscriber.subscribe(channel, (message) => {
        try {
          const data = JSON.parse(message) as unknown
          // Notify all publishers
          entry?.publishers.forEach((cb) => cb(data))
        } catch (err) {
          logger.error({ err, message, channel }, 'Failed to parse Redis message')
        }
      }).catch((err) => {
        logger.error({ err, channel }, 'Failed to subscribe to Redis channel')
      })

      this.subscriptions.set(channel, entry)
      logger.info({ channel }, 'Created new Redis subscription')
    }

    // Add publisher and increment ref count
    entry.publishers.add(onMessage)
    entry.refCount++

    logger.info(
      { channel, refCount: entry.refCount },
      `Added publisher to Redis subscription`
    )

    // Return unsubscribe function
    return () => {
      this.unsubscribe(channel, onMessage)
    }
  }

  /**
   * Unsubscribe from a channel, decrementing ref count
   * Cleans up subscription when ref count reaches 0
   */
  private unsubscribe(channel: string, onMessage: (data: unknown) => void): void {
    const entry = this.subscriptions.get(channel)

    if (!entry) {
      logger.warn({ channel }, 'Cannot unsubscribe - no subscription found')
      return
    }

    // Remove publisher and decrement ref count
    entry.publishers.delete(onMessage)
    entry.refCount--

    logger.info(
      { channel, refCount: entry.refCount },
      `Removed publisher from Redis subscription`
    )

    // Clean up when no more publishers
    if (entry.refCount <= 0) {
      this.cleanupSubscription(channel, entry)
    }
  }

  /**
   * Clean up a subscription when ref count reaches 0
   */
  private async cleanupSubscription(
    channel: string,
    entry: SubscriptionEntry
  ): Promise<void> {
    logger.info({ channel }, 'Cleaning up Redis subscription (refCount = 0)')

    try {
      await entry.subscriber.unsubscribe(channel)
      logger.info({ channel }, 'Unsubscribed from Redis channel')
    } catch (err) {
      logger.error({ err, channel }, 'Error unsubscribing from Redis channel')
    }

    try {
      await entry.subscriber.disconnect()
      logger.info({ channel }, 'Disconnected Redis subscriber')
    } catch (err) {
      logger.error({ err, channel }, 'Error disconnecting Redis subscriber')
    }

    this.subscriptions.delete(channel)
    logger.info({ channel }, 'Deleted subscription entry')
  }

  /**
   * Setup reconnection logic for a subscriber
   */
  private setupReconnection(
    subscriber: RedisClient,
    channel: string
  ): void {
    let retryCount = 0
    let retryDelay = this.initialRetryDelay

    subscriber.on('error', (err) => {
      logger.error({ err, channel }, 'Redis subscriber error')
    })

    subscriber.on('end', () => {
      if (this.isShuttingDown) {
        logger.info({ channel }, 'Subscriber ended (shutdown)')
        return
      }

      logger.warn({ channel, retryCount }, 'Subscriber connection ended, attempting reconnect')

      if (retryCount >= this.maxRetries) {
        logger.error(
          { channel, retryCount },
          'Max reconnection attempts reached, giving up'
        )
        return
      }

      retryCount++

      // Exponential backoff with jitter
      const jitter = Math.random() * 0.3 * retryDelay
      const delay = Math.min(retryDelay + jitter, this.maxRetryDelay)

      logger.info({ channel, retryCount, delay }, 'Reconnecting in %d ms')

      setTimeout(async () => {
        try {
          await subscriber.connect()
          logger.info({ channel }, 'Subscriber reconnected')
          retryCount = 0
          retryDelay = this.initialRetryDelay
        } catch (err) {
          logger.error({ err, channel }, 'Reconnection failed')
        }
      }, delay)
    })

    subscriber.on('connect', () => {
      if (retryCount > 0) {
        logger.info({ channel, retryCount }, 'Successfully reconnected after %d attempts')
      }
    })
  }

  /**
   * Get current subscription count (for debugging)
   */
  public getSubscriptionCount(): number {
    return this.subscriptions.size
  }

  /**
   * Get subscription details (for debugging)
   */
  public getSubscriptionInfo(channel: string): { refCount: number; publisherCount: number } | null {
    const entry = this.subscriptions.get(channel)
    if (!entry) return null

    return {
      refCount: entry.refCount,
      publisherCount: entry.publishers.size,
    }
  }

  /**
   * Get all active channels (for debugging)
   */
  public getActiveChannels(): string[] {
    return Array.from(this.subscriptions.keys())
  }

  /**
   * Shutdown all subscriptions gracefully
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down Redis subscription manager')
    this.isShuttingDown = true

    const cleanupPromises: Array<Promise<void>> = []

    // Use Array.from for compatibility with downlevelIteration
    for (const [channel, entry] of Array.from(this.subscriptions.entries())) {
      cleanupPromises.push(this.cleanupSubscription(channel, entry))
    }

    await Promise.all(cleanupPromises)
    logger.info('Redis subscription manager shutdown complete')
  }

  /**
   * Reset singleton instance (for testing)
   */
  public static resetInstance(): void {
    RedisSubscriptionManager.instance = null
  }
}

// Export singleton instance for convenience
export const subscriptionManager = RedisSubscriptionManager.getInstance()
