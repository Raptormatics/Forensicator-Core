/**
 * Shared Redis connection options for BullMQ queues and workers.
 * BullMQ bundles its own ioredis — pass plain options, not an external Redis instance.
 */
export function getRedisConnection() {
  return {
    host:                   process.env.REDIS_HOST     ?? "127.0.0.1",
    port:                   Number(process.env.REDIS_PORT ?? 6379),
    password:               process.env.REDIS_PASSWORD ?? undefined,
    tls:                    process.env.REDIS_TLS === "true" ? {} : undefined,
    maxRetriesPerRequest:   null,      // required by BullMQ
    enableOfflineQueue:     false,     // fail fast if Redis is unreachable
    connectTimeout:         5000,
    lazyConnect:            false,
  };
}
