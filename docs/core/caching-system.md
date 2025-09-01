# 🚀 **Caching System - High-Performance Data Management**

## 🎯 **Overview**

The **Caching System** is the high-performance data management infrastructure for the Navigator API, providing multi-level caching, Redis integration, intelligent cache management, and performance optimization across all system components.

---

## 📍 **Caching Architecture Overview**

### **What is the Caching System?**
The caching system provides enterprise-grade performance optimization through:
- **Multi-Level Caching**: Memory + Redis distributed caching
- **Intelligent Cache Management**: TTL, eviction, and invalidation strategies
- **Performance Monitoring**: Cache hit/miss ratios and metrics
- **Distributed Cache Coordination**: Redis cluster support
- **Cache Warming**: Proactive cache population
- **Fallback Mechanisms**: Graceful degradation on cache failures

### **Caching System Architecture**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Multi-Level Caching System                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Application Layer Cache                        │  │
│  │  ├─ Memory Cache ──────────┬─ Fast In-Memory Storage          │  │
│  │  ├─ Local Cache ───────────┼─ Node.js Process Cache           │  │
│  │  ├─ Request Cache ─────────┼─ Per-Request Caching             │  │
│  │  └─ Session Cache ─────────┴─ User Session Data                │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Distributed Cache Layer                        │  │
│  │  ├─ Redis Cache ──────────┬─ Distributed Key-Value Store      │  │
│  │  ├─ Redis Cluster ────────┼─ High Availability & Scaling      │  │
│  │  ├─ Cache Replication ────┼─ Data Consistency                 │  │
│  │  └─ Cache Persistence ────┴─ Data Durability                  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Cache Management Layer                         │  │
│  │  ├─ Cache Invalidation ──┬─ Smart Cache Clearing              │  │
│  │  ├─ Cache Warming ───────┼─ Proactive Data Loading           │  │
│  │  ├─ Cache Monitoring ────┼─ Performance Metrics               │  │
│  │  └─ Cache Strategies ────┴─ TTL, LRU, LFU Policies            │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Redis Configuration**

```typescript
// File: libs/common/src/config/redis.config.ts

import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
  db: parseInt(process.env.REDIS_DB || '0', 10),

  // Connection options
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,

  // Cluster configuration (if using Redis Cluster)
  cluster: process.env.REDIS_CLUSTER === 'true' ? {
    enableReadyCheck: false,
    clusterRetryDelay: 100,
  } : undefined,

  // TLS configuration (for secure connections)
  tls: process.env.REDIS_TLS === 'true' ? {
    rejectUnauthorized: false,
  } : undefined,
}));
```

### **2. Cache Module Setup**

```typescript
// File: src/cache/cache.module.ts

import { Module, Global } from '@nestjs/common';
import { CacheModule as NestCacheModule } from '@nestjs/cache-manager';
import { RedisService } from './redis.service';
import { CacheService } from './cache.service';
import { CacheInterceptor } from './cache.interceptor';
import redisConfig from '@app/common/config/redis.config';

@Global()
@Module({
  imports: [
    NestCacheModule.registerAsync({
      useFactory: async (configService: ConfigService) => {
        const redisConfig = configService.get('redis');

        return {
          store: 'redis',
          host: redisConfig.host,
          port: redisConfig.port,
          password: redisConfig.password,
          db: redisConfig.db,

          // TTL settings
          ttl: 300, // 5 minutes default

          // Advanced options
          max: 1000, // Maximum number of items
          isGlobal: true,
        };
      },
      inject: [ConfigService],
    }),
  ],
  providers: [
    RedisService,
    CacheService,
    CacheInterceptor,
  ],
  exports: [
    RedisService,
    CacheService,
    CacheInterceptor,
    NestCacheModule,
  ],
})
export class CacheModule {}
```

### **3. Redis Service**

```typescript
// File: src/cache/redis.service.ts

import { Injectable, Inject, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Redis } from 'ioredis';

@Injectable()
export class RedisService {
  private readonly logger = new Logger(RedisService.name);
  private redisClient: Redis;

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {
    // Get the underlying Redis client from cache manager
    this.redisClient = (this.cacheManager as any).store.getClient();
    this.setupEventHandlers();
  }

  /**
   * Setup Redis event handlers for monitoring
   */
  private setupEventHandlers(): void {
    this.redisClient.on('connect', () => {
      this.logger.log('Connected to Redis');
    });

    this.redisClient.on('ready', () => {
      this.logger.log('Redis client ready');
    });

    this.redisClient.on('error', (error) => {
      this.logger.error('Redis connection error', error);
    });

    this.redisClient.on('close', () => {
      this.logger.warn('Redis connection closed');
    });
  }

  /**
   * Get cache value with type safety
   */
  async get<T>(key: string): Promise<T | undefined> {
    try {
      const value = await this.cacheManager.get<T>(key);
      return value;
    } catch (error) {
      this.logger.error(`Failed to get cache key: ${key}`, error);
      return undefined;
    }
  }

  /**
   * Set cache value with TTL
   */
  async set<T>(
    key: string,
    value: T,
    ttl?: number,
    options?: { compress?: boolean },
  ): Promise<void> {
    try {
      await this.cacheManager.set(key, value, ttl);
      this.logger.debug(`Cache set: ${key}, TTL: ${ttl || 'default'}`);
    } catch (error) {
      this.logger.error(`Failed to set cache key: ${key}`, error);
    }
  }

  /**
   * Delete cache key
   */
  async delete(key: string): Promise<boolean> {
    try {
      await this.cacheManager.del(key);
      this.logger.debug(`Cache deleted: ${key}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete cache key: ${key}`, error);
      return false;
    }
  }

  /**
   * Clear all cache
   */
  async clear(): Promise<void> {
    try {
      await this.cacheManager.reset();
      this.logger.warn('Cache cleared');
    } catch (error) {
      this.logger.error('Failed to clear cache', error);
    }
  }

  /**
   * Get cache statistics
   */
  async getStats(): Promise<CacheStats> {
    try {
      const info = await this.redisClient.info();

      return {
        connected: this.redisClient.status === 'ready',
        usedMemory: this.parseRedisInfo(info, 'used_memory'),
        totalConnections: this.parseRedisInfo(info, 'total_connections_received'),
        hits: this.parseRedisInfo(info, 'keyspace_hits'),
        misses: this.parseRedisInfo(info, 'keyspace_misses'),
        uptime: this.parseRedisInfo(info, 'uptime_in_seconds'),
      };
    } catch (error) {
      this.logger.error('Failed to get cache stats', error);
      return {
        connected: false,
        usedMemory: 0,
        totalConnections: 0,
        hits: 0,
        misses: 0,
        uptime: 0,
      };
    }
  }

  /**
   * Set multiple keys at once
   */
  async mset(keyValuePairs: Array<{ key: string; value: any; ttl?: number }>): Promise<void> {
    const pipeline = this.redisClient.pipeline();

    keyValuePairs.forEach(({ key, value, ttl }) => {
      if (ttl) {
        pipeline.setex(key, ttl, JSON.stringify(value));
      } else {
        pipeline.set(key, JSON.stringify(value));
      }
    });

    try {
      await pipeline.exec();
      this.logger.debug(`Batch set ${keyValuePairs.length} cache keys`);
    } catch (error) {
      this.logger.error('Failed to batch set cache keys', error);
    }
  }

  /**
   * Get multiple keys at once
   */
  async mget<T = any>(keys: string[]): Promise<(T | undefined)[]> {
    try {
      const values = await this.redisClient.mget(...keys);
      return values.map(value => value ? JSON.parse(value) : undefined);
    } catch (error) {
      this.logger.error('Failed to batch get cache keys', error);
      return new Array(keys.length).fill(undefined);
    }
  }

  /**
   * Check if key exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redisClient.exists(key);
      return result === 1;
    } catch (error) {
      this.logger.error(`Failed to check existence of key: ${key}`, error);
      return false;
    }
  }

  /**
   * Set key expiration
   */
  async expire(key: string, ttl: number): Promise<boolean> {
    try {
      const result = await this.redisClient.expire(key, ttl);
      return result === 1;
    } catch (error) {
      this.logger.error(`Failed to set expiration for key: ${key}`, error);
      return false;
    }
  }

  /**
   * Get TTL for key
   */
  async ttl(key: string): Promise<number> {
    try {
      return await this.redisClient.ttl(key);
    } catch (error) {
      this.logger.error(`Failed to get TTL for key: ${key}`, error);
      return -1;
    }
  }

  /**
   * Parse Redis INFO command output
   */
  private parseRedisInfo(info: string, key: string): number {
    const lines = info.split('\n');
    const line = lines.find(line => line.startsWith(key + ':'));

    if (line) {
      const value = line.split(':')[1];
      return parseInt(value, 10) || 0;
    }

    return 0;
  }
}

interface CacheStats {
  connected: boolean;
  usedMemory: number;
  totalConnections: number;
  hits: number;
  misses: number;
  uptime: number;
}
```

### **4. Cache Service**

```typescript
// File: src/cache/cache.service.ts

import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from './redis.service';

@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);

  constructor(private readonly redisService: RedisService) {}

  /**
   * Get or set cache value with function
   */
  async getOrSet<T>(
    key: string,
    factory: () => Promise<T>,
    ttl?: number,
  ): Promise<T> {
    try {
      // Try to get from cache first
      const cached = await this.redisService.get<T>(key);
      if (cached !== undefined) {
        this.logger.debug(`Cache hit for key: ${key}`);
        return cached;
      }

      // Cache miss - execute factory function
      this.logger.debug(`Cache miss for key: ${key}`);
      const value = await factory();

      // Cache the result
      await this.redisService.set(key, value, ttl);

      return value;
    } catch (error) {
      this.logger.error(`Cache operation failed for key: ${key}`, error);
      // Fallback to factory function if caching fails
      return factory();
    }
  }

  /**
   * Cache with custom key generation
   */
  async getOrSetWithKey<T>(
    keyGenerator: (args: any[]) => string,
    args: any[],
    factory: (...args: any[]) => Promise<T>,
    ttl?: number,
  ): Promise<T> {
    const key = keyGenerator(args);
    return this.getOrSet(key, () => factory(...args), ttl);
  }

  /**
   * Invalidate cache by pattern
   */
  async invalidatePattern(pattern: string): Promise<void> {
    try {
      const keys = await this.redisService.getKeysByPattern(pattern);

      if (keys.length > 0) {
        await this.redisService.deleteMultiple(keys);
        this.logger.log(`Invalidated ${keys.length} cache keys matching pattern: ${pattern}`);
      }
    } catch (error) {
      this.logger.error(`Failed to invalidate cache pattern: ${pattern}`, error);
    }
  }

  /**
   * Cache warming for frequently accessed data
   */
  async warmCache(warmupData: CacheWarmupItem[]): Promise<void> {
    this.logger.log(`Starting cache warmup with ${warmupData.length} items`);

    const cachePromises = warmupData.map(async (item) => {
      try {
        const value = await item.factory();
        await this.redisService.set(item.key, value, item.ttl);
        this.logger.debug(`Warmed cache for key: ${item.key}`);
      } catch (error) {
        this.logger.error(`Failed to warm cache for key: ${item.key}`, error);
      }
    });

    await Promise.allSettled(cachePromises);
    this.logger.log('Cache warmup completed');
  }

  /**
   * Get cache hit ratio
   */
  async getHitRatio(): Promise<number> {
    try {
      const stats = await this.redisService.getStats();

      if (stats.hits + stats.misses === 0) {
        return 0;
      }

      return stats.hits / (stats.hits + stats.misses);
    } catch (error) {
      this.logger.error('Failed to calculate cache hit ratio', error);
      return 0;
    }
  }

  /**
   * Health check for cache system
   */
  async healthCheck(): Promise<CacheHealth> {
    try {
      const stats = await this.redisService.getStats();
      const hitRatio = await this.getHitRatio();

      return {
        healthy: stats.connected,
        hitRatio,
        memoryUsage: stats.usedMemory,
        uptime: stats.uptime,
        lastChecked: new Date(),
      };
    } catch (error) {
      this.logger.error('Cache health check failed', error);
      return {
        healthy: false,
        hitRatio: 0,
        memoryUsage: 0,
        uptime: 0,
        lastChecked: new Date(),
        error: error.message,
      };
    }
  }
}

interface CacheWarmupItem {
  key: string;
  factory: () => Promise<any>;
  ttl?: number;
}

interface CacheHealth {
  healthy: boolean;
  hitRatio: number;
  memoryUsage: number;
  uptime: number;
  lastChecked: Date;
  error?: string;
}
```

### **5. Cache Interceptor**

```typescript
// File: src/cache/cache.interceptor.ts

import {
  Injectable,
  ExecutionContext,
  CallHandler,
  CacheInterceptor as NestCacheInterceptor,
  Logger,
} from '@nestjs/common';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';
import { RedisService } from './redis.service';

@Injectable()
export class CacheInterceptor extends NestCacheInterceptor {
  private readonly logger = new Logger(CacheInterceptor.name);

  constructor(
    private readonly redisService: RedisService,
  ) {
    super();
  }

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const cacheKey = this.generateCacheKey(context);

    // Check if caching is enabled for this endpoint
    if (this.shouldSkipCache(context)) {
      return next.handle();
    }

    try {
      // Try to get from cache
      const cachedResponse = await this.redisService.get(cacheKey);

      if (cachedResponse !== undefined) {
        this.logger.debug(`Cache hit for ${cacheKey}`);
        return of(cachedResponse);
      }

      // Cache miss - execute handler and cache result
      return next.handle().pipe(
        tap(async (response) => {
          if (this.shouldCacheResponse(response)) {
            const ttl = this.getCacheTTL(context);
            await this.redisService.set(cacheKey, response, ttl);
            this.logger.debug(`Cached response for ${cacheKey} with TTL ${ttl}s`);
          }
        }),
      );
    } catch (error) {
      this.logger.error(`Cache operation failed for ${cacheKey}`, error);
      // Fallback to normal execution if caching fails
      return next.handle();
    }
  }

  /**
   * Generate cache key from execution context
   */
  private generateCacheKey(context: ExecutionContext): string {
    const request = context.switchToHttp().getRequest();
    const handler = context.getHandler();
    const className = context.getClass().name;
    const methodName = handler.name;

    // Include relevant request parameters in cache key
    const params = {
      url: request.url,
      method: request.method,
      query: request.query,
      userId: request.user?.id,
    };

    // Create hash of parameters for cache key
    const keyString = `${className}:${methodName}:${JSON.stringify(params)}`;
    return this.hashString(keyString);
  }

  /**
   * Determine if caching should be skipped
   */
  private shouldSkipCache(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const handler = context.getHandler();

    // Skip caching for:
    // - Non-GET requests
    // - Requests with Cache-Control: no-cache
    // - Handlers marked with @CacheSkip decorator
    return (
      request.method !== 'GET' ||
      request.headers['cache-control'] === 'no-cache' ||
      Reflect.hasMetadata('cache:skip', handler)
    );
  }

  /**
   * Determine if response should be cached
   */
  private shouldCacheResponse(response: any): boolean {
    // Don't cache:
    // - Error responses
    // - Empty responses
    // - Responses with sensitive data
    return (
      response &&
      !response.error &&
      !this.containsSensitiveData(response)
    );
  }

  /**
   * Get cache TTL from handler metadata or default
   */
  private getCacheTTL(context: ExecutionContext): number {
    const handler = context.getHandler();
    const ttl = Reflect.getMetadata('cache:ttl', handler);

    return ttl || 300; // Default 5 minutes
  }

  /**
   * Check if response contains sensitive data
   */
  private containsSensitiveData(response: any): boolean {
    // Check for common sensitive data patterns
    const sensitivePatterns = [
      /password/i,
      /token/i,
      /secret/i,
      /ssn/i,
      /credit.?card/i,
    ];

    const responseString = JSON.stringify(response);
    return sensitivePatterns.some(pattern => pattern.test(responseString));
  }

  /**
   * Generate hash for cache key
   */
  private hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }
}
```

---

## 🎯 **Cache Management Strategies**

### **1. Cache Key Management**

```typescript
// Cache key generation utilities
@Injectable()
export class CacheKeyGenerator {
  /**
   * Generate user-specific cache key
   */
  static userKey(userId: string, resource: string): string {
    return `user:${userId}:${resource}`;
  }

  /**
   * Generate resource-specific cache key
   */
  static resourceKey(resource: string, id: string): string {
    return `resource:${resource}:${id}`;
  }

  /**
   * Generate API response cache key
   */
  static apiKey(endpoint: string, params: Record<string, any>): string {
    const sortedParams = Object.keys(params)
      .sort()
      .map(key => `${key}:${params[key]}`)
      .join('|');

    return `api:${endpoint}:${this.hashString(sortedParams)}`;
  }

  /**
   * Generate search result cache key
   */
  static searchKey(query: string, filters: Record<string, any>): string {
    const filterString = Object.keys(filters)
      .sort()
      .map(key => `${key}:${filters[key]}`)
      .join('|');

    return `search:${this.hashString(query)}:${this.hashString(filterString)}`;
  }

  private static hashString(str: string): string {
    // Simple hash function for cache keys
    return Buffer.from(str).toString('base64').substring(0, 10);
  }
}
```

### **2. Cache Invalidation Strategies**

```typescript
@Injectable()
export class CacheInvalidationService {
  constructor(private readonly redisService: RedisService) {}

  /**
   * Invalidate user-specific cache
   */
  async invalidateUserCache(userId: string): Promise<void> {
    const patterns = [
      `user:${userId}:*`,
      `resource:profile:${userId}`,
      `api:/users/${userId}/*`,
    ];

    for (const pattern of patterns) {
      await this.invalidatePattern(pattern);
    }
  }

  /**
   * Invalidate resource-specific cache
   */
  async invalidateResourceCache(resource: string, id?: string): Promise<void> {
    if (id) {
      await this.redisService.delete(`resource:${resource}:${id}`);
    } else {
      await this.invalidatePattern(`resource:${resource}:*`);
    }
  }

  /**
   * Invalidate API endpoint cache
   */
  async invalidateApiCache(endpoint: string): Promise<void> {
    await this.invalidatePattern(`api:${endpoint}*`);
  }

  /**
   * Invalidate all cache (use with caution)
   */
  async invalidateAllCache(): Promise<void> {
    await this.redisService.clear();
  }

  /**
   * Smart cache invalidation based on data changes
   */
  async invalidateOnDataChange(
    tableName: string,
    recordId: string,
    operation: 'INSERT' | 'UPDATE' | 'DELETE',
  ): Promise<void> {
    const invalidationRules = {
      users: () => this.invalidateUserCache(recordId),
      appointments: () => this.invalidateUserCache('*'), // Invalidate all user caches
      preferences: () => this.invalidateResourceCache('preferences', recordId),
    };

    const rule = invalidationRules[tableName];
    if (rule) {
      await rule();
    }
  }

  private async invalidatePattern(pattern: string): Promise<void> {
    // Implementation to delete keys matching pattern
    const keys = await this.redisService.getKeysByPattern(pattern);
    if (keys.length > 0) {
      await this.redisService.deleteMultiple(keys);
    }
  }
}
```

### **3. Cache Warming Service**

```typescript
@Injectable()
export class CacheWarmingService {
  constructor(
    private readonly cacheService: CacheService,
    private readonly logger: Logger,
  ) {}

  /**
   * Warm up frequently accessed data
   */
  async warmFrequentlyAccessedData(): Promise<void> {
    this.logger.log('Starting cache warming for frequently accessed data');

    const warmupTasks = [
      this.warmUserProfiles(),
      this.warmSystemConfiguration(),
      this.warmReferenceData(),
      this.warmPopularResources(),
    ];

    await Promise.allSettled(warmupTasks);
    this.logger.log('Cache warming completed');
  }

  /**
   * Warm user profile data
   */
  private async warmUserProfiles(): Promise<void> {
    const recentUserIds = await this.getRecentActiveUsers();

    const warmupItems = recentUserIds.map(userId => ({
      key: CacheKeyGenerator.userKey(userId, 'profile'),
      factory: () => this.loadUserProfile(userId),
      ttl: 3600, // 1 hour
    }));

    await this.cacheService.warmCache(warmupItems);
  }

  /**
   * Warm system configuration
   */
  private async warmSystemConfiguration(): Promise<void> {
    const configItems = [
      {
        key: 'system:config:features',
        factory: () => this.loadFeatureFlags(),
        ttl: 1800, // 30 minutes
      },
      {
        key: 'system:config:settings',
        factory: () => this.loadSystemSettings(),
        ttl: 3600, // 1 hour
      },
    ];

    await this.cacheService.warmCache(configItems);
  }

  /**
   * Warm reference data
   */
  private async warmReferenceData(): Promise<void> {
    const referenceItems = [
      {
        key: 'reference:specialties',
        factory: () => this.loadSpecialtyList(),
        ttl: 86400, // 24 hours
      },
      {
        key: 'reference:departments',
        factory: () => this.loadDepartmentList(),
        ttl: 86400,
      },
    ];

    await this.cacheService.warmCache(referenceItems);
  }

  /**
   * Warm popular resources
   */
  private async warmPopularResources(): Promise<void> {
    const popularResources = await this.getPopularResourceIds();

    const warmupItems = popularResources.map(resourceId => ({
      key: CacheKeyGenerator.resourceKey('document', resourceId),
      factory: () => this.loadResource(resourceId),
      ttl: 1800, // 30 minutes
    }));

    await this.cacheService.warmCache(warmupItems);
  }

  /**
   * Scheduled cache warming
   */
  @Cron('0 */6 * * *') // Every 6 hours
  async scheduledCacheWarming(): Promise<void> {
    this.logger.log('Running scheduled cache warming');
    await this.warmFrequentlyAccessedData();
  }

  // Helper methods (implementations would depend on your data sources)
  private async getRecentActiveUsers(): Promise<string[]> { /* ... */ }
  private async loadUserProfile(userId: string): Promise<any> { /* ... */ }
  private async loadFeatureFlags(): Promise<any> { /* ... */ }
  private async loadSystemSettings(): Promise<any> { /* ... */ }
  private async loadSpecialtyList(): Promise<any> { /* ... */ }
  private async loadDepartmentList(): Promise<any> { /* ... */ }
  private async getPopularResourceIds(): Promise<string[]> { /* ... */ }
  private async loadResource(resourceId: string): Promise<any> { /* ... */ }
}
```

---

## 🎯 **Usage Examples**

### **1. Basic Caching in Services**

```typescript
@Injectable()
export class UserService {
  constructor(private readonly cacheService: CacheService) {}

  async getUserProfile(userId: string): Promise<UserProfile> {
    const cacheKey = `user:${userId}:profile`;

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        // Expensive database operation
        return this.userRepository.findProfileById(userId);
      },
      3600, // 1 hour TTL
    );
  }

  async updateUserProfile(userId: string, profile: UpdateProfileDto): Promise<void> {
    // Update database
    await this.userRepository.updateProfile(userId, profile);

    // Invalidate related cache
    await this.cacheInvalidationService.invalidateUserCache(userId);
  }
}
```

### **2. API-Level Caching with Interceptor**

```typescript
@Controller('users')
@UseInterceptors(CacheInterceptor)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get(':id/profile')
  @CacheTTL(600) // 10 minutes
  async getUserProfile(@Param('id') userId: string): Promise<UserProfile> {
    return this.userService.getUserProfile(userId);
  }

  @Get('search')
  @CacheTTL(300) // 5 minutes
  async searchUsers(@Query() query: SearchQuery): Promise<User[]> {
    return this.userService.searchUsers(query);
  }

  @Post(':id/profile')
  @CacheSkip() // Don't cache POST requests
  async updateProfile(
    @Param('id') userId: string,
    @Body() update: UpdateProfileDto,
  ): Promise<void> {
    return this.userService.updateUserProfile(userId, update);
  }
}
```

### **3. Advanced Cache Patterns**

```typescript
@Injectable()
export class AdvancedCachingService {
  constructor(private readonly redisService: RedisService) {}

  /**
   * Multi-level caching with fallback
   */
  async getWithMultiLevelCache<T>(key: string): Promise<T | null> {
    // Check L1 cache (memory)
    let data = await this.memoryCache.get<T>(key);
    if (data) {
      this.logger.debug('L1 cache hit');
      return data;
    }

    // Check L2 cache (Redis)
    data = await this.redisService.get<T>(key);
    if (data) {
      this.logger.debug('L2 cache hit');
      // Warm L1 cache
      await this.memoryCache.set(key, data, 300);
      return data;
    }

    this.logger.debug('Cache miss');
    return null;
  }

  /**
   * Cache with stale-while-revalidate pattern
   */
  async getWithStaleWhileRevalidate<T>(
    key: string,
    factory: () => Promise<T>,
    ttl: number = 3600,
  ): Promise<T> {
    const data = await this.redisService.get<T>(key);

    if (data) {
      // Return stale data immediately
      // Refresh in background
      setImmediate(async () => {
        try {
          const freshData = await factory();
          await this.redisService.set(key, freshData, ttl);
        } catch (error) {
          this.logger.error('Failed to refresh cache', error);
        }
      });

      return data;
    }

    // No cache - fetch fresh data
    const freshData = await factory();
    await this.redisService.set(key, freshData, ttl);
    return freshData;
  }
}
```

---

## 📊 **Cache Monitoring & Analytics**

### **1. Cache Metrics Service**

```typescript
@Injectable()
export class CacheMetricsService {
  constructor(
    private readonly redisService: RedisService,
    private readonly metricsService: MetricsService,
  ) {}

  /**
   * Record cache hit
   */
  async recordCacheHit(key: string, responseTime: number): Promise<void> {
    this.metricsService.increment('cache.hits');
    this.metricsService.histogram('cache.response_time', responseTime, {
      result: 'hit',
      key_pattern: this.extractKeyPattern(key),
    });
  }

  /**
   * Record cache miss
   */
  async recordCacheMiss(key: string, responseTime: number): Promise<void> {
    this.metricsService.increment('cache.misses');
    this.metricsService.histogram('cache.response_time', responseTime, {
      result: 'miss',
      key_pattern: this.extractKeyPattern(key),
    });
  }

  /**
   * Calculate and record hit ratio
   */
  async recordHitRatio(): Promise<void> {
    const stats = await this.redisService.getStats();
    const total = stats.hits + stats.misses;
    const ratio = total > 0 ? stats.hits / total : 0;

    this.metricsService.gauge('cache.hit_ratio', ratio);
    this.metricsService.gauge('cache.total_requests', total);
  }

  /**
   * Monitor cache memory usage
   */
  async recordMemoryUsage(): Promise<void> {
    const stats = await this.redisService.getStats();

    this.metricsService.gauge('cache.memory_used_bytes', stats.usedMemory);
    this.metricsService.gauge('cache.memory_peak_bytes', stats.peakMemory);
    this.metricsService.gauge('cache.memory_fragmentation_ratio', stats.fragmentationRatio);
  }

  /**
   * Monitor cache eviction
   */
  async recordEvictionStats(): Promise<void> {
    const stats = await this.redisService.getStats();

    this.metricsService.gauge('cache.evicted_keys', stats.evictedKeys);
    this.metricsService.gauge('cache.expired_keys', stats.expiredKeys);
  }

  private extractKeyPattern(key: string): string {
    // Extract pattern from cache key (e.g., "user:123:profile" -> "user:*:profile")
    return key.replace(/\d+/g, '*');
  }
}
```

### **2. Cache Health Check**

```typescript
@Injectable()
export class CacheHealthIndicator implements HealthIndicator {
  constructor(private readonly redisService: RedisService) {}

  async isHealthy(key: string): Promise<HealthCheckResult> {
    try {
      // Test basic connectivity
      await this.redisService.ping();

      // Test basic operations
      await this.redisService.set('health-check', 'ok', 10);
      const value = await this.redisService.get('health-check');

      if (value !== 'ok') {
        throw new Error('Cache read/write test failed');
      }

      // Get performance metrics
      const stats = await this.redisService.getStats();
      const hitRatio = await this.calculateHitRatio();

      return {
        [key]: {
          status: 'up',
          uptime: stats.uptime,
          memory: stats.usedMemory,
          connections: stats.totalConnections,
          hitRatio,
        },
      };
    } catch (error) {
      return {
        [key]: {
          status: 'down',
          error: error.message,
        },
      };
    }
  }

  private async calculateHitRatio(): Promise<number> {
    const stats = await this.redisService.getStats();
    const total = stats.hits + stats.misses;
    return total > 0 ? stats.hits / total : 0;
  }
}
```

---

## ⚙️ **Configuration & Best Practices**

### **1. Environment-Specific Configuration**

```typescript
// config/cache.config.ts
export default registerAs('cache', () => ({
  // Development configuration
  development: {
    ttl: 300, // 5 minutes
    maxItems: 1000,
    strategy: 'LRU',
    compression: false,
  },

  // Staging configuration
  staging: {
    ttl: 600, // 10 minutes
    maxItems: 5000,
    strategy: 'LFU',
    compression: true,
  },

  // Production configuration
  production: {
    ttl: 1800, // 30 minutes
    maxItems: 10000,
    strategy: 'TTL',
    compression: true,
    cluster: {
      nodes: process.env.REDIS_CLUSTER_NODES?.split(','),
      options: {
        maxRetriesPerRequest: 3,
        retryDelayOnFailover: 100,
      },
    },
  },
}));
```

### **2. Cache Best Practices**

```typescript
@Injectable()
export class CacheBestPractices {
  /**
   * Use descriptive cache keys
   */
  generateCacheKey(entity: string, id: string, context?: string): string {
    const parts = [entity, id];
    if (context) parts.push(context);
    return parts.join(':').toLowerCase();
  }

  /**
   * Implement cache versioning for breaking changes
   */
  generateVersionedKey(key: string, version: string = 'v1'): string {
    return `${key}:v${version}`;
  }

  /**
   * Set appropriate TTL based on data volatility
   */
  getTTLForEntity(entity: string): number {
    const ttlMap = {
      'user-profile': 3600,     // 1 hour
      'system-config': 1800,    // 30 minutes
      'reference-data': 86400,  // 24 hours
      'search-results': 600,    // 10 minutes
      'analytics': 300,         // 5 minutes
    };

    return ttlMap[entity] || 300; // Default 5 minutes
  }

  /**
   * Implement graceful cache degradation
   */
  async getWithFallback<T>(
    key: string,
    factory: () => Promise<T>,
    ttl?: number,
  ): Promise<T> {
    try {
      return await this.cacheService.getOrSet(key, factory, ttl);
    } catch (cacheError) {
      this.logger.warn('Cache operation failed, falling back to direct query', cacheError);
      return factory();
    }
  }

  /**
   * Implement cache warming for critical data
   */
  async warmCriticalCache(): Promise<void> {
    const criticalKeys = [
      'system:config',
      'reference:specialties',
      'user:admin:profile',
    ];

    for (const key of criticalKeys) {
      try {
        await this.cacheService.warmKey(key);
      } catch (error) {
        this.logger.error(`Failed to warm cache for key: ${key}`, error);
      }
    }
  }
}
```

---

## 🎯 **Next Steps**

This comprehensive caching system provides:
- ✅ **Multi-level caching** with Redis integration
- ✅ **Intelligent cache management** with TTL and eviction strategies
- ✅ **Performance monitoring** and health checks
- ✅ **Cache warming** and invalidation patterns
- ✅ **Enterprise-grade reliability** with fallback mechanisms

**The caching system is now fully documented and ready for high-performance data management! 🚀**

**Key components now documented:**
- Redis configuration and clustering
- Cache services with advanced patterns
- Cache interceptors for automatic caching
- Cache warming and invalidation strategies
- Monitoring and health checks
- Best practices and configuration guidelines
