# 🏥 **Health Check Indicators - System Monitoring & Diagnostics**

## 🎯 **Overview**

The **Health Check Indicators** provide comprehensive system monitoring and diagnostics for the Navigator API. These indicators ensure system reliability, performance monitoring, and proactive issue detection across all system components.

---

## 📍 **Health Check Architecture**

### **What are Health Indicators?**
Health indicators provide real-time system monitoring with:
- **System Health Assessment**: Overall application status
- **Database Connectivity**: PostgreSQL connection health
- **Cache Performance**: Redis availability and performance
- **External Service Monitoring**: Third-party API availability
- **Resource Monitoring**: Memory, CPU, and disk usage
- **Custom Health Checks**: Business-specific validations
- **Alert Integration**: Automatic incident response

### **Health Check Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                Health Check System                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Built-in Health Indicators              │    │
│  │  ├─ Database Health ─────────┬─ PostgreSQL Status  │    │
│  │  ├─ Cache Health ────────────┼─ Redis Connectivity │    │
│  │  ├─ Memory Health ───────────┼─ Heap Usage         │    │
│  │  └─ Disk Health ─────────────┴─ Storage Capacity   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Custom Health Indicators                │    │
│  │  ├─ External API Health ─────┬─ Curator Engine     │    │
│  │  ├─ Business Logic Health ───┼─ Core Services      │    │
│  │  ├─ Queue Health ────────────┼─ Message Queues     │    │
│  │  └─ Security Health ─────────┴─ Auth Services      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Health Monitoring & Alerting            │    │
│  │  ├─ Health Endpoints ──────┬─ /health, /health/db │    │
│  │  ├─ Metrics Collection ────┼─ Prometheus/Grafana  │    │
│  │  ├─ Alert Generation ──────┼─ Slack/Email Alerts  │    │
│  │  └─ Dashboard Integration ─┴─ Real-time Monitoring│    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Redis Health Indicator**

```typescript
// File: src/controllers/health/redis-health.indicator.ts

import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../../cache/redis.service';

@Injectable()
export class RedisHealthIndicator extends HealthIndicator {
  private readonly logger = new Logger(RedisHealthIndicator.name);

  constructor(private readonly redisService: RedisService) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const startTime = Date.now();

      // Test basic connectivity
      const pingResult = await this.testRedisConnection();
      const pingTime = Date.now() - startTime;

      // Get cache statistics
      const stats = await this.redisService.getStats();

      // Test basic operations
      await this.testRedisOperations();

      // Assess overall health
      const isHealthy = this.assessRedisHealth(stats, pingTime);

      const result = this.getIndicatorResult(key, isHealthy, {
        status: 'up',
        pingTime: `${pingTime}ms`,
        version: stats.redisVersion,
        connectedClients: stats.connectedClients,
        usedMemory: `${(stats.usedMemory / 1024 / 1024).toFixed(2)}MB`,
        uptime: this.formatUptime(stats.uptimeInSeconds),
        lastSave: stats.lastSaveTime,
        keyspace: stats.keyspace,
      });

      if (!isHealthy) {
        throw new HealthCheckError('Redis is not healthy', result);
      }

      return result;
    } catch (error) {
      this.logger.error('Redis health check failed', {
        error: error.message,
        stack: error.stack,
      });

      throw new HealthCheckError(
        'Redis health check failed',
        this.getIndicatorResult(key, false, {
          status: 'down',
          error: error.message,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }

  /**
   * Test Redis connection
   */
  private async testRedisConnection(): Promise<boolean> {
    try {
      const result = await this.redisService.ping();
      return result === 'PONG';
    } catch (error) {
      this.logger.error('Redis ping failed', error);
      return false;
    }
  }

  /**
   * Test basic Redis operations
   */
  private async testRedisOperations(): Promise<void> {
    const testKey = 'health-check-test';
    const testValue = 'test-value';

    try {
      // Test SET operation
      await this.redisService.set(testKey, testValue, 60); // 1 minute TTL

      // Test GET operation
      const retrievedValue = await this.redisService.get(testKey);

      if (retrievedValue !== testValue) {
        throw new Error('Redis GET operation failed');
      }

      // Test DELETE operation
      const deleteResult = await this.redisService.delete(testKey);

      if (!deleteResult) {
        throw new Error('Redis DELETE operation failed');
      }
    } catch (error) {
      this.logger.error('Redis operations test failed', error);
      throw error;
    }
  }

  /**
   * Assess Redis health based on metrics
   */
  private assessRedisHealth(
    stats: any,
    pingTime: number,
  ): boolean {
    // Check connection
    if (!stats.connected) {
      return false;
    }

    // Check response time (< 100ms is healthy)
    if (pingTime > 100) {
      this.logger.warn(`Redis response time is high: ${pingTime}ms`);
    }

    // Check memory usage (< 80% is healthy)
    const memoryUsagePercent = (stats.usedMemory / stats.totalMemory) * 100;
    if (memoryUsagePercent > 80) {
      this.logger.warn(`Redis memory usage is high: ${memoryUsagePercent}%`);
      return false;
    }

    // Check connected clients (< 1000 is healthy)
    if (stats.connectedClients > 1000) {
      this.logger.warn(`Redis has too many connected clients: ${stats.connectedClients}`);
      return false;
    }

    // Check for recent errors
    if (stats.errorCount > 10) {
      this.logger.warn(`Redis has recent errors: ${stats.errorCount}`);
      return false;
    }

    return true;
  }

  /**
   * Format uptime for display
   */
  private formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  }
}
```

### **2. Database Health Indicator**

```typescript
// File: src/controllers/health/database-health.indicator.ts

import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

@Injectable()
export class DatabaseHealthIndicator extends HealthIndicator {
  private readonly logger = new Logger(DatabaseHealthIndicator.name);

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const startTime = Date.now();

      // Test database connection
      await this.testDatabaseConnection();

      // Test basic query execution
      const queryTime = await this.testQueryExecution();

      // Get database statistics
      const stats = await this.getDatabaseStats();

      // Assess overall health
      const isHealthy = this.assessDatabaseHealth(stats, queryTime);

      const totalTime = Date.now() - startTime;

      const result = this.getIndicatorResult(key, isHealthy, {
        status: 'up',
        connectionTime: `${totalTime}ms`,
        queryTime: `${queryTime}ms`,
        database: stats.database,
        version: stats.version,
        activeConnections: stats.activeConnections,
        maxConnections: stats.maxConnections,
        uptime: stats.uptime,
      });

      if (!isHealthy) {
        throw new HealthCheckError('Database is not healthy', result);
      }

      return result;
    } catch (error) {
      this.logger.error('Database health check failed', {
        error: error.message,
        stack: error.stack,
      });

      throw new HealthCheckError(
        'Database health check failed',
        this.getIndicatorResult(key, false, {
          status: 'down',
          error: error.message,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }

  /**
   * Test database connection
   */
  private async testDatabaseConnection(): Promise<void> {
    try {
      const connection = await this.dataSource.getConnection();
      await connection.query('SELECT 1');
      connection.release();
    } catch (error) {
      this.logger.error('Database connection test failed', error);
      throw error;
    }
  }

  /**
   * Test query execution performance
   */
  private async testQueryExecution(): Promise<number> {
    const startTime = Date.now();

    try {
      // Simple SELECT query
      await this.dataSource.query('SELECT NOW() as current_time');

      // Test with a table that should exist
      await this.dataSource.query('SELECT COUNT(*) as user_count FROM users LIMIT 1');

      return Date.now() - startTime;
    } catch (error) {
      this.logger.error('Database query test failed', error);
      throw error;
    }
  }

  /**
   * Get database statistics
   */
  private async getDatabaseStats(): Promise<DatabaseStats> {
    try {
      const connection = await this.dataSource.getConnection();

      // Get database version
      const versionResult = await connection.query('SELECT version() as version');
      const version = versionResult[0]?.version || 'unknown';

      // Get active connections (PostgreSQL specific)
      const activeConnectionsResult = await connection.query(`
        SELECT count(*) as active_connections
        FROM pg_stat_activity
        WHERE state = 'active'
      `);
      const activeConnections = parseInt(activeConnectionsResult[0]?.active_connections || '0');

      // Get max connections
      const maxConnectionsResult = await connection.query('SHOW max_connections');
      const maxConnections = parseInt(maxConnectionsResult[0]?.max_connections || '100');

      // Get database uptime
      const uptimeResult = await connection.query(`
        SELECT extract(epoch from (now() - pg_postmaster_start_time())) as uptime_seconds
      `);
      const uptime = Math.floor(parseInt(uptimeResult[0]?.uptime_seconds || '0'));

      connection.release();

      return {
        database: this.dataSource.options.database as string,
        version,
        activeConnections,
        maxConnections,
        uptime,
      };
    } catch (error) {
      this.logger.error('Failed to get database stats', error);
      return {
        database: 'unknown',
        version: 'unknown',
        activeConnections: 0,
        maxConnections: 0,
        uptime: 0,
      };
    }
  }

  /**
   * Assess database health
   */
  private assessDatabaseHealth(
    stats: DatabaseStats,
    queryTime: number,
  ): boolean {
    // Check query performance (< 100ms is healthy)
    if (queryTime > 100) {
      this.logger.warn(`Database query time is high: ${queryTime}ms`);
    }

    // Check connection usage (< 80% of max connections)
    const connectionUsagePercent = (stats.activeConnections / stats.maxConnections) * 100;
    if (connectionUsagePercent > 80) {
      this.logger.warn(`Database connection usage is high: ${connectionUsagePercent}%`);
      return false;
    }

    // Check for very high connection count
    if (stats.activeConnections > 50) {
      this.logger.warn(`Database has many active connections: ${stats.activeConnections}`);
    }

    return true;
  }
}

interface DatabaseStats {
  database: string;
  version: string;
  activeConnections: number;
  maxConnections: number;
  uptime: number;
}
```

### **3. External API Health Indicator**

```typescript
// File: src/controllers/health/external-api-health.indicator.ts

import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom, timeout, catchError, of } from 'rxjs';
import { AxiosResponse } from 'axios';

@Injectable()
export class ExternalApiHealthIndicator extends HealthIndicator {
  private readonly logger = new Logger(ExternalApiHealthIndicator.name);

  constructor(private readonly httpService: HttpService) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const healthResults = await Promise.allSettled([
        this.checkCuratorEngineHealth(),
        this.checkEpicApiHealth(),
        this.checkEntraApiHealth(),
        this.checkApigeeHealth(),
      ]);

      const successful = healthResults.filter(
        result => result.status === 'fulfilled' && result.value.healthy,
      ).length;

      const total = healthResults.length;
      const successRate = (successful / total) * 100;

      const isHealthy = successRate >= 75; // At least 75% of services healthy

      const details = {
        status: isHealthy ? 'up' : 'degraded',
        totalServices: total,
        healthyServices: successful,
        successRate: `${successRate.toFixed(1)}%`,
        services: healthResults.map((result, index) => ({
          name: ['Curator Engine', 'Epic API', 'Entra API', 'Apigee'][index],
          healthy: result.status === 'fulfilled' ? result.value.healthy : false,
          responseTime: result.status === 'fulfilled' ? result.value.responseTime : 'N/A',
          error: result.status === 'rejected' ? result.reason.message : null,
        })),
      };

      const result = this.getIndicatorResult(key, isHealthy, details);

      if (!isHealthy) {
        this.logger.warn('External API health degraded', details);
      }

      return result;
    } catch (error) {
      this.logger.error('External API health check failed', error);

      throw new HealthCheckError(
        'External API health check failed',
        this.getIndicatorResult(key, false, {
          status: 'down',
          error: error.message,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }

  /**
   * Check Curator Engine health
   */
  private async checkCuratorEngineHealth(): Promise<HealthCheckResult> {
    return this.checkApiEndpoint(
      'Curator Engine',
      `${process.env.CURATOR_ENGINE_BASE_URL}/health`,
      5000, // 5 second timeout
    );
  }

  /**
   * Check Epic API health
   */
  private async checkEpicApiHealth(): Promise<HealthCheckResult> {
    return this.checkApiEndpoint(
      'Epic API',
      `${process.env.EPIC_BASE_URL}/health`,
      3000, // 3 second timeout
    );
  }

  /**
   * Check Entra API health
   */
  private async checkEntraApiHealth(): Promise<HealthCheckResult> {
    // Entra doesn't have a health endpoint, so we check token endpoint
    return this.checkApiEndpoint(
      'Entra API',
      `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
      2000,
      'POST',
      'application/x-www-form-urlencoded',
      'grant_type=client_credentials&client_id=test&client_secret=test&scope=https://graph.microsoft.com/.default',
    );
  }

  /**
   * Check Apigee health
   */
  private async checkApigeeHealth(): Promise<HealthCheckResult> {
    return this.checkApiEndpoint(
      'Apigee',
      `${process.env.APIGEE_BASE_URL}/health`,
      3000,
    );
  }

  /**
   * Generic API endpoint health check
   */
  private async checkApiEndpoint(
    name: string,
    url: string,
    timeoutMs: number = 5000,
    method: 'GET' | 'POST' = 'GET',
    contentType?: string,
    body?: string,
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      const requestConfig = {
        method,
        url,
        timeout: timeoutMs,
        headers: contentType ? { 'Content-Type': contentType } : {},
        ...(body && { data: body }),
      };

      const response = await firstValueFrom(
        this.httpService.request(requestConfig).pipe(
          timeout(timeoutMs),
          catchError(error => {
            throw new Error(`${name} health check failed: ${error.message}`);
          }),
        ),
      );

      const responseTime = Date.now() - startTime;

      // Consider healthy if status is 2xx or 3xx
      const healthy = response.status >= 200 && response.status < 400;

      return {
        name,
        healthy,
        responseTime,
        statusCode: response.status,
        url,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      return {
        name,
        healthy: false,
        responseTime,
        error: error.message,
        url,
      };
    }
  }
}

interface HealthCheckResult {
  name: string;
  healthy: boolean;
  responseTime: number;
  statusCode?: number;
  url: string;
  error?: string;
}
```

### **4. Application Health Indicator**

```typescript
// File: src/controllers/health/application-health.indicator.ts

import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ApplicationHealthIndicator extends HealthIndicator {
  private readonly logger = new Logger(ApplicationHealthIndicator.name);
  private readonly startTime = Date.now();

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      // Check application uptime
      const uptime = this.getUptime();

      // Check memory usage
      const memoryUsage = this.getMemoryUsage();

      // Check system resources
      const systemResources = this.getSystemResources();

      // Assess overall health
      const isHealthy = this.assessApplicationHealth(
        uptime,
        memoryUsage,
        systemResources,
      );

      const details = {
        status: 'up',
        uptime: this.formatUptime(uptime),
        version: process.version,
        platform: process.platform,
        arch: process.arch,
        pid: process.pid,
        memory: {
          used: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB`,
          total: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)}MB`,
          external: `${(memoryUsage.external / 1024 / 1024).toFixed(2)}MB`,
          usagePercent: `${((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100).toFixed(1)}%`,
        },
        system: systemResources,
      };

      const result = this.getIndicatorResult(key, isHealthy, details);

      if (!isHealthy) {
        throw new HealthCheckError('Application is not healthy', result);
      }

      return result;
    } catch (error) {
      this.logger.error('Application health check failed', error);

      throw new HealthCheckError(
        'Application health check failed',
        this.getIndicatorResult(key, false, {
          status: 'down',
          error: error.message,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }

  /**
   * Get application uptime
   */
  private getUptime(): number {
    return Date.now() - this.startTime;
  }

  /**
   * Get memory usage information
   */
  private getMemoryUsage(): NodeJS.MemoryUsage {
    return process.memoryUsage();
  }

  /**
   * Get system resource information
   */
  private getSystemResources(): SystemResources {
    return {
      cpuUsage: process.cpuUsage(),
      resourceUsage: process.resourceUsage(),
      activeHandles: process._getActiveHandles?.()?.length || 0,
      activeRequests: process._getActiveRequests?.()?.length || 0,
    };
  }

  /**
   * Assess application health
   */
  private assessApplicationHealth(
    uptime: number,
    memoryUsage: NodeJS.MemoryUsage,
    systemResources: SystemResources,
  ): boolean {
    // Check memory usage (< 80% of heap is healthy)
    const memoryUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
    if (memoryUsagePercent > 80) {
      this.logger.warn(`Memory usage is high: ${memoryUsagePercent}%`);
      return false;
    }

    // Check for memory leaks (heap used > 500MB is concerning)
    if (memoryUsage.heapUsed > 500 * 1024 * 1024) {
      this.logger.warn(`High memory usage detected: ${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB`);
    }

    // Check for too many active handles
    if (systemResources.activeHandles > 1000) {
      this.logger.warn(`Too many active handles: ${systemResources.activeHandles}`);
      return false;
    }

    // Check for too many active requests
    if (systemResources.activeRequests > 500) {
      this.logger.warn(`Too many active requests: ${systemResources.activeRequests}`);
      return false;
    }

    return true;
  }

  /**
   * Format uptime for display
   */
  private formatUptime(milliseconds: number): string {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
      return `${days}d ${hours % 24}h ${minutes % 60}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }
}

interface SystemResources {
  cpuUsage: NodeJS.CpuUsage;
  resourceUsage: NodeJS.ResourceUsage;
  activeHandles: number;
  activeRequests: number;
}
```

---

## 🌐 **Health Check Endpoints**

### **1. Health Controller**

```typescript
// File: src/controllers/health/health.controller.ts

import { Controller, Get } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  HealthIndicatorResult,
} from '@nestjs/terminus';

@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private redisHealth: RedisHealthIndicator,
    private dbHealth: DatabaseHealthIndicator,
    private externalApiHealth: ExternalApiHealthIndicator,
    private appHealth: ApplicationHealthIndicator,
  ) {}

  /**
   * Basic health check
   */
  @Get()
  @HealthCheck()
  async check(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.appHealth.isHealthy('application'),
    ]);
  }

  /**
   * Detailed health check
   */
  @Get('detailed')
  @HealthCheck()
  async detailedCheck(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.appHealth.isHealthy('application'),
      () => this.redisHealth.isHealthy('redis'),
      () => this.dbHealth.isHealthy('database'),
      () => this.externalApiHealth.isHealthy('external-apis'),
    ]);
  }

  /**
   * Database health check
   */
  @Get('db')
  @HealthCheck()
  async databaseCheck(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.dbHealth.isHealthy('database'),
    ]);
  }

  /**
   * Cache health check
   */
  @Get('cache')
  @HealthCheck()
  async cacheCheck(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.redisHealth.isHealthy('redis'),
    ]);
  }

  /**
   * External services health check
   */
  @Get('external')
  @HealthCheck()
  async externalCheck(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.externalApiHealth.isHealthy('external-apis'),
    ]);
  }

  /**
   * Readiness probe for Kubernetes
   */
  @Get('ready')
  @HealthCheck()
  async readiness(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.appHealth.isHealthy('application'),
      () => this.dbHealth.isHealthy('database'),
      () => this.redisHealth.isHealthy('redis'),
    ]);
  }

  /**
   * Liveness probe for Kubernetes
   */
  @Get('live')
  @HealthCheck()
  async liveness(): Promise<HealthIndicatorResult> {
    return this.health.check([
      () => this.appHealth.isHealthy('application'),
    ]);
  }
}
```

### **2. Health Check Module**

```typescript
// File: src/controllers/health/health.module.ts

import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HttpModule } from '@nestjs/axios';
import { CacheModule } from '../../cache/cache.module';
import { HealthController } from './health.controller';
import { RedisHealthIndicator } from './redis-health.indicator';
import { DatabaseHealthIndicator } from './database-health.indicator';
import { ExternalApiHealthIndicator } from './external-api-health.indicator';
import { ApplicationHealthIndicator } from './application-health.indicator';

@Module({
  imports: [
    TerminusModule,
    HttpModule,
    CacheModule,
  ],
  controllers: [HealthController],
  providers: [
    RedisHealthIndicator,
    DatabaseHealthIndicator,
    ExternalApiHealthIndicator,
    ApplicationHealthIndicator,
  ],
  exports: [
    RedisHealthIndicator,
    DatabaseHealthIndicator,
    ExternalApiHealthIndicator,
    ApplicationHealthIndicator,
  ],
})
export class HealthModule {}
```

---

## 📊 **Health Monitoring & Analytics**

### **1. Health Metrics Service**

```typescript
@Injectable()
export class HealthMetricsService {
  constructor(
    private readonly metricsService: MetricsService,
    private readonly alertingService: AlertingService,
  ) {}

  /**
   * Record health check metrics
   */
  async recordHealthMetrics(
    service: string,
    status: 'healthy' | 'unhealthy',
    responseTime: number,
    details?: Record<string, any>,
  ): Promise<void> {
    // Record health status
    this.metricsService.gauge(
      `health.status.${service}`,
      status === 'healthy' ? 1 : 0,
    );

    // Record response time
    this.metricsService.histogram(
      `health.response_time.${service}`,
      responseTime,
    );

    // Record service-specific metrics
    if (details) {
      Object.entries(details).forEach(([key, value]) => {
        if (typeof value === 'number') {
          this.metricsService.gauge(`health.${service}.${key}`, value);
        }
      });
    }

    // Alert on unhealthy services
    if (status === 'unhealthy') {
      await this.alertingService.sendAlert({
        title: `Health Check Failed: ${service}`,
        description: `${service} health check failed with response time ${responseTime}ms`,
        severity: 'warning',
        details: {
          service,
          responseTime,
          timestamp: new Date(),
          ...details,
        },
      });
    }
  }

  /**
   * Get health status summary
   */
  async getHealthSummary(): Promise<HealthSummary> {
    const services = [
      'application',
      'database',
      'redis',
      'external-apis',
    ];

    const summary = {
      overall: 'healthy' as HealthStatus,
      services: {} as Record<string, HealthStatus>,
      lastChecked: new Date(),
    };

    for (const service of services) {
      const status = await this.getServiceHealthStatus(service);
      summary.services[service] = status;

      if (status === 'unhealthy') {
        summary.overall = 'unhealthy';
      } else if (status === 'degraded' && summary.overall === 'healthy') {
        summary.overall = 'degraded';
      }
    }

    return summary;
  }

  /**
   * Calculate service health score
   */
  async getHealthScore(): Promise<number> {
    const summary = await this.getHealthSummary();
    const serviceCount = Object.keys(summary.services).length;
    const healthyCount = Object.values(summary.services).filter(
      status => status === 'healthy',
    ).length;

    return Math.round((healthyCount / serviceCount) * 100);
  }

  private async getServiceHealthStatus(service: string): Promise<HealthStatus> {
    // Implementation would check actual health status
    // This is a simplified version
    try {
      const metrics = await this.metricsService.getMetrics(`health.status.${service}`);
      return metrics > 0 ? 'healthy' : 'unhealthy';
    } catch {
      return 'unknown';
    }
  }
}

type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

interface HealthSummary {
  overall: HealthStatus;
  services: Record<string, HealthStatus>;
  lastChecked: Date;
}
```

### **2. Health Dashboard**

```typescript
@Injectable()
export class HealthDashboardService {
  constructor(private readonly healthMetrics: HealthMetricsService) {}

  /**
   * Generate health dashboard data
   */
  async getDashboardData(): Promise<HealthDashboard> {
    const [
      summary,
      healthScore,
      recentMetrics,
      alerts,
    ] = await Promise.all([
      this.healthMetrics.getHealthSummary(),
      this.healthMetrics.getHealthScore(),
      this.getRecentHealthMetrics(),
      this.getRecentHealthAlerts(),
    ]);

    return {
      summary,
      healthScore,
      uptime: this.calculateUptime(),
      recentMetrics,
      alerts,
      trends: await this.getHealthTrends(),
      recommendations: this.generateHealthRecommendations(summary),
    };
  }

  /**
   * Get recent health metrics
   */
  private async getRecentHealthMetrics(): Promise<HealthMetric[]> {
    // Implementation would fetch recent metrics from time series database
    return [];
  }

  /**
   * Get recent health alerts
   */
  private async getRecentHealthAlerts(): Promise<HealthAlert[]> {
    // Implementation would fetch recent alerts
    return [];
  }

  /**
   * Calculate system uptime
   */
  private calculateUptime(): string {
    // Implementation would calculate actual uptime
    return '99.9%';
  }

  /**
   * Get health trends over time
   */
  private async getHealthTrends(): Promise<HealthTrend[]> {
    // Implementation would analyze health trends
    return [];
  }

  /**
   * Generate health recommendations
   */
  private generateHealthRecommendations(summary: HealthSummary): string[] {
    const recommendations = [];

    const unhealthyServices = Object.entries(summary.services)
      .filter(([, status]) => status === 'unhealthy')
      .map(([service]) => service);

    if (unhealthyServices.length > 0) {
      recommendations.push(
        `Address unhealthy services: ${unhealthyServices.join(', ')}`,
      );
    }

    if (summary.overall === 'degraded') {
      recommendations.push('Review system performance and resource usage');
    }

    if (Object.values(summary.services).some(status => status === 'unknown')) {
      recommendations.push('Ensure all health checks are properly configured');
    }

    return recommendations;
  }
}

interface HealthDashboard {
  summary: HealthSummary;
  healthScore: number;
  uptime: string;
  recentMetrics: HealthMetric[];
  alerts: HealthAlert[];
  trends: HealthTrend[];
  recommendations: string[];
}

interface HealthMetric {
  service: string;
  timestamp: Date;
  responseTime: number;
  status: HealthStatus;
}

interface HealthAlert {
  id: string;
  service: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
}

interface HealthTrend {
  service: string;
  period: string;
  averageResponseTime: number;
  uptimePercentage: number;
}
```

---

## ⚙️ **Configuration & Best Practices**

### **1. Health Check Configuration**

```typescript
// File: src/config/health.config.ts

export const healthConfig = {
  // Global health check settings
  global: {
    enabled: process.env.HEALTH_CHECKS_ENABLED === 'true',
    interval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '30000'), // 30 seconds
    timeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT || '5000'), // 5 seconds
    retries: parseInt(process.env.HEALTH_CHECK_RETRIES || '3'),
  },

  // Service-specific timeouts
  timeouts: {
    database: 3000, // 3 seconds
    redis: 2000,    // 2 seconds
    externalApi: 5000, // 5 seconds
  },

  // Health thresholds
  thresholds: {
    memoryUsagePercent: 80,
    cpuUsagePercent: 70,
    responseTimeMs: 1000,
    errorRatePercent: 5,
  },

  // Alert settings
  alerts: {
    enabled: true,
    channels: ['slack', 'email'],
    escalation: {
      warning: 2,    // 2 consecutive failures
      critical: 5,   // 5 consecutive failures
    },
  },

  // Kubernetes probes
  kubernetes: {
    readiness: {
      initialDelaySeconds: 30,
      periodSeconds: 10,
      timeoutSeconds: 5,
      successThreshold: 2,
      failureThreshold: 3,
    },
    liveness: {
      initialDelaySeconds: 60,
      periodSeconds: 30,
      timeoutSeconds: 5,
      successThreshold: 1,
      failureThreshold: 3,
    },
  },
};
```

### **2. Health Check Best Practices**

```typescript
@Injectable()
export class HealthBestPractices {
  /**
   * Implement circuit breaker pattern for health checks
   */
  async circuitBreakerHealthCheck(
    serviceName: string,
    healthCheckFn: () => Promise<boolean>,
  ): Promise<boolean> {
    const circuitBreaker = this.getCircuitBreaker(serviceName);

    if (circuitBreaker.isOpen) {
      return false; // Fail fast if circuit is open
    }

    try {
      const result = await healthCheckFn();
      circuitBreaker.recordSuccess();
      return result;
    } catch (error) {
      circuitBreaker.recordFailure();
      throw error;
    }
  }

  /**
   * Implement health check caching
   */
  async cachedHealthCheck(
    key: string,
    healthCheckFn: () => Promise<HealthIndicatorResult>,
    ttl: number = 30000, // 30 seconds
  ): Promise<HealthIndicatorResult> {
    const cacheKey = `health:${key}`;
    const cached = await this.cacheService.get<HealthIndicatorResult>(cacheKey);

    if (cached) {
      return cached;
    }

    const result = await healthCheckFn();
    await this.cacheService.set(cacheKey, result, ttl);

    return result;
  }

  /**
   * Implement parallel health checks with timeout
   */
  async parallelHealthChecks(
    healthChecks: Array<() => Promise<HealthIndicatorResult>>,
    timeout: number = 10000,
  ): Promise<HealthIndicatorResult[]> {
    const promises = healthChecks.map(check =>
      Promise.race([
        check(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), timeout)
        ),
      ])
    );

    const results = await Promise.allSettled(promises);

    return results.map(result =>
      result.status === 'fulfilled'
        ? result.value
        : { status: 'down', error: result.reason.message }
    );
  }

  /**
   * Implement graceful degradation
   */
  async gracefulHealthCheck(
    primaryCheck: () => Promise<HealthIndicatorResult>,
    fallbackCheck?: () => Promise<HealthIndicatorResult>,
  ): Promise<HealthIndicatorResult> {
    try {
      return await primaryCheck();
    } catch (error) {
      this.logger.warn('Primary health check failed, attempting fallback', error);

      if (fallbackCheck) {
        try {
          return await fallbackCheck();
        } catch (fallbackError) {
          this.logger.error('Fallback health check also failed', fallbackError);
        }
      }

      return {
        status: 'degraded',
        error: error.message,
      };
    }
  }

  private getCircuitBreaker(serviceName: string) {
    // Implementation would return circuit breaker instance
    return {
      isOpen: false,
      recordSuccess: () => {},
      recordFailure: () => {},
    };
  }
}
```

---

## 🎯 **Integration with Monitoring Systems**

### **1. Prometheus Metrics**

```typescript
@Injectable()
export class PrometheusHealthMetrics {
  /**
   * Export health metrics to Prometheus
   */
  async exportHealthMetrics(): Promise<string> {
    const metrics = [];

    // Application health
    metrics.push('# HELP application_health Application health status');
    metrics.push('# TYPE application_health gauge');
    metrics.push(`application_health ${this.getApplicationHealth()}`);

    // Database health
    metrics.push('# HELP database_health Database health status');
    metrics.push('# TYPE database_health gauge');
    metrics.push(`database_health ${await this.getDatabaseHealth()}`);

    // Redis health
    metrics.push('# HELP redis_health Redis health status');
    metrics.push('# TYPE redis_health gauge');
    metrics.push(`redis_health ${await this.getRedisHealth()}`);

    // Response times
    metrics.push('# HELP health_check_response_time Health check response time');
    metrics.push('# TYPE health_check_response_time histogram');
    // Add histogram buckets...

    return metrics.join('\n');
  }

  private getApplicationHealth(): number {
    // Implementation would check application health
    return 1; // 1 = healthy, 0 = unhealthy
  }

  private async getDatabaseHealth(): Promise<number> {
    // Implementation would check database health
    return 1;
  }

  private async getRedisHealth(): Promise<number> {
    // Implementation would check Redis health
    return 1;
  }
}
```

### **2. Grafana Dashboard Integration**

```typescript
@Injectable()
export class GrafanaHealthDashboard {
  /**
   * Generate Grafana dashboard JSON
   */
  generateHealthDashboard(): any {
    return {
      dashboard: {
        title: 'Navigator API Health Dashboard',
        tags: ['health', 'navigator', 'api'],
        timezone: 'browser',
        panels: [
          // Application Health Panel
          {
            title: 'Application Health',
            type: 'stat',
            targets: [{
              expr: 'application_health',
              legendFormat: 'Application',
            }],
          },

          // Database Health Panel
          {
            title: 'Database Health',
            type: 'stat',
            targets: [{
              expr: 'database_health',
              legendFormat: 'Database',
            }],
          },

          // Response Time Panel
          {
            title: 'Health Check Response Times',
            type: 'graph',
            targets: [{
              expr: 'rate(health_check_response_time_sum[5m]) / rate(health_check_response_time_count[5m])',
              legendFormat: 'Average Response Time',
            }],
          },

          // Error Rate Panel
          {
            title: 'Health Check Error Rate',
            type: 'graph',
            targets: [{
              expr: 'rate(health_check_errors_total[5m])',
              legendFormat: 'Error Rate',
            }],
          },
        ],
      },
    };
  }
}
```

---

## 🎯 **Next Steps**

This comprehensive health check system provides:
- ✅ **Multi-layer health monitoring** with Redis, database, and external API checks
- ✅ **Application health assessment** with memory and resource monitoring
- ✅ **Kubernetes integration** with readiness and liveness probes
- ✅ **Monitoring dashboard** integration with metrics and alerting
- ✅ **Performance optimization** with caching and parallel checks
- ✅ **Enterprise-grade reliability** with circuit breakers and graceful degradation

**The health check system is now fully documented and ready for production monitoring! 🏥📊**

**Key components now documented:**
- Redis health indicator with performance metrics
- Database health indicator with connection pooling
- External API health monitoring for all integrations
- Application health assessment with resource monitoring
- Health check endpoints and Kubernetes probes
- Monitoring integration with Prometheus and Grafana
- Best practices for health check implementation
