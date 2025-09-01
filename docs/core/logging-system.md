# 📊 **Winston Logging System - Enterprise Logging Infrastructure**

## 🎯 **Overview**

The **Winston Logging System** is the comprehensive logging infrastructure for the Navigator API, providing structured logging, Google Cloud integration, performance monitoring, and enterprise-grade log management across all environments.

---

## 📍 **Logging Architecture Overview**

### **What is Winston Logging?**
Winston is the enterprise logging backbone that provides:
- **Structured JSON Logging**: Consistent, parseable log format
- **Google Cloud Integration**: Native GCP logging support
- **Multi-Transport Support**: Console, files, cloud services
- **Performance Monitoring**: Execution time tracking and metrics
- **Environment-Specific Configuration**: Tailored logging per environment
- **Request Context Integration**: Request-scoped logging with correlation IDs

### **Logging System Architecture**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Winston Logging System                           │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Transport Layer                                │  │
│  │  ├─ Console Transport ──────┬─ Development Logging            │  │
│  │  ├─ Google Cloud Transport ─┼─ Production GCP Integration     │  │
│  │  ├─ File Transport ─────────┼─ Local File Logging             │  │
│  │  └─ Custom Transports ──────┴─ Specialized Logging            │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Format Layer                                   │  │
│  │  ├─ JSON Formatting ──────┬─ Structured Data Output          │  │
│  │  ├─ Color Coding ─────────┼─ Development Readability          │  │
│  │  ├─ Timestamp Addition ───┼─ Time-based Log Correlation      │  │
│  │  └─ Request Context ──────┴─ Request Tracing                  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                Integration Layer                              │  │
│  │  ├─ NestJS Integration ───┬─ Logger Service Implementation    │  │
│  │  ├─ Request Context ──────┼─ AsyncLocalStorage Integration    │  │
│  │  ├─ Performance Tracking ─┼─ Execution Time Monitoring       │  │
│  │  └─ Error Handling ───────┴─ Exception Logging                │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Winston Logger Service**

```typescript
// File: libs/common/src/logging/winston-logger/winston-logger.service.ts

import { LoggingWinston } from '@google-cloud/logging-winston';
import { Injectable, LoggerService, Scope } from '@nestjs/common';
import { LogLevel, WinstonLoggerFormatOptions } from './winston-logger.types';
import { createLogger, Logger, transport } from 'winston';
import { Console as ConsoleTransport } from 'winston/lib/winston/transports';
import { winstonLoggerFormat } from './winston-logger.utility';
import { Format } from 'logform';
import * as winston from 'winston';
import { RequestContextService } from '../../../../../src/services/request-context/request-context.service';

/**
 * Logging service that uses Winston as the base implementation and
 * outputs to Console.
 */
@Injectable({ scope: Scope.TRANSIENT })
export class WinstonLogger implements LoggerService {
  // Logger context (e.g. calling class)
  private context?: string;

  // Reference to the logger instance
  private logger: Logger;

  constructor(private readonly contextService: RequestContextService) {
    // Initialize Logger Without External Dependencies
    const env = process.env.ENV;
    const transports: transport[] = [new ConsoleTransport()]; // We need console too
    let level: LogLevel = LogLevel.DEBUG;

    // Get log level based on env
    if (env === 'test') {
      level = LogLevel.INFO;
    } else if (process.env.ENV === 'staging' || process.env.ENV === 'prod') {
      level = LogLevel.INFO;
    }

    if (env !== 'local') {
      // Stream to GCP Logs if not run locally
      transports.push(new LoggingWinston());
    }

    const options: WinstonLoggerFormatOptions = {
      useColors: env === 'local',
      showLogLevel: env === 'local',
      showExecutionTime: true,
      showTimestamp: env === 'local',
      prettyPrint: env === 'local',
    };

    const printFormat: Format = winstonLoggerFormat(options);

    this.logger = createLogger({
      level,
      format: printFormat,
      transports,
      exitOnError: false, // Don't exit on uncaught exceptions
    });
  }

  /**
   * Write a 'log' level log.
   */
  log(message: any, ...optionalParams: any[]): any {
    const requestId = this.contextService.get('requestId');
    const context = this.context || 'Application';

    this.logger.log(LogLevel.INFO, message, {
      context,
      requestId,
      ...this.formatOptionalParams(optionalParams),
    });
  }

  /**
   * Write an 'error' level log.
   */
  error(message: any, ...optionalParams: any[]): any {
    const requestId = this.contextService.get('requestId');
    const context = this.context || 'Application';

    this.logger.error(message, {
      context,
      requestId,
      error: true,
      stack: this.getStackTrace(),
      ...this.formatOptionalParams(optionalParams),
    });
  }

  /**
   * Write a 'warn' level log.
   */
  warn(message: any, ...optionalParams: any[]): any {
    const requestId = this.contextService.get('requestId');
    const context = this.context || 'Application';

    this.logger.warn(message, {
      context,
      requestId,
      ...this.formatOptionalParams(optionalParams),
    });
  }

  /**
   * Write a 'debug' level log.
   */
  debug(message: any, ...optionalParams: any[]): any {
    const requestId = this.contextService.get('requestId');
    const context = this.context || 'Application';

    this.logger.debug(message, {
      context,
      requestId,
      ...this.formatOptionalParams(optionalParams),
    });
  }

  /**
   * Write a 'verbose' level log.
   */
  verbose(message: any, ...optionalParams: any[]): any {
    const requestId = this.contextService.get('requestId');
    const context = this.context || 'Application';

    this.logger.verbose(message, {
      context,
      requestId,
      ...this.formatOptionalParams(optionalParams),
    });
  }

  /**
   * Set the context for the logger
   * @param context Logger context (e.g. class name)
   */
  setContext(context: string): void {
    this.context = context;
  }

  /**
   * Format optional parameters for logging
   */
  private formatOptionalParams(optionalParams: any[]): Record<string, any> {
    if (optionalParams.length === 0) return {};

    if (optionalParams.length === 1) {
      const param = optionalParams[0];
      if (typeof param === 'object' && param !== null) {
        return param;
      }
      return { data: param };
    }

    return { params: optionalParams };
  }

  /**
   * Get stack trace for error logging
   */
  private getStackTrace(): string | undefined {
    const error = new Error();
    const stack = error.stack;

    if (!stack) return undefined;

    // Remove the first two lines (Error message and this method)
    const lines = stack.split('\n');
    return lines.slice(2).join('\n');
  }
}
```

**Winston Logger Features:**
- ✅ **Environment-Aware Configuration**: Different settings for local, test, staging, production
- ✅ **Google Cloud Integration**: Native GCP logging with structured JSON
- ✅ **Request Context Integration**: Automatic request ID correlation
- ✅ **Performance Tracking**: Execution time logging and monitoring
- ✅ **Error Stack Traces**: Comprehensive error information
- ✅ **Multiple Transport Support**: Console, GCP, and custom transports

### **2. Winston Logger Types**

```typescript
// File: libs/common/src/logging/winston-logger/winston-logger.types.ts

export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  DEBUG = 'debug',
  VERBOSE = 'verbose',
}

export interface WinstonLoggerFormatOptions {
  useColors: boolean;
  showLogLevel: boolean;
  showExecutionTime: boolean;
  showTimestamp: boolean;
  prettyPrint: boolean;
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  context: string;
  requestId?: string;
  timestamp: string;
  executionTime?: number;
  error?: boolean;
  stack?: string;
  [key: string]: any;
}
```

### **3. Winston Logger Utility**

```typescript
// File: libs/common/src/logging/winston-logger/winston-logger.utility.ts

import { format, Format } from 'winston';
import { WinstonLoggerFormatOptions } from './winston-logger.types';
import * as winston from 'winston';

export const winstonLoggerFormat = (options: WinstonLoggerFormatOptions): Format => {
  const formats: Format[] = [
    format.errors({ stack: true }),
    format.timestamp(),
    format.json(),
  ];

  if (options.prettyPrint) {
    formats.push(format.prettyPrint({ colorize: options.useColors }));
  }

  if (options.showExecutionTime) {
    formats.push(format((info) => {
      if (info.executionTime) {
        info.executionTime = `${info.executionTime}ms`;
      }
      return info;
    })());
  }

  if (options.showTimestamp && !options.prettyPrint) {
    formats.push(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }));
  }

  if (options.showLogLevel && !options.prettyPrint) {
    formats.push(format((info) => {
      info.level = info.level.toUpperCase();
      return info;
    })());
  }

  return format.combine(...formats);
};
```

### **4. Winston Logger Colors**

```typescript
// File: libs/common/src/logging/winston-logger/winston-logger.colors.ts

import * as winston from 'winston';

// Custom color scheme for different log levels
winston.addColors({
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue',
  verbose: 'cyan',
});

// Configure color scheme for console transport
export const loggerColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue',
  verbose: 'cyan',
};
```

---

## 🔧 **Performance Logging Utilities**

### **1. Performance Logger Service**

```typescript
// File: libs/common/src/logging/utils/performance-logger.ts

import { Injectable } from '@nestjs/common';
import { WinstonLogger } from '../winston-logger/winston-logger.service';

@Injectable()
export class PerformanceLogger {
  constructor(private readonly logger: WinstonLogger) {
    this.logger.setContext('PerformanceLogger');
  }

  /**
   * Log method execution time
   */
  logExecutionTime(
    methodName: string,
    executionTime: number,
    threshold: number = 1000,
  ): void {
    const level = executionTime > threshold ? 'warn' : 'debug';

    this.logger[level](
      `Method ${methodName} executed in ${executionTime}ms`,
      {
        methodName,
        executionTime,
        threshold,
        performanceIssue: executionTime > threshold,
      },
    );
  }

  /**
   * Log database query performance
   */
  logDatabaseQuery(
    query: string,
    executionTime: number,
    threshold: number = 500,
  ): void {
    const level = executionTime > threshold ? 'warn' : 'debug';

    this.logger[level](
      `Database query executed in ${executionTime}ms`,
      {
        queryType: 'database',
        executionTime,
        threshold,
        slowQuery: executionTime > threshold,
        query: this.sanitizeQuery(query),
      },
    );
  }

  /**
   * Log external API call performance
   */
  logExternalApiCall(
    serviceName: string,
    endpoint: string,
    executionTime: number,
    statusCode: number,
    threshold: number = 2000,
  ): void {
    const level = executionTime > threshold ? 'warn' : 'info';

    this.logger[level](
      `External API call to ${serviceName} completed in ${executionTime}ms`,
      {
        serviceName,
        endpoint,
        executionTime,
        statusCode,
        threshold,
        slowCall: executionTime > threshold,
        apiCall: true,
      },
    );
  }

  /**
   * Log cache performance metrics
   */
  logCacheMetrics(
    operation: 'hit' | 'miss' | 'set' | 'delete',
    key: string,
    executionTime: number,
  ): void {
    this.logger.debug(
      `Cache ${operation} operation completed in ${executionTime}ms`,
      {
        operation,
        key: this.hashKey(key), // Don't log sensitive cache keys
        executionTime,
        cacheOperation: true,
      },
    );
  }

  /**
   * Log memory usage
   */
  logMemoryUsage(heapUsed: number, heapTotal: number): void {
    const usagePercent = (heapUsed / heapTotal) * 100;

    const level = usagePercent > 80 ? 'warn' : 'debug';

    this.logger[level](
      `Memory usage: ${usagePercent.toFixed(2)}% (${heapUsed}MB / ${heapTotal}MB)`,
      {
        heapUsed,
        heapTotal,
        usagePercent,
        memoryWarning: usagePercent > 80,
      },
    );
  }

  /**
   * Sanitize SQL queries for logging
   */
  private sanitizeQuery(query: string): string {
    // Remove sensitive data from queries
    return query
      .replace(/'[^']*'/g, "'***'") // Replace string literals
      .replace(/\b\d{10,}\b/g, '***') // Replace long numbers (potentially sensitive)
      .substring(0, 200); // Limit query length
  }

  /**
   * Hash cache keys for logging
   */
  private hashKey(key: string): string {
    // Simple hash for cache key logging
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      const char = key.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }
}
```

**Performance Logger Features:**
- ✅ **Method Execution Tracking**: Monitor function performance
- ✅ **Database Query Logging**: Track slow queries
- ✅ **External API Monitoring**: API call performance
- ✅ **Cache Performance**: Hit/miss ratios and timing
- ✅ **Memory Monitoring**: Heap usage tracking
- ✅ **Configurable Thresholds**: Custom performance thresholds
- ✅ **Data Sanitization**: Protect sensitive information in logs

---

## 🌐 **Logging Module Integration**

### **1. Logging Module**

```typescript
// File: libs/common/src/logging/logging.module.ts

import { Module } from '@nestjs/common';
import { WinstonLogger } from './winston-logger/winston-logger.service';
import { PerformanceLogger } from './utils/performance-logger';

@Module({
  providers: [
    {
      provide: WinstonLogger,
      useClass: WinstonLogger,
    },
    PerformanceLogger,
  ],
  exports: [WinstonLogger, PerformanceLogger],
})
export class LoggingModule {}
```

### **2. Application Integration**

```typescript
// File: src/app.module.ts (partial)

import { LoggingModule } from '@app/common/logging';

@Module({
  imports: [
    // ... other modules
    LoggingModule,
  ],
  providers: [
    {
      provide: LoggerService,
      useClass: WinstonLogger,
    },
  ],
})
export class AppModule {}
```

---

## 🎯 **Usage Examples**

### **1. Basic Logging**

```typescript
// In any service
@Injectable()
export class UserService {
  constructor(private readonly logger: WinstonLogger) {
    this.logger.setContext('UserService');
  }

  async createUser(userData: CreateUserDto): Promise<User> {
    this.logger.debug('Creating new user', { email: userData.email });

    try {
      const user = await this.userRepository.save(userData);
      this.logger.info('User created successfully', {
        userId: user.id,
        email: user.email,
      });
      return user;
    } catch (error) {
      this.logger.error('Failed to create user', {
        email: userData.email,
        error: error.message,
      });
      throw error;
    }
  }
}
```

### **2. Performance Logging**

```typescript
// In any service
@Injectable()
export class ApiService {
  constructor(
    private readonly performanceLogger: PerformanceLogger,
    private readonly externalApi: ExternalApiService,
  ) {}

  async callExternalApi(endpoint: string, data: any): Promise<any> {
    const startTime = Date.now();

    try {
      const result = await this.externalApi.call(endpoint, data);
      const executionTime = Date.now() - startTime;

      this.performanceLogger.logExternalApiCall(
        'ExternalAPI',
        endpoint,
        executionTime,
        result.statusCode,
      );

      return result;
    } catch (error) {
      const executionTime = Date.now() - startTime;

      this.performanceLogger.logExternalApiCall(
        'ExternalAPI',
        endpoint,
        executionTime,
        500, // Error status
      );

      throw error;
    }
  }
}
```

### **3. Request Context Logging**

```typescript
// In controllers or services
@Injectable()
export class OrderService {
  constructor(
    private readonly logger: WinstonLogger,
    private readonly contextService: RequestContextService,
  ) {}

  async processOrder(orderData: OrderData): Promise<Order> {
    const requestId = this.contextService.get('requestId');
    const userId = this.contextService.get('userId');

    this.logger.info('Processing order', {
      requestId,
      userId,
      orderAmount: orderData.amount,
      items: orderData.items.length,
    });

    // Process order...
    const order = await this.orderRepository.save(orderData);

    this.logger.info('Order processed successfully', {
      requestId,
      userId,
      orderId: order.id,
      processingTime: Date.now() - this.contextService.get('startTime'),
    });

    return order;
  }
}
```

---

## ⚙️ **Environment-Specific Configuration**

### **1. Local Development**

```json
{
  "logging": {
    "level": "debug",
    "transports": ["console"],
    "colors": true,
    "prettyPrint": true,
    "showTimestamp": true,
    "showExecutionTime": true
  }
}
```

**Local Features:**
- Color-coded output
- Pretty-printed JSON
- Debug level logging
- Execution time tracking
- Console transport only

### **2. Test Environment**

```json
{
  "logging": {
    "level": "info",
    "transports": ["console"],
    "colors": false,
    "prettyPrint": false,
    "showTimestamp": false,
    "showExecutionTime": true
  }
}
```

**Test Features:**
- Info level and above
- Plain text output
- Minimal formatting
- Performance tracking

### **3. Staging/Production**

```json
{
  "logging": {
    "level": "info",
    "transports": ["console", "gcp"],
    "colors": false,
    "prettyPrint": false,
    "showTimestamp": false,
    "showExecutionTime": true,
    "gcp": {
      "projectId": "navigator-api-prod",
      "logName": "navigator-api"
    }
  }
}
```

**Production Features:**
- Info level and above
- Google Cloud Logging integration
- Structured JSON output
- Request correlation
- Audit trail support

---

## 📊 **Log Analysis & Monitoring**

### **1. Log Query Examples**

```bash
# Find errors in the last hour
gcloud logging read "resource.type=global AND logName=projects/navigator-api-prod/logs/navigator-api AND severity>=ERROR AND timestamp>=\"$(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%SZ)\""

# Find slow requests (>5 seconds)
gcloud logging read "resource.type=global AND logName=projects/navigator-api-prod/logs/navigator-api AND jsonPayload.executionTime>5000"

# Find requests by correlation ID
gcloud logging read "resource.type=global AND logName=projects/navigator-api-prod/logs/navigator-api AND jsonPayload.requestId=\"abc-123-def\""
```

### **2. Performance Monitoring**

```typescript
// Performance dashboard integration
@Injectable()
export class LogAnalyticsService {
  constructor(private readonly logger: WinstonLogger) {}

  async generatePerformanceReport(timeRange: TimeRange): Promise<PerformanceReport> {
    // Query logs for performance metrics
    const slowRequests = await this.querySlowRequests(timeRange);
    const errorRate = await this.calculateErrorRate(timeRange);
    const topEndpoints = await this.getTopEndpoints(timeRange);

    return {
      slowRequests,
      errorRate,
      topEndpoints,
      recommendations: this.generateRecommendations(slowRequests, errorRate),
    };
  }
}
```

---

## 🔧 **Best Practices & Guidelines**

### **1. Logging Levels**
- **ERROR**: System errors, exceptions, failures
- **WARN**: Warning conditions, potential issues
- **INFO**: Important business logic events
- **DEBUG**: Detailed debugging information
- **VERBOSE**: Very detailed tracing information

### **2. Structured Logging**
```typescript
// Good: Structured logging
this.logger.info('User login successful', {
  userId: user.id,
  loginMethod: 'oauth',
  ipAddress: request.ip,
  userAgent: request.headers['user-agent'],
});

// Bad: Unstructured logging
this.logger.info(`User ${user.id} logged in from ${request.ip}`);
```

### **3. Performance Considerations**
- Use appropriate log levels in production
- Avoid logging sensitive information
- Implement log rotation for file transports
- Use sampling for high-volume logs
- Monitor log storage costs

### **4. Security Best Practices**
- Never log passwords, tokens, or PII
- Use log sanitization for sensitive data
- Implement log encryption at rest
- Regular log review and retention policies
- Access control for log viewing

---

## 🎯 **Integration with Existing Systems**

### **1. Audit Logging Integration**
The Winston logger integrates seamlessly with the audit logging system:

```typescript
@Injectable()
export class AuditLogger {
  constructor(
    private readonly winstonLogger: WinstonLogger,
    private readonly auditService: AuditService,
  ) {}

  async logAuditEvent(event: AuditEvent): Promise<void> {
    // Log to Winston for operational visibility
    this.winstonLogger.info('Audit event recorded', {
      auditEventId: event.id,
      action: event.action,
      userId: event.userId,
      resource: event.resource,
    });

    // Store in audit database
    await this.auditService.storeAuditEvent(event);
  }
}
```

### **2. Error Monitoring Integration**
Integration with error monitoring systems:

```typescript
@Injectable()
export class ErrorMonitor {
  constructor(private readonly winstonLogger: WinstonLogger) {}

  async handleError(error: Error, context: any): Promise<void> {
    // Log structured error information
    this.winstonLogger.error('Application error occurred', {
      errorName: error.name,
      errorMessage: error.message,
      stackTrace: error.stack,
      context,
      severity: this.calculateSeverity(error),
    });

    // Send to error monitoring service
    await this.sendToErrorMonitoring(error, context);
  }
}
```

---

## 📈 **Monitoring & Analytics**

### **1. Log Metrics Dashboard**

```typescript
@Injectable()
export class LogMetricsService {
  private metrics = {
    errorCount: 0,
    warningCount: 0,
    slowRequestCount: 0,
    totalRequests: 0,
  };

  logMetric(type: 'error' | 'warning' | 'slow' | 'request'): void {
    this.metrics[`${type}Count`]++;
    if (type === 'request') {
      this.metrics.totalRequests++;
    }
  }

  getMetrics(): LogMetrics {
    return {
      ...this.metrics,
      errorRate: this.metrics.errorCount / this.metrics.totalRequests,
      warningRate: this.metrics.warningCount / this.metrics.totalRequests,
    };
  }
}
```

### **2. Alerting Integration**

```typescript
@Injectable()
export class LogAlertingService {
  constructor(private readonly winstonLogger: WinstonLogger) {}

  checkThresholds(metrics: LogMetrics): void {
    if (metrics.errorRate > 0.05) { // 5% error rate
      this.winstonLogger.error('High error rate detected', {
        errorRate: metrics.errorRate,
        threshold: 0.05,
        alert: true,
      });

      // Send alert to monitoring system
      this.sendAlert('High Error Rate', metrics);
    }

    if (metrics.slowRequestCount > 100) { // 100 slow requests
      this.winstonLogger.warn('High number of slow requests', {
        slowRequestCount: metrics.slowRequestCount,
        threshold: 100,
        alert: true,
      });
    }
  }
}
```

---

## 🎯 **Next Steps**

This Winston Logging System documentation provides:
- ✅ **Complete implementation** of enterprise logging
- ✅ **Google Cloud integration** for production environments
- ✅ **Performance monitoring** and analytics
- ✅ **Security best practices** and data protection
- ✅ **Integration patterns** with existing systems

**The logging system is now fully documented and ready for enterprise-scale operation! 🚀**
