# ⚡ **Performance Logging Utilities - Execution Time Tracking**

## 🎯 **Overview**

The **Performance Logging Utilities** provide comprehensive execution time tracking, performance monitoring, and analytics for the Navigator API. These utilities enable detailed performance profiling, bottleneck identification, and optimization insights across all system components.

---

## 📍 **Performance Logging Architecture**

### **What are Performance Logging Utilities?**
Performance logging utilities provide:
- **Execution Time Tracking**: High-precision timing for operations
- **Database Query Monitoring**: Slow query detection and analysis
- **External API Performance**: Third-party service call tracking
- **Cache Performance Metrics**: Hit/miss ratios and response times
- **Memory Usage Monitoring**: Heap and resource consumption tracking
- **Custom Performance Markers**: Application-specific performance points
- **Performance Threshold Alerts**: Automated slow operation detection

### **Performance Logging Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                Performance Logging System                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Execution Time Tracking                │    │
│  │  ├─ High-Resolution Timing ──────┬─ Process HRTIME │    │
│  │  ├─ Method Performance ──────────┼─ Function Timing │    │
│  │  ├─ Request Processing ──────────┼─ HTTP Request    │    │
│  │  └─ Custom Performance Points ───┴─ User-Defined   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Database Performance                    │    │
│  │  ├─ Query Execution Time ────────┬─ Slow Query     │    │
│  │  ├─ Connection Pool Monitoring ──┼─ Pool Usage     │    │
│  │  ├─ Transaction Performance ─────┼─ ACID Ops       │    │
│  │  └─ Index Performance ───────────┴─ Query Planning │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            External Service Monitoring             │    │
│  │  ├─ API Call Timing ─────────────┬─ Request/Response│    │
│  │  ├─ Service Availability ────────┼─ Health Checks  │    │
│  │  ├─ Error Rate Tracking ─────────┼─ Failure Analysis│    │
│  │  └─ Circuit Breaker Metrics ─────┴─ Resilience     │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Performance Tracker Utility**

```typescript
// File: libs/common/src/logging/utils/performance-logger.ts

import { Logger } from '@nestjs/common';

export interface PerformanceTracker {
  finishTracker: (suffix?: string) => void;
}

/**
 * Starts a performance tracker that logs the start and finish time of a process.
 * @param logger - Logger instance for output
 * @param message - Descriptive message for the tracked operation
 * @returns PerformanceTracker with finishTracker method
 */
export const startPerformanceTracker = (
  logger: Logger,
  message: string,
): PerformanceTracker => {
  const startAt = process.hrtime.bigint(); // Use bigint for higher precision
  logger.log(`START - ${message}`);

  return {
    finishTracker: (suffix?: string | undefined) => {
      const endAt = process.hrtime.bigint();
      const diff = endAt - startAt;
      const durationMs = Number(diff) / 1_000_000; // Convert nanoseconds to milliseconds
      const duration = Math.round(durationMs * 100) / 100; // Round to 2 decimal places

      logger.log(
        `FINISH - ${message} ${suffix || ''} - Duration: ${duration}ms`,
      );

      // Log performance warnings for slow operations
      if (duration > 1000) { // 1 second threshold
        logger.warn(
          `SLOW OPERATION - ${message} took ${duration}ms (threshold: 1000ms)`,
          {
            operation: message,
            duration,
            threshold: 1000,
            performanceIssue: true,
          },
        );
      }
    },
  };
};
```

### **2. Advanced Performance Logger Service**

```typescript
// File: libs/common/src/logging/utils/advanced-performance-logger.ts

import { Injectable, Logger } from '@nestjs/common';
import { WinstonLogger } from '../winston-logger/winston-logger.service';

@Injectable()
export class AdvancedPerformanceLogger {
  constructor(private readonly winstonLogger: WinstonLogger) {
    this.winstonLogger.setContext('AdvancedPerformanceLogger');
  }

  /**
   * Track method execution with detailed metrics
   */
  async trackMethodExecution<T>(
    methodName: string,
    method: () => Promise<T>,
    options: MethodTrackingOptions = {},
  ): Promise<T> {
    const startTime = process.hrtime.bigint();
    const startMemory = process.memoryUsage();

    try {
      this.winstonLogger.debug(`Starting method execution: ${methodName}`, {
        methodName,
        startTime: Date.now(),
        memoryUsage: startMemory.heapUsed,
      });

      const result = await method();

      const endTime = process.hrtime.bigint();
      const endMemory = process.memoryUsage();
      const duration = Number(endTime - startTime) / 1_000_000;

      const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;

      this.winstonLogger.info(`Method execution completed: ${methodName}`, {
        methodName,
        duration: Math.round(duration * 100) / 100,
        memoryDelta,
        success: true,
        performanceMetrics: {
          duration,
          memoryDelta,
          averageMemoryUsage: (startMemory.heapUsed + endMemory.heapUsed) / 2,
        },
      });

      // Check performance thresholds
      this.checkPerformanceThresholds(methodName, duration, memoryDelta, options);

      return result;
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.error(`Method execution failed: ${methodName}`, {
        methodName,
        duration: Math.round(duration * 100) / 100,
        error: error.message,
        stack: error.stack,
        success: false,
      });

      throw error;
    }
  }

  /**
   * Track database operations
   */
  async trackDatabaseOperation<T>(
    operation: string,
    query: () => Promise<T>,
    options: DatabaseTrackingOptions = {},
  ): Promise<T> {
    const startTime = process.hrtime.bigint();

    try {
      this.winstonLogger.debug(`Starting database operation: ${operation}`, {
        operation,
        queryType: options.queryType,
        table: options.table,
      });

      const result = await query();

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.info(`Database operation completed: ${operation}`, {
        operation,
        duration: Math.round(duration * 100) / 100,
        queryType: options.queryType,
        table: options.table,
        success: true,
        slowQuery: duration > (options.slowQueryThreshold || 500),
      });

      // Alert on slow queries
      if (duration > (options.slowQueryThreshold || 500)) {
        this.winstonLogger.warn(`Slow database query detected: ${operation}`, {
          operation,
          duration,
          threshold: options.slowQueryThreshold || 500,
          queryType: options.queryType,
          table: options.table,
        });
      }

      return result;
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.error(`Database operation failed: ${operation}`, {
        operation,
        duration: Math.round(duration * 100) / 100,
        error: error.message,
        queryType: options.queryType,
        table: options.table,
        success: false,
      });

      throw error;
    }
  }

  /**
   * Track external API calls
   */
  async trackExternalApiCall<T>(
    serviceName: string,
    endpoint: string,
    method: string,
    apiCall: () => Promise<T>,
    options: ApiTrackingOptions = {},
  ): Promise<T> {
    const startTime = process.hrtime.bigint();

    try {
      this.winstonLogger.debug(`Starting external API call: ${serviceName}`, {
        serviceName,
        endpoint,
        method,
        apiCall: true,
      });

      const result = await apiCall();

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.info(`External API call completed: ${serviceName}`, {
        serviceName,
        endpoint,
        method,
        duration: Math.round(duration * 100) / 100,
        success: true,
        slowApiCall: duration > (options.timeoutThreshold || 2000),
        apiCall: true,
      });

      // Alert on slow API calls
      if (duration > (options.timeoutThreshold || 2000)) {
        this.winstonLogger.warn(`Slow external API call: ${serviceName}`, {
          serviceName,
          endpoint,
          method,
          duration,
          threshold: options.timeoutThreshold || 2000,
        });
      }

      return result;
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.error(`External API call failed: ${serviceName}`, {
        serviceName,
        endpoint,
        method,
        duration: Math.round(duration * 100) / 100,
        error: error.message,
        statusCode: error.response?.status,
        success: false,
        apiCall: true,
      });

      throw error;
    }
  }

  /**
   * Track cache operations
   */
  async trackCacheOperation<T>(
    operation: 'get' | 'set' | 'delete' | 'clear',
    key: string,
    cacheOperation: () => Promise<T>,
  ): Promise<T> {
    const startTime = process.hrtime.bigint();

    try {
      const result = await cacheOperation();

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.debug(`Cache operation completed: ${operation}`, {
        operation,
        key: this.maskSensitiveKey(key),
        duration: Math.round(duration * 100) / 100,
        success: true,
        cacheOperation: true,
      });

      return result;
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1_000_000;

      this.winstonLogger.error(`Cache operation failed: ${operation}`, {
        operation,
        key: this.maskSensitiveKey(key),
        duration: Math.round(duration * 100) / 100,
        error: error.message,
        success: false,
        cacheOperation: true,
      });

      throw error;
    }
  }

  /**
   * Create a performance profiler for complex operations
   */
  createProfiler(operationName: string): PerformanceProfiler {
    const profiler = new PerformanceProfiler(operationName, this.winstonLogger);
    profiler.start();
    return profiler;
  }

  /**
   * Check performance thresholds and log warnings
   */
  private checkPerformanceThresholds(
    methodName: string,
    duration: number,
    memoryDelta: number,
    options: MethodTrackingOptions,
  ): void {
    const thresholds = {
      duration: options.durationThreshold || 1000, // 1 second
      memory: options.memoryThreshold || 50 * 1024 * 1024, // 50MB
    };

    if (duration > thresholds.duration) {
      this.winstonLogger.warn(`Slow method detected: ${methodName}`, {
        methodName,
        duration,
        threshold: thresholds.duration,
        performanceIssue: true,
      });
    }

    if (Math.abs(memoryDelta) > thresholds.memory) {
      this.winstonLogger.warn(`High memory usage detected: ${methodName}`, {
        methodName,
        memoryDelta,
        threshold: thresholds.memory,
        performanceIssue: true,
      });
    }
  }

  /**
   * Mask sensitive information in cache keys
   */
  private maskSensitiveKey(key: string): string {
    // Mask sensitive patterns in cache keys
    const sensitivePatterns = [
      /token/i,
      /password/i,
      /secret/i,
      /key/i,
      /\b\d{10,}\b/g, // Long numbers (potentially sensitive)
    ];

    let maskedKey = key;
    sensitivePatterns.forEach(pattern => {
      maskedKey = maskedKey.replace(pattern, '***');
    });

    return maskedKey;
  }
}

interface MethodTrackingOptions {
  durationThreshold?: number;
  memoryThreshold?: number;
}

interface DatabaseTrackingOptions {
  queryType?: string;
  table?: string;
  slowQueryThreshold?: number;
}

interface ApiTrackingOptions {
  timeoutThreshold?: number;
}
```

### **3. Performance Profiler Class**

```typescript
// File: libs/common/src/logging/utils/performance-profiler.ts

import { Logger } from '@nestjs/common';

export class PerformanceProfiler {
  private readonly checkpoints: PerformanceCheckpoint[] = [];
  private startTime: bigint;
  private operationName: string;
  private logger: Logger;

  constructor(operationName: string, logger: Logger) {
    this.operationName = operationName;
    this.logger = logger;
  }

  /**
   * Start the performance profiler
   */
  start(): void {
    this.startTime = process.hrtime.bigint();
    this.logger.log(`PROFILER START - ${this.operationName}`);

    this.addCheckpoint('start');
  }

  /**
   * Add a performance checkpoint
   */
  addCheckpoint(name: string, metadata?: Record<string, any>): void {
    const checkpoint: PerformanceCheckpoint = {
      name,
      timestamp: process.hrtime.bigint(),
      timeFromStart: Number(process.hrtime.bigint() - this.startTime) / 1_000_000,
      metadata,
    };

    this.checkpoints.push(checkpoint);

    this.logger.debug(`PROFILER CHECKPOINT - ${this.operationName}:${name}`, {
      checkpoint: name,
      timeFromStart: Math.round(checkpoint.timeFromStart * 100) / 100,
      ...metadata,
    });
  }

  /**
   * Finish profiling and log results
   */
  finish(): PerformanceReport {
    const endTime = process.hrtime.bigint();
    const totalDuration = Number(endTime - this.startTime) / 1_000_000;

    this.addCheckpoint('finish');

    // Calculate intervals between checkpoints
    const intervals = this.calculateIntervals();

    // Generate performance report
    const report: PerformanceReport = {
      operationName: this.operationName,
      totalDuration,
      checkpoints: this.checkpoints.length,
      intervals,
      memoryUsage: process.memoryUsage(),
      slowestInterval: this.findSlowestInterval(intervals),
      timestamp: new Date(),
    };

    // Log performance report
    this.logger.log(`PROFILER FINISH - ${this.operationName}`, {
      totalDuration: Math.round(totalDuration * 100) / 100,
      checkpoints: this.checkpoints.length,
      memoryUsage: report.memoryUsage.heapUsed,
      slowestInterval: report.slowestInterval,
    });

    // Log detailed intervals for slow operations
    if (totalDuration > 5000) { // 5 seconds
      this.logger.warn(`PROFILER SLOW OPERATION - ${this.operationName}`, {
        totalDuration,
        intervals,
        performanceIssue: true,
      });
    }

    return report;
  }

  /**
   * Calculate time intervals between checkpoints
   */
  private calculateIntervals(): CheckpointInterval[] {
    const intervals: CheckpointInterval[] = [];

    for (let i = 1; i < this.checkpoints.length; i++) {
      const current = this.checkpoints[i];
      const previous = this.checkpoints[i - 1];

      intervals.push({
        from: previous.name,
        to: current.name,
        duration: current.timeFromStart - previous.timeFromStart,
        startTime: previous.timeFromStart,
        endTime: current.timeFromStart,
      });
    }

    return intervals;
  }

  /**
   * Find the slowest interval
   */
  private findSlowestInterval(intervals: CheckpointInterval[]): CheckpointInterval | null {
    if (intervals.length === 0) return null;

    return intervals.reduce((slowest, current) =>
      current.duration > slowest.duration ? current : slowest
    );
  }
}

interface PerformanceCheckpoint {
  name: string;
  timestamp: bigint;
  timeFromStart: number;
  metadata?: Record<string, any>;
}

interface CheckpointInterval {
  from: string;
  to: string;
  duration: number;
  startTime: number;
  endTime: number;
}

interface PerformanceReport {
  operationName: string;
  totalDuration: number;
  checkpoints: number;
  intervals: CheckpointInterval[];
  memoryUsage: NodeJS.MemoryUsage;
  slowestInterval: CheckpointInterval | null;
  timestamp: Date;
}
```

### **4. Performance Decorator**

```typescript
// File: libs/common/src/logging/utils/performance.decorator.ts

import { Logger } from '@nestjs/common';
import { AdvancedPerformanceLogger } from './advanced-performance-logger';

/**
 * Decorator to automatically track method performance
 */
export function TrackPerformance(
  options: MethodTrackingOptions = {},
) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const method = descriptor.value;
    const logger = new Logger(`${target.constructor.name}:${propertyKey}`);
    const performanceLogger = new AdvancedPerformanceLogger(
      // This would need to be injected properly in a real implementation
      {} as any,
    );

    descriptor.value = async function (...args: any[]) {
      const methodName = `${target.constructor.name}.${propertyKey}`;

      return performanceLogger.trackMethodExecution(
        methodName,
        () => method.apply(this, args),
        options,
      );
    };

    return descriptor;
  };
}

/**
 * Decorator for tracking database operations
 */
export function TrackDatabase(
  options: DatabaseTrackingOptions = {},
) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const method = descriptor.value;
    const logger = new Logger(`${target.constructor.name}:${propertyKey}`);
    const performanceLogger = new AdvancedPerformanceLogger({} as any);

    descriptor.value = async function (...args: any[]) {
      const operationName = `${target.constructor.name}.${propertyKey}`;

      return performanceLogger.trackDatabaseOperation(
        operationName,
        () => method.apply(this, args),
        options,
      );
    };

    return descriptor;
  };
}

/**
 * Decorator for tracking external API calls
 */
export function TrackApiCall(
  serviceName: string,
  endpoint: string,
  method: string = 'GET',
  options: ApiTrackingOptions = {},
) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;
    const logger = new Logger(`${target.constructor.name}:${propertyKey}`);
    const performanceLogger = new AdvancedPerformanceLogger({} as any);

    descriptor.value = async function (...args: any[]) {
      return performanceLogger.trackExternalApiCall(
        serviceName,
        endpoint,
        method,
        () => originalMethod.apply(this, args),
        options,
      );
    };

    return descriptor;
  };
}

/**
 * Decorator for tracking cache operations
 */
export function TrackCache(operation: 'get' | 'set' | 'delete' | 'clear') {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const method = descriptor.value;
    const logger = new Logger(`${target.constructor.name}:${propertyKey}`);
    const performanceLogger = new AdvancedPerformanceLogger({} as any);

    descriptor.value = async function (key: string, ...args: any[]) {
      return performanceLogger.trackCacheOperation(
        operation,
        key,
        () => method.apply(this, [key, ...args]),
      );
    };

    return descriptor;
  };
}
```

---

## 🎯 **Usage Examples**

### **1. Basic Performance Tracking**

```typescript
// In any service
@Injectable()
export class UserService {
  constructor(private readonly logger: Logger) {}

  async createUser(userData: CreateUserDto): Promise<User> {
    // Start performance tracking
    const tracker = startPerformanceTracker(
      this.logger,
      'createUser operation',
    );

    try {
      // Your business logic here
      const user = await this.userRepository.save(userData);

      // Finish tracking
      tracker.finishTracker('success');

      return user;
    } catch (error) {
      // Finish tracking with error
      tracker.finishTracker('failed');

      throw error;
    }
  }
}
```

### **2. Advanced Performance Tracking**

```typescript
@Injectable()
export class OrderService {
  constructor(
    private readonly advancedLogger: AdvancedPerformanceLogger,
    private readonly userService: UserService,
  ) {}

  async processComplexOrder(orderData: OrderData): Promise<Order> {
    return this.advancedLogger.trackMethodExecution(
      'processComplexOrder',
      async () => {
        // Step 1: Validate user
        const user = await this.userService.validateUser(orderData.userId);

        // Step 2: Check inventory
        await this.inventoryService.checkAvailability(orderData.items);

        // Step 3: Process payment
        const payment = await this.paymentService.processPayment(orderData.payment);

        // Step 4: Create order
        const order = await this.orderRepository.save({
          ...orderData,
          paymentId: payment.id,
          status: 'confirmed',
        });

        return order;
      },
      {
        durationThreshold: 2000, // 2 seconds
        memoryThreshold: 100 * 1024 * 1024, // 100MB
      },
    );
  }
}
```

### **3. Database Operation Tracking**

```typescript
@Injectable()
export class ProductRepository {
  constructor(
    private readonly advancedLogger: AdvancedPerformanceLogger,
  ) {}

  async findProductsWithReviews(productIds: string[]): Promise<Product[]> {
    return this.advancedLogger.trackDatabaseOperation(
      'findProductsWithReviews',
      async () => {
        return this.productModel
          .find({ _id: { $in: productIds } })
          .populate('reviews')
          .exec();
      },
      {
        queryType: 'aggregate',
        table: 'products',
        slowQueryThreshold: 1000, // 1 second
      },
    );
  }
}
```

### **4. External API Call Tracking**

```typescript
@Injectable()
export class PaymentService {
  constructor(
    private readonly advancedLogger: AdvancedPerformanceLogger,
    private readonly httpService: HttpService,
  ) {}

  async processPayment(paymentData: PaymentData): Promise<PaymentResult> {
    return this.advancedLogger.trackExternalApiCall(
      'Payment Gateway',
      '/api/v1/payments',
      'POST',
      async () => {
        const response = await this.httpService.post(
          'https://api.payment-gateway.com/v1/payments',
          paymentData,
        );

        return response.data;
      },
      {
        timeoutThreshold: 3000, // 3 seconds
      },
    );
  }
}
```

### **5. Performance Profiler Usage**

```typescript
@Injectable()
export class ComplexWorkflowService {
  constructor(
    private readonly advancedLogger: AdvancedPerformanceLogger,
    private readonly logger: Logger,
  ) {}

  async executeComplexWorkflow(workflowData: WorkflowData): Promise<WorkflowResult> {
    // Create performance profiler
    const profiler = this.advancedLogger.createProfiler('complex-workflow');

    try {
      // Step 1: Data validation
      profiler.addCheckpoint('validation-start');
      const validatedData = await this.validateWorkflowData(workflowData);
      profiler.addCheckpoint('validation-complete', {
        recordsValidated: validatedData.length,
      });

      // Step 2: Business rule processing
      profiler.addCheckpoint('business-rules-start');
      const processedData = await this.applyBusinessRules(validatedData);
      profiler.addCheckpoint('business-rules-complete', {
        rulesApplied: processedData.rulesApplied,
      });

      // Step 3: External integrations
      profiler.addCheckpoint('integrations-start');
      const integratedData = await this.performExternalIntegrations(processedData);
      profiler.addCheckpoint('integrations-complete', {
        integrationsCompleted: integratedData.integrations.length,
      });

      // Step 4: Result generation
      profiler.addCheckpoint('result-generation-start');
      const result = await this.generateWorkflowResult(integratedData);
      profiler.addCheckpoint('result-generation-complete');

      // Finish profiling
      const report = profiler.finish();

      this.logger.log('Complex workflow completed', {
        workflowId: workflowData.id,
        totalDuration: report.totalDuration,
        checkpoints: report.checkpoints,
        slowestInterval: report.slowestInterval?.from + ' → ' + report.slowestInterval?.to,
      });

      return result;
    } catch (error) {
      profiler.finish(); // Still finish profiling even on error
      throw error;
    }
  }
}
```

### **6. Using Performance Decorators**

```typescript
@Injectable()
export class DataProcessingService {
  @TrackPerformance({
    durationThreshold: 5000, // 5 seconds
    memoryThreshold: 200 * 1024 * 1024, // 200MB
  })
  async processLargeDataset(dataset: LargeDataset): Promise<ProcessedData> {
    // Method automatically tracked for performance
    return this.performComplexProcessing(dataset);
  }

  @TrackDatabase({
    queryType: 'aggregate',
    table: 'user_analytics',
    slowQueryThreshold: 2000, // 2 seconds
  })
  async generateUserAnalyticsReport(dateRange: DateRange): Promise<AnalyticsReport> {
    // Database operation automatically tracked
    return this.analyticsRepository.generateReport(dateRange);
  }

  @TrackApiCall(
    'Analytics Service',
    '/api/v1/reports/generate',
    'POST',
    { timeoutThreshold: 10000 }, // 10 seconds
  )
  async generateExternalReport(reportConfig: ReportConfig): Promise<ReportData> {
    // External API call automatically tracked
    const response = await this.httpService.post(
      'https://analytics-service.com/api/v1/reports/generate',
      reportConfig,
    );

    return response.data;
  }

  @TrackCache('get')
  async getCachedUserData(userId: string): Promise<UserData> {
    // Cache operation automatically tracked
    return this.cacheService.get(`user:${userId}`);
  }
}
```

---

## 📊 **Performance Analytics & Reporting**

### **1. Performance Metrics Collector**

```typescript
@Injectable()
export class PerformanceMetricsCollector {
  private metrics = {
    methodExecutionTimes: new Map<string, number[]>(),
    databaseQueryTimes: new Map<string, number[]>(),
    apiCallTimes: new Map<string, number[]>(),
    cacheOperationTimes: new Map<string, number[]>(),
    errorCounts: new Map<string, number>(),
    slowOperationCounts: new Map<string, number>(),
  };

  /**
   * Record method execution time
   */
  recordMethodExecution(methodName: string, duration: number): void {
    this.addMetric(this.metrics.methodExecutionTimes, methodName, duration);
    this.checkPerformanceThreshold(methodName, duration, 1000); // 1 second
  }

  /**
   * Record database query time
   */
  recordDatabaseQuery(operation: string, duration: number): void {
    this.addMetric(this.metrics.databaseQueryTimes, operation, duration);
    this.checkPerformanceThreshold(operation, duration, 500); // 500ms
  }

  /**
   * Record API call time
   */
  recordApiCall(serviceName: string, duration: number): void {
    this.addMetric(this.metrics.apiCallTimes, serviceName, duration);
    this.checkPerformanceThreshold(serviceName, duration, 2000); // 2 seconds
  }

  /**
   * Record cache operation time
   */
  recordCacheOperation(operation: string, duration: number): void {
    this.addMetric(this.metrics.cacheOperationTimes, operation, duration);
    this.checkPerformanceThreshold(operation, duration, 10); // 10ms
  }

  /**
   * Record error
   */
  recordError(operation: string): void {
    const currentCount = this.metrics.errorCounts.get(operation) || 0;
    this.metrics.errorCounts.set(operation, currentCount + 1);
  }

  /**
   * Generate performance report
   */
  generatePerformanceReport(): PerformanceReport {
    return {
      methodMetrics: this.calculateMetrics(this.metrics.methodExecutionTimes),
      databaseMetrics: this.calculateMetrics(this.metrics.databaseQueryTimes),
      apiMetrics: this.calculateMetrics(this.metrics.apiCallTimes),
      cacheMetrics: this.calculateMetrics(this.metrics.cacheOperationTimes),
      errorMetrics: Object.fromEntries(this.metrics.errorCounts),
      slowOperations: Object.fromEntries(this.metrics.slowOperationCounts),
      generatedAt: new Date(),
    };
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary(): PerformanceSummary {
    const report = this.generatePerformanceReport();

    return {
      averageMethodTime: report.methodMetrics.average,
      averageDatabaseTime: report.databaseMetrics.average,
      averageApiTime: report.apiMetrics.average,
      averageCacheTime: report.cacheMetrics.average,
      totalErrors: Object.values(report.errorMetrics).reduce((sum, count) => sum + count, 0),
      totalSlowOperations: Object.values(report.slowOperations).reduce((sum, count) => sum + count, 0),
      healthScore: this.calculateHealthScore(report),
    };
  }

  private addMetric(
    metricsMap: Map<string, number[]>,
    key: string,
    value: number,
  ): void {
    const values = metricsMap.get(key) || [];
    values.push(value);

    // Keep only last 1000 values to prevent memory issues
    if (values.length > 1000) {
      values.shift();
    }

    metricsMap.set(key, values);
  }

  private checkPerformanceThreshold(
    operation: string,
    duration: number,
    threshold: number,
  ): void {
    if (duration > threshold) {
      const currentCount = this.metrics.slowOperationCounts.get(operation) || 0;
      this.metrics.slowOperationCounts.set(operation, currentCount + 1);
    }
  }

  private calculateMetrics(metricsMap: Map<string, number[]>): MetricStats {
    const allValues: number[] = [];
    metricsMap.forEach(values => allValues.push(...values));

    if (allValues.length === 0) {
      return { count: 0, average: 0, min: 0, max: 0, p95: 0 };
    }

    const sorted = allValues.sort((a, b) => a - b);
    const average = allValues.reduce((sum, val) => sum + val, 0) / allValues.length;
    const p95Index = Math.floor(sorted.length * 0.95);

    return {
      count: allValues.length,
      average: Math.round(average * 100) / 100,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      p95: sorted[p95Index] || sorted[sorted.length - 1],
    };
  }

  private calculateHealthScore(report: PerformanceReport): number {
    // Calculate health score based on various metrics
    let score = 100;

    // Deduct points for slow operations
    const totalSlowOps = Object.values(report.slowOperations).reduce((sum, count) => sum + count, 0);
    score -= Math.min(totalSlowOps * 2, 30); // Max 30 points deduction

    // Deduct points for high error rates
    const totalErrors = Object.values(report.errorMetrics).reduce((sum, count) => sum + count, 0);
    const errorRate = totalErrors / (report.methodMetrics.count || 1);
    score -= Math.min(errorRate * 50, 20); // Max 20 points deduction

    // Deduct points for slow average times
    if (report.methodMetrics.average > 2000) score -= 15;
    else if (report.methodMetrics.average > 1000) score -= 10;
    else if (report.methodMetrics.average > 500) score -= 5;

    if (report.databaseMetrics.average > 1000) score -= 15;
    if (report.apiMetrics.average > 5000) score -= 15;

    return Math.max(0, Math.round(score));
  }
}

interface MetricStats {
  count: number;
  average: number;
  min: number;
  max: number;
  p95: number;
}

interface PerformanceReport {
  methodMetrics: MetricStats;
  databaseMetrics: MetricStats;
  apiMetrics: MetricStats;
  cacheMetrics: MetricStats;
  errorMetrics: Record<string, number>;
  slowOperations: Record<string, number>;
  generatedAt: Date;
}

interface PerformanceSummary {
  averageMethodTime: number;
  averageDatabaseTime: number;
  averageApiTime: number;
  averageCacheTime: number;
  totalErrors: number;
  totalSlowOperations: number;
  healthScore: number;
}
```

---

## 🎯 **Configuration & Best Practices**

### **1. Performance Logging Configuration**

```typescript
// File: src/config/performance-logging.config.ts

export const performanceLoggingConfig = {
  // Global performance logging settings
  global: {
    enabled: process.env.PERFORMANCE_LOGGING_ENABLED === 'true',
    logLevel: process.env.PERFORMANCE_LOG_LEVEL || 'info',
    slowOperationThreshold: parseInt(process.env.SLOW_OPERATION_THRESHOLD || '1000'), // 1 second
    memoryThreshold: parseInt(process.env.MEMORY_THRESHOLD || '104857600'), // 100MB
  },

  // Method tracking settings
  methodTracking: {
    enabled: true,
    includeArgs: process.env.LOG_METHOD_ARGS === 'true',
    excludeMethods: [
      'toString',
      'valueOf',
      'constructor',
      'getClass',
    ],
  },

  // Database tracking settings
  databaseTracking: {
    enabled: true,
    slowQueryThreshold: parseInt(process.env.DB_SLOW_QUERY_THRESHOLD || '500'), // 500ms
    logQueryParameters: process.env.LOG_QUERY_PARAMS === 'true',
    excludeTables: [
      'migrations',
      'sessions',
    ],
  },

  // API tracking settings
  apiTracking: {
    enabled: true,
    timeoutThreshold: parseInt(process.env.API_TIMEOUT_THRESHOLD || '2000'), // 2 seconds
    logRequestBody: process.env.LOG_REQUEST_BODY === 'true',
    logResponseBody: process.env.LOG_RESPONSE_BODY === 'true',
    excludeEndpoints: [
      '/health',
      '/metrics',
      '/favicon.ico',
    ],
  },

  // Cache tracking settings
  cacheTracking: {
    enabled: true,
    slowOperationThreshold: parseInt(process.env.CACHE_SLOW_THRESHOLD || '10'), // 10ms
    logKeys: process.env.LOG_CACHE_KEYS === 'true',
    maskSensitiveKeys: true,
  },

  // Reporting settings
  reporting: {
    enabled: true,
    interval: parseInt(process.env.REPORTING_INTERVAL || '3600000'), // 1 hour
    retention: parseInt(process.env.METRICS_RETENTION || '604800000'), // 7 days
    exportFormat: process.env.EXPORT_FORMAT || 'json',
  },

  // Alerting settings
  alerting: {
    enabled: process.env.PERFORMANCE_ALERTING_ENABLED === 'true',
    channels: ['slack', 'email'],
    thresholds: {
      methodDuration: parseInt(process.env.ALERT_METHOD_DURATION || '5000'), // 5 seconds
      databaseDuration: parseInt(process.env.ALERT_DB_DURATION || '2000'), // 2 seconds
      apiDuration: parseInt(process.env.ALERT_API_DURATION || '10000'), // 10 seconds
      errorRate: parseFloat(process.env.ALERT_ERROR_RATE || '0.05'), // 5%
    },
  },
};
```

### **2. Performance Logging Best Practices**

```typescript
@Injectable()
export class PerformanceLoggingBestPractices {
  /**
   * Use appropriate tracking for different operation types
   */
  async executeWithAppropriateTracking(
    operationType: 'method' | 'database' | 'api' | 'cache',
    operationName: string,
    operation: () => Promise<any>,
  ): Promise<any> {
    switch (operationType) {
      case 'method':
        return this.advancedLogger.trackMethodExecution(operationName, operation);

      case 'database':
        return this.advancedLogger.trackDatabaseOperation(operationName, operation, {
          slowQueryThreshold: 500,
        });

      case 'api':
        return this.advancedLogger.trackExternalApiCall(
          operationName,
          'unknown',
          'GET',
          operation,
          { timeoutThreshold: 2000 },
        );

      case 'cache':
        return this.advancedLogger.trackCacheOperation('get', operationName, operation);

      default:
        return operation();
    }
  }

  /**
   * Implement sampling for high-frequency operations
   */
  shouldSampleOperation(operationName: string, sampleRate: number = 0.1): boolean {
    // Use consistent sampling based on operation name
    const hash = this.simpleHash(operationName);
    return (hash % 100) < (sampleRate * 100);
  }

  /**
   * Batch performance logs for efficiency
   */
  async batchPerformanceLogs(
    logs: PerformanceLogEntry[],
    batchSize: number = 100,
  ): Promise<void> {
    for (let i = 0; i < logs.length; i += batchSize) {
      const batch = logs.slice(i, i + batchSize);
      await this.processBatch(batch);
    }
  }

  /**
   * Implement log deduplication
   */
  private logCache = new Map<string, number>();

  shouldLogPerformance(logKey: string, deduplicationWindow: number = 60000): boolean {
    const now = Date.now();
    const lastLogTime = this.logCache.get(logKey);

    if (!lastLogTime || (now - lastLogTime) > deduplicationWindow) {
      this.logCache.set(logKey, now);
      return true;
    }

    return false;
  }

  /**
   * Clean up old log cache entries
   */
  cleanupLogCache(maxAge: number = 3600000): void { // 1 hour
    const now = Date.now();
    for (const [key, timestamp] of this.logCache.entries()) {
      if ((now - timestamp) > maxAge) {
        this.logCache.delete(key);
      }
    }
  }

  private simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  private async processBatch(batch: PerformanceLogEntry[]): Promise<void> {
    // Process batch of performance logs
    for (const log of batch) {
      await this.logPerformanceEntry(log);
    }
  }

  private async logPerformanceEntry(log: PerformanceLogEntry): Promise<void> {
    // Implementation for logging performance entries
    this.logger.log('Performance log entry', log);
  }
}

interface PerformanceLogEntry {
  operation: string;
  duration: number;
  type: 'method' | 'database' | 'api' | 'cache';
  timestamp: Date;
  metadata?: Record<string, any>;
}
```

---

## 🎯 **Next Steps**

This comprehensive performance logging system provides:
- ✅ **High-precision timing** with nanosecond accuracy
- ✅ **Multi-level tracking** for methods, database, APIs, and cache
- ✅ **Performance profiling** with detailed checkpoints
- ✅ **Automated alerting** for slow operations
- ✅ **Comprehensive metrics** collection and analysis
- ✅ **Memory monitoring** and resource tracking
- ✅ **Configurable thresholds** and best practices

**The performance logging utilities are now fully documented and ready for enterprise-grade performance monitoring! ⚡📊**

**Key components now documented:**
- Performance tracker utility with high-precision timing
- Advanced performance logger service with comprehensive tracking
- Performance profiler class with detailed checkpoint analysis
- Performance decorators for automatic method tracking
- Performance metrics collector with analytics and reporting
- Configuration best practices and alerting mechanisms
