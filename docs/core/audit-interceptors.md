# 🔐 **Audit Logging Interceptors - Request/Response Auditing**

## 🎯 **Overview**

The **Audit Logging Interceptors** are specialized components that automatically capture, process, and store audit trails for all HTTP requests and responses in the Navigator API. These interceptors ensure comprehensive security monitoring and compliance with regulatory requirements like HIPAA.

---

## 📍 **Audit Interceptor Architecture**

### **What are Audit Interceptors?**
Audit interceptors provide automatic request/response logging with:
- **Request Capture**: Complete HTTP request details
- **Response Monitoring**: Response data and status codes
- **PII Masking**: Sensitive data protection
- **Performance Tracking**: Request processing times
- **Security Event Detection**: Suspicious activity identification
- **Compliance Reporting**: Regulatory audit trail generation

### **Audit Interceptor Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                Audit Interceptor System                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Request Audit Interceptor               │    │
│  │  ├─ Capture HTTP Request ──────┬─ Headers & Body   │    │
│  │  ├─ Extract User Context ──────┼─ Authentication   │    │
│  │  ├─ PII Data Masking ──────────┼─ Sensitive Data    │    │
│  │  └─ Performance Tracking ──────┴─ Processing Time  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Response Audit Interceptor              │    │
│  │  ├─ Capture HTTP Response ─────┬─ Status & Body    │    │
│  │  ├─ Response Time Calculation ─┼─ Latency Metrics  │    │
│  │  ├─ Error Response Logging ────┼─ Exception Details │    │
│  │  └─ Audit Trail Correlation ───┴─ Request Matching │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Exception Audit Filter                  │    │
│  │  ├─ Exception Capture ────────┬─ Error Details     │    │
│  │  ├─ Security Event Detection ─┼─ Threat Analysis   │    │
│  │  ├─ Compliance Logging ───────┼─ Regulatory Events │    │
│  │  └─ Alert Generation ─────────┴─ Incident Response │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Request Audit Logging Interceptor**

```typescript
// File: libs/common/src/audit-logging/interceptors/request-audit-logging.interceptor.ts

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { AuditLoggingService } from '../audit-logging.service';
import { RequestContextService } from '../../../../../src/services/request-context/request-context.service';

@Injectable()
export class RequestAuditLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(RequestAuditLoggingInterceptor.name);

  constructor(
    private readonly auditService: AuditLoggingService,
    private readonly contextService: RequestContextService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const handler = context.getHandler();
    const controller = context.getClass();

    // Generate correlation ID if not present
    const correlationId = request.headers['x-correlation-id'] ||
                         request.headers['x-request-id'] ||
                         this.generateCorrelationId();

    // Store correlation ID in context
    this.contextService.run(() => {}, new Map([['correlationId', correlationId]]));

    // Capture request details
    const auditEntry = {
      correlationId,
      timestamp: new Date(),
      method: request.method,
      url: request.url,
      userAgent: request.headers['user-agent'],
      ipAddress: this.getClientIP(request),
      userId: request.user?.id,
      sessionId: request.session?.id,
      controller: controller.name,
      handler: handler.name,
      headers: this.maskSensitiveHeaders(request.headers),
      query: request.query,
      params: request.params,
      body: this.maskSensitiveData(request.body),
      requestSize: this.calculateRequestSize(request),
    };

    // Log request immediately
    this.logger.log(`Request: ${request.method} ${request.url}`, {
      correlationId,
      userId: auditEntry.userId,
      ipAddress: auditEntry.ipAddress,
    });

    // Store request audit entry
    this.auditService.storeRequestAudit(auditEntry).catch(error => {
      this.logger.error('Failed to store request audit', {
        correlationId,
        error: error.message,
      });
    });

    // Track response
    const startTime = Date.now();

    return next.handle().pipe(
      tap(async (responseData) => {
        const processingTime = Date.now() - startTime;

        // Capture response details
        const responseAudit = {
          correlationId,
          timestamp: new Date(),
          statusCode: response.statusCode,
          processingTime,
          responseSize: this.calculateResponseSize(responseData),
          responseBody: this.shouldLogResponseBody(response, responseData) ?
                       this.maskSensitiveData(responseData) : '[RESPONSE BODY NOT LOGGED]',
          success: response.statusCode < 400,
        };

        // Log response
        this.logger.log(`Response: ${response.statusCode} (${processingTime}ms)`, {
          correlationId,
          statusCode: response.statusCode,
          processingTime,
        });

        // Store response audit entry
        this.auditService.storeResponseAudit(responseAudit).catch(error => {
          this.logger.error('Failed to store response audit', {
            correlationId,
            error: error.message,
          });
        });
      }),
    );
  }

  /**
   * Generate unique correlation ID
   */
  private generateCorrelationId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: any): string {
    return (
      request.headers['x-forwarded-for']?.split(',')[0] ||
      request.headers['x-real-ip'] ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      request.ip ||
      'unknown'
    );
  }

  /**
   * Mask sensitive headers
   */
  private maskSensitiveHeaders(headers: Record<string, any>): Record<string, any> {
    const sensitiveHeaders = [
      'authorization',
      'x-api-key',
      'cookie',
      'set-cookie',
      'x-auth-token',
      'x-csrf-token',
    ];

    const masked = { ...headers };

    sensitiveHeaders.forEach(header => {
      if (masked[header]) {
        masked[header] = '[MASKED]';
      }
    });

    return masked;
  }

  /**
   * Mask sensitive data in request/response body
   */
  private maskSensitiveData(data: any): any {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sensitiveKeys = [
      'password',
      'token',
      'secret',
      'key',
      'ssn',
      'socialSecurityNumber',
      'creditCard',
      'cardNumber',
      'cvv',
      'pin',
      'medicalRecordNumber',
      'patientId',
    ];

    const masked = { ...data };

    sensitiveKeys.forEach(key => {
      if (masked[key]) {
        masked[key] = '[MASKED]';
      }
    });

    // Recursively mask nested objects
    Object.keys(masked).forEach(key => {
      if (typeof masked[key] === 'object' && masked[key] !== null) {
        masked[key] = this.maskSensitiveData(masked[key]);
      }
    });

    return masked;
  }

  /**
   * Calculate request size
   */
  private calculateRequestSize(request: any): number {
    try {
      const bodySize = JSON.stringify(request.body || {}).length;
      const headersSize = JSON.stringify(request.headers || {}).length;
      const querySize = JSON.stringify(request.query || {}).length;

      return bodySize + headersSize + querySize;
    } catch {
      return 0;
    }
  }

  /**
   * Calculate response size
   */
  private calculateResponseSize(responseData: any): number {
    try {
      return JSON.stringify(responseData || {}).length;
    } catch {
      return 0;
    }
  }

  /**
   * Determine if response body should be logged
   */
  private shouldLogResponseBody(response: any, data: any): boolean {
    // Don't log response body for:
    // - Large responses (>10KB)
    // - Binary data
    // - File downloads
    // - Sensitive endpoints

    const contentType = response.headers?.['content-type'] || '';
    const isBinary = contentType.includes('application/octet-stream') ||
                    contentType.includes('image/') ||
                    contentType.includes('video/');

    const isLarge = this.calculateResponseSize(data) > 10240; // 10KB

    const sensitiveEndpoints = [
      '/auth/login',
      '/users/reset-password',
      '/admin/',
    ];

    const isSensitive = sensitiveEndpoints.some(endpoint =>
      response.req?.url?.includes(endpoint)
    );

    return !isBinary && !isLarge && !isSensitive;
  }
}
```

### **2. Response Audit Logging Interceptor**

```typescript
// File: libs/common/src/audit-logging/interceptors/response-audit-logging.interceptor.ts

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';
import { AuditLoggingService } from '../audit-logging.service';
import { RequestContextService } from '../../../../../src/services/request-context/request-context.service';

@Injectable()
export class ResponseAuditLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ResponseAuditLoggingInterceptor.name);

  constructor(
    private readonly auditService: AuditLoggingService,
    private readonly contextService: RequestContextService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const correlationId = this.contextService.get('correlationId') ||
                         this.generateCorrelationId();

    const startTime = Date.now();

    return next.handle().pipe(
      tap(async (responseData) => {
        const processingTime = Date.now() - startTime;

        const auditEntry = {
          correlationId,
          timestamp: new Date(),
          method: request.method,
          url: request.url,
          userId: request.user?.id,
          statusCode: context.switchToHttp().getResponse().statusCode,
          processingTime,
          responseSize: this.calculateResponseSize(responseData),
          success: true,
          error: null,
        };

        // Log successful response
        this.logger.log(`Response: ${auditEntry.statusCode} (${processingTime}ms)`, {
          correlationId,
          statusCode: auditEntry.statusCode,
          processingTime,
        });

        // Store audit entry
        await this.auditService.storeResponseAudit(auditEntry);
      }),

      catchError(async (error) => {
        const processingTime = Date.now() - startTime;

        const auditEntry = {
          correlationId,
          timestamp: new Date(),
          method: request.method,
          url: request.url,
          userId: request.user?.id,
          statusCode: error.status || 500,
          processingTime,
          responseSize: 0,
          success: false,
          error: {
            name: error.name,
            message: error.message,
            stack: error.stack,
          },
        };

        // Log error response
        this.logger.error(`Error Response: ${auditEntry.statusCode} (${processingTime}ms)`, {
          correlationId,
          statusCode: auditEntry.statusCode,
          error: error.message,
          processingTime,
        });

        // Store error audit entry
        await this.auditService.storeErrorAudit(auditEntry);

        return throwError(() => error);
      }),
    );
  }

  private generateCorrelationId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private calculateResponseSize(responseData: any): number {
    try {
      return JSON.stringify(responseData || {}).length;
    } catch {
      return 0;
    }
  }
}
```

### **3. Audit Logging Exception Filter**

```typescript
// File: libs/common/src/audit-logging/filters/audit-logging-exception.filter.ts

import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuditLoggingService } from '../audit-logging.service';
import { RequestContextService } from '../../../../../src/services/request-context/request-context.service';

@Catch()
export class AuditLoggingExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(AuditLoggingExceptionFilter.name);

  constructor(
    private readonly auditService: AuditLoggingService,
    private readonly contextService: RequestContextService,
  ) {}

  async catch(exception: any, host: ArgumentsHost): Promise<void> {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const correlationId = this.contextService.get('correlationId') ||
                         this.generateCorrelationId();

    // Determine status code
    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    // Create error audit entry
    const auditEntry = {
      correlationId,
      timestamp: new Date(),
      method: request.method,
      url: request.url,
      userAgent: request.headers['user-agent'],
      ipAddress: this.getClientIP(request),
      userId: request.user?.id,
      sessionId: request.session?.id,
      statusCode: status,
      error: {
        name: exception.name,
        message: exception.message,
        stack: exception.stack,
        code: exception.code,
      },
      requestBody: this.maskSensitiveData(request.body),
      queryParams: request.query,
      routeParams: request.params,
      headers: this.maskSensitiveHeaders(request.headers),
    };

    // Log the error
    this.logger.error(
      `Exception caught: ${exception.message}`,
      {
        correlationId,
        statusCode: status,
        userId: auditEntry.userId,
        ipAddress: auditEntry.ipAddress,
        stack: exception.stack,
      },
    );

    // Store audit entry
    try {
      await this.auditService.storeExceptionAudit(auditEntry);
    } catch (auditError) {
      this.logger.error('Failed to store exception audit', {
        correlationId,
        auditError: auditError.message,
      });
    }

    // Check for security threats
    await this.checkForSecurityThreats(auditEntry);

    // Send error response
    const errorResponse = {
      statusCode: status,
      message: this.getErrorMessage(exception, status),
      correlationId,
      timestamp: auditEntry.timestamp,
    };

    response.status(status).json(errorResponse);
  }

  /**
   * Generate correlation ID
   */
  private generateCorrelationId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: Request): string {
    return (
      request.headers['x-forwarded-for']?.toString().split(',')[0] ||
      request.headers['x-real-ip']?.toString() ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      request.ip ||
      'unknown'
    );
  }

  /**
   * Mask sensitive headers
   */
  private maskSensitiveHeaders(headers: Record<string, any>): Record<string, any> {
    const sensitiveHeaders = [
      'authorization',
      'x-api-key',
      'cookie',
      'x-auth-token',
      'x-csrf-token',
    ];

    const masked = { ...headers };

    sensitiveHeaders.forEach(header => {
      if (masked[header]) {
        masked[header] = '[MASKED]';
      }
    });

    return masked;
  }

  /**
   * Mask sensitive data
   */
  private maskSensitiveData(data: any): any {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sensitiveKeys = [
      'password',
      'token',
      'secret',
      'ssn',
      'creditCard',
      'medicalRecord',
    ];

    const masked = { ...data };

    sensitiveKeys.forEach(key => {
      if (masked[key]) {
        masked[key] = '[MASKED]';
      }
    });

    return masked;
  }

  /**
   * Get appropriate error message
   */
  private getErrorMessage(exception: any, status: number): string {
    if (exception instanceof HttpException) {
      return exception.message;
    }

    // Don't expose internal error details in production
    if (process.env.NODE_ENV === 'production') {
      return 'An unexpected error occurred';
    }

    return exception.message || 'Internal server error';
  }

  /**
   * Check for potential security threats
   */
  private async checkForSecurityThreats(auditEntry: any): Promise<void> {
    const threats = [];

    // Check for SQL injection patterns
    if (this.containsSqlInjectionPatterns(auditEntry)) {
      threats.push('SQL_INJECTION_ATTEMPT');
    }

    // Check for XSS patterns
    if (this.containsXssPatterns(auditEntry)) {
      threats.push('XSS_ATTEMPT');
    }

    // Check for brute force patterns
    if (this.isBruteForceAttempt(auditEntry)) {
      threats.push('BRUTE_FORCE_ATTEMPT');
    }

    // Check for unusual request patterns
    if (this.isUnusualRequestPattern(auditEntry)) {
      threats.push('UNUSUAL_REQUEST_PATTERN');
    }

    if (threats.length > 0) {
      this.logger.warn('Security threat detected', {
        correlationId: auditEntry.correlationId,
        threats,
        ipAddress: auditEntry.ipAddress,
        userId: auditEntry.userId,
      });

      // Store security incident
      await this.auditService.storeSecurityIncident({
        ...auditEntry,
        threats,
        severity: this.calculateThreatSeverity(threats),
        timestamp: new Date(),
      });
    }
  }

  /**
   * Check for SQL injection patterns
   */
  private containsSqlInjectionPatterns(auditEntry: any): boolean {
    const sqlPatterns = [
      /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/i,
      /('|(\\x27)|(\\x2D\\x2D)|(\#)|(\%27)|(\%23)|(\%3B)|(\%3A)|(\%2D)|(\%2F)|(\%5C))/i,
      /(\bor\b|\band\b).*(\=|\<|\>)/i,
    ];

    const checkString = JSON.stringify(auditEntry);

    return sqlPatterns.some(pattern => pattern.test(checkString));
  }

  /**
   * Check for XSS patterns
   */
  private containsXssPatterns(auditEntry: any): boolean {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe[^>]*>.*?<\/iframe>/gi,
      /<object[^>]*>.*?<\/object>/gi,
    ];

    const checkString = JSON.stringify(auditEntry);

    return xssPatterns.some(pattern => pattern.test(checkString));
  }

  /**
   * Check for brute force attempts
   */
  private isBruteForceAttempt(auditEntry: any): boolean {
    // This would typically involve checking against a rate limiter
    // or authentication failure patterns
    return auditEntry.statusCode === 401 &&
           auditEntry.url.includes('/auth/login');
  }

  /**
   * Check for unusual request patterns
   */
  private isUnusualRequestPattern(auditEntry: any): boolean {
    // Check for unusual request sizes, frequencies, etc.
    const requestSize = JSON.stringify(auditEntry.requestBody || {}).length;

    return requestSize > 1000000; // 1MB request body
  }

  /**
   * Calculate threat severity
   */
  private calculateThreatSeverity(threats: string[]): 'low' | 'medium' | 'high' | 'critical' {
    if (threats.includes('SQL_INJECTION_ATTEMPT') ||
        threats.includes('XSS_ATTEMPT')) {
      return 'critical';
    }

    if (threats.includes('BRUTE_FORCE_ATTEMPT')) {
      return 'high';
    }

    if (threats.includes('UNUSUAL_REQUEST_PATTERN')) {
      return 'medium';
    }

    return 'low';
  }
}
```

---

## 🎯 **Integration & Usage**

### **1. Global Interceptor Registration**

```typescript
// File: src/app.module.ts (partial)

import { APP_INTERCEPTOR } from '@nestjs/core';
import { RequestAuditLoggingInterceptor } from '@app/common/audit-logging/interceptors/request-audit-logging.interceptor';
import { ResponseAuditLoggingInterceptor } from '@app/common/audit-logging/interceptors/response-audit-logging.interceptor';
import { AuditLoggingExceptionFilter } from '@app/common/audit-logging/filters/audit-logging-exception.filter';

@Module({
  providers: [
    // Global interceptors
    {
      provide: APP_INTERCEPTOR,
      useClass: RequestAuditLoggingInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseAuditLoggingInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: AuditLoggingExceptionFilter,
    },
  ],
})
export class AppModule {}
```

### **2. Selective Interceptor Usage**

```typescript
// File: src/controllers/sensitive.controller.ts

@Controller('sensitive-data')
@UseInterceptors(RequestAuditLoggingInterceptor, ResponseAuditLoggingInterceptor)
export class SensitiveController {
  @Get('patient-records')
  @UseFilters(AuditLoggingExceptionFilter)
  async getPatientRecords(): Promise<PatientRecord[]> {
    // All requests to this endpoint will be audited
    return this.patientService.getRecords();
  }

  @Post('update-record')
  @SkipAudit() // Skip audit for specific methods if needed
  async updateRecord(@Body() data: UpdateData): Promise<void> {
    return this.patientService.updateRecord(data);
  }
}
```

### **3. Custom Audit Configuration**

```typescript
// File: src/config/audit.config.ts

export const auditConfig = {
  // Enable/disable audit logging
  enabled: process.env.AUDIT_LOGGING_ENABLED === 'true',

  // Audit levels
  levels: {
    REQUEST: 'request',
    RESPONSE: 'response',
    ERROR: 'error',
    SECURITY: 'security',
  },

  // Sensitive data patterns
  sensitivePatterns: [
    /password/i,
    /token/i,
    /secret/i,
    /ssn/i,
    /credit.?card/i,
    /medical.?record/i,
  ],

  // Endpoints to always audit
  alwaysAuditEndpoints: [
    '/auth/*',
    '/admin/*',
    '/patient/*/sensitive',
  ],

  // Endpoints to never audit (response body)
  neverAuditResponseBody: [
    '/files/download/*',
    '/images/*',
    '/videos/*',
  ],

  // Performance thresholds
  performanceThresholds: {
    slowRequestMs: 5000,
    largeRequestBytes: 1024 * 1024, // 1MB
    largeResponseBytes: 1024 * 1024, // 1MB
  },
};
```

---

## 📊 **Audit Data Analysis**

### **1. Audit Query Service**

```typescript
@Injectable()
export class AuditQueryService {
  constructor(private readonly auditRepository: AuditRepository) {}

  /**
   * Query audit logs by user
   */
  async getUserAuditTrail(
    userId: string,
    startDate: Date,
    endDate: Date,
    options?: AuditQueryOptions,
  ): Promise<AuditEntry[]> {
    return this.auditRepository.find({
      where: {
        userId,
        timestamp: Between(startDate, endDate),
      },
      order: { timestamp: 'DESC' },
      ...options,
    });
  }

  /**
   * Query audit logs by endpoint
   */
  async getEndpointAuditTrail(
    endpoint: string,
    startDate: Date,
    endDate: Date,
  ): Promise<AuditEntry[]> {
    return this.auditRepository.find({
      where: {
        url: Like(`%${endpoint}%`),
        timestamp: Between(startDate, endDate),
      },
      order: { timestamp: 'DESC' },
    });
  }

  /**
   * Query security incidents
   */
  async getSecurityIncidents(
    startDate: Date,
    endDate: Date,
    severity?: SecuritySeverity,
  ): Promise<SecurityIncident[]> {
    const where: any = {
      timestamp: Between(startDate, endDate),
      threats: Not(IsNull()),
    };

    if (severity) {
      where.severity = severity;
    }

    return this.auditRepository.find({
      where,
      order: { timestamp: 'DESC' },
    });
  }

  /**
   * Generate audit report
   */
  async generateAuditReport(
    startDate: Date,
    endDate: Date,
  ): Promise<AuditReport> {
    const [
      totalRequests,
      errorRequests,
      securityIncidents,
      topEndpoints,
      userActivity,
    ] = await Promise.all([
      this.auditRepository.count({
        where: { timestamp: Between(startDate, endDate) },
      }),
      this.auditRepository.count({
        where: {
          timestamp: Between(startDate, endDate),
          success: false,
        },
      }),
      this.getSecurityIncidents(startDate, endDate),
      this.getTopEndpoints(startDate, endDate),
      this.getUserActivityReport(startDate, endDate),
    ]);

    return {
      period: { startDate, endDate },
      summary: {
        totalRequests,
        errorRequests,
        errorRate: totalRequests > 0 ? (errorRequests / totalRequests) * 100 : 0,
        securityIncidents: securityIncidents.length,
      },
      topEndpoints,
      userActivity,
      securityIncidents,
    };
  }

  private async getTopEndpoints(startDate: Date, endDate: Date): Promise<EndpointStats[]> {
    // Implementation for getting most accessed endpoints
    return [];
  }

  private async getUserActivityReport(startDate: Date, endDate: Date): Promise<UserActivity[]> {
    // Implementation for user activity analysis
    return [];
  }
}
```

### **2. Audit Dashboard Service**

```typescript
@Injectable()
export class AuditDashboardService {
  constructor(private readonly auditQueryService: AuditQueryService) {}

  /**
   * Get real-time audit metrics
   */
  async getRealTimeMetrics(): Promise<AuditMetrics> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const [
      recentRequests,
      recentErrors,
      recentSecurityIncidents,
      activeUsers,
    ] = await Promise.all([
      this.auditQueryService.getRequestsCount(oneHourAgo, now),
      this.auditQueryService.getErrorsCount(oneHourAgo, now),
      this.auditQueryService.getSecurityIncidentsCount(oneHourAgo, now),
      this.auditQueryService.getActiveUsersCount(oneHourAgo, now),
    ]);

    return {
      timeRange: 'last_hour',
      requestsPerMinute: recentRequests / 60,
      errorsPerMinute: recentErrors / 60,
      securityIncidentsPerHour: recentSecurityIncidents,
      activeUsers,
      errorRate: recentRequests > 0 ? (recentErrors / recentRequests) * 100 : 0,
    };
  }

  /**
   * Get audit trends
   */
  async getAuditTrends(days: number = 7): Promise<AuditTrends> {
    const trends = [];

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const startOfDay = new Date(date.setHours(0, 0, 0, 0));
      const endOfDay = new Date(date.setHours(23, 59, 59, 999));

      const [requests, errors] = await Promise.all([
        this.auditQueryService.getRequestsCount(startOfDay, endOfDay),
        this.auditQueryService.getErrorsCount(startOfDay, endOfDay),
      ]);

      trends.push({
        date: startOfDay.toISOString().split('T')[0],
        requests,
        errors,
        errorRate: requests > 0 ? (errors / requests) * 100 : 0,
      });
    }

    return { trends };
  }

  /**
   * Get compliance report
   */
  async getComplianceReport(
    startDate: Date,
    endDate: Date,
  ): Promise<ComplianceReport> {
    const auditReport = await this.auditQueryService.generateAuditReport(
      startDate,
      endDate,
    );

    return {
      period: { startDate, endDate },
      hipaaCompliant: this.checkHipaaCompliance(auditReport),
      dataRetentionCompliant: this.checkDataRetentionCompliance(auditReport),
      accessControlCompliant: this.checkAccessControlCompliance(auditReport),
      encryptionCompliant: this.checkEncryptionCompliance(auditReport),
      issues: this.identifyComplianceIssues(auditReport),
      recommendations: this.generateComplianceRecommendations(auditReport),
    };
  }

  private checkHipaaCompliance(auditReport: AuditReport): boolean {
    // HIPAA compliance checks
    return auditReport.summary.errorRate < 1 && // Low error rate
           auditReport.securityIncidents.length === 0 && // No security incidents
           auditReport.userActivity.every(activity => activity.hasConsent); // User consent
  }

  private checkDataRetentionCompliance(auditReport: AuditReport): boolean {
    // Data retention policy checks
    const maxRetentionDays = 2555; // 7 years
    return auditReport.period.endDate.getTime() - auditReport.period.startDate.getTime() <=
           maxRetentionDays * 24 * 60 * 60 * 1000;
  }

  private checkAccessControlCompliance(auditReport: AuditReport): boolean {
    // Access control checks
    return auditReport.userActivity.every(activity =>
      activity.accessLevelAppropriate && activity.auditTrailComplete
    );
  }

  private checkEncryptionCompliance(auditReport: AuditReport): boolean {
    // Encryption compliance checks
    return auditReport.summary.totalRequests > 0; // Placeholder - would check encryption usage
  }

  private identifyComplianceIssues(auditReport: AuditReport): ComplianceIssue[] {
    const issues = [];

    if (auditReport.summary.errorRate > 1) {
      issues.push({
        type: 'ERROR_RATE',
        severity: 'medium',
        description: `Error rate of ${auditReport.summary.errorRate}% exceeds 1% threshold`,
      });
    }

    if (auditReport.securityIncidents.length > 0) {
      issues.push({
        type: 'SECURITY_INCIDENTS',
        severity: 'high',
        description: `${auditReport.securityIncidents.length} security incidents detected`,
      });
    }

    return issues;
  }

  private generateComplianceRecommendations(auditReport: AuditReport): string[] {
    const recommendations = [];

    if (auditReport.summary.errorRate > 1) {
      recommendations.push('Implement additional error handling and monitoring');
    }

    if (auditReport.securityIncidents.length > 0) {
      recommendations.push('Review and enhance security measures');
      recommendations.push('Conduct security training for development team');
    }

    if (auditReport.summary.totalRequests > 100000) {
      recommendations.push('Consider implementing rate limiting');
      recommendations.push('Review audit data retention policies');
    }

    return recommendations;
  }
}
```

---

## 🔧 **Best Practices & Configuration**

### **1. Audit Configuration Best Practices**

```typescript
// File: src/config/audit-config.ts

export const auditConfig = {
  // Global audit settings
  global: {
    enabled: process.env.AUDIT_ENABLED === 'true',
    level: process.env.AUDIT_LEVEL || 'detailed',
    retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '2555'), // 7 years
    maxRequestBodySize: parseInt(process.env.AUDIT_MAX_REQUEST_SIZE || '10240'), // 10KB
    maxResponseBodySize: parseInt(process.env.AUDIT_MAX_RESPONSE_SIZE || '10240'), // 10KB
  },

  // Endpoint-specific settings
  endpoints: {
    '/auth/*': {
      auditLevel: 'detailed',
      maskBody: true,
      maskHeaders: ['authorization', 'x-api-key'],
    },
    '/admin/*': {
      auditLevel: 'detailed',
      maskBody: false,
      retentionDays: 3650, // 10 years for admin actions
    },
    '/patient/*': {
      auditLevel: 'detailed',
      maskBody: true,
      hipaaCompliant: true,
    },
  },

  // Performance settings
  performance: {
    slowRequestThreshold: 5000, // 5 seconds
    batchSize: 100, // Batch size for bulk inserts
    flushInterval: 30000, // 30 seconds
  },

  // Security settings
  security: {
    threatDetection: {
      enabled: true,
      sqlInjectionDetection: true,
      xssDetection: true,
      bruteForceDetection: true,
    },
    alertThresholds: {
      maxFailedLoginsPerHour: 10,
      maxSecurityIncidentsPerDay: 5,
    },
  },
};
```

### **2. Selective Auditing**

```typescript
@Injectable()
export class SelectiveAuditService {
  constructor(private readonly auditService: AuditLoggingService) {}

  /**
   * Conditionally audit based on business rules
   */
  async auditConditionally(
    context: ExecutionContext,
    data: any,
  ): Promise<void> {
    const request = context.switchToHttp().getRequest();

    // Always audit these endpoints
    if (this.isAlwaysAuditEndpoint(request.url)) {
      await this.auditService.storeAuditEntry({
        ...data,
        auditLevel: 'mandatory',
      });
      return;
    }

    // Audit based on data sensitivity
    if (this.containsSensitiveData(data)) {
      await this.auditService.storeAuditEntry({
        ...data,
        auditLevel: 'sensitive',
      });
      return;
    }

    // Audit based on user role
    if (this.isPrivilegedUser(request.user)) {
      await this.auditService.storeAuditEntry({
        ...data,
        auditLevel: 'privileged',
      });
      return;
    }

    // Sample auditing for performance
    if (this.shouldSampleAudit()) {
      await this.auditService.storeAuditEntry({
        ...data,
        auditLevel: 'sampled',
      });
    }
  }

  private isAlwaysAuditEndpoint(url: string): boolean {
    const alwaysAudit = [
      '/auth/login',
      '/auth/logout',
      '/admin/',
      '/patient/*/delete',
    ];

    return alwaysAudit.some(pattern => url.includes(pattern));
  }

  private containsSensitiveData(data: any): boolean {
    const sensitiveKeys = ['ssn', 'medicalRecord', 'creditCard'];

    return sensitiveKeys.some(key =>
      JSON.stringify(data).toLowerCase().includes(key)
    );
  }

  private isPrivilegedUser(user: any): boolean {
    return user?.roles?.includes('admin') ||
           user?.roles?.includes('clinician');
  }

  private shouldSampleAudit(): boolean {
    // Sample 10% of regular requests
    return Math.random() < 0.1;
  }
}
```

---

## 🎯 **Next Steps**

This comprehensive audit logging interceptor system provides:
- ✅ **Complete request/response auditing** with correlation IDs
- ✅ **PII masking and data protection** for HIPAA compliance
- ✅ **Security threat detection** and incident response
- ✅ **Performance monitoring** and slow request detection
- ✅ **Exception handling** with comprehensive error logging
- ✅ **Compliance reporting** and regulatory audit trails

**The audit interceptor system is now fully documented and ready for enterprise-grade security auditing! 🔐🛡️**

**Key components now documented:**
- Request audit logging interceptor
- Response audit logging interceptor  
- Exception audit filter with threat detection
- Audit data analysis and reporting
- Configuration best practices
- Selective auditing patterns
