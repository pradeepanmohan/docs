# 🎨 Parameter & Metadata Decorators - TypeScript Metadata System

## 🎯 **Overview**

The **Parameter & Metadata Decorators** are powerful TypeScript decorators that provide metadata attachment and parameter extraction capabilities for the Navigator API. These decorators enable seamless access to authenticated user information, route metadata, and request context throughout the application.

---

## 📍 **Decorator Architecture Overview**

### **What are Parameter & Metadata Decorators?**
Parameter & Metadata Decorators are TypeScript decorators that:
- **Extract user information** from authenticated requests
- **Attach metadata** to controllers, methods, and parameters
- **Enable conditional logic** based on route characteristics
- **Provide type-safe access** to request context
- **Support authentication workflows** for different identity providers
- **Enable route-level configuration** without code changes

### **Decorator Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│         Parameter & Metadata Decorator Architecture         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Current User Decorator                    │    │
│  │  ├─ User Context Extraction ─────┬─ Request.user     │    │
│  │  ├─ Type-Safe Access ────────────┼─ RequestUser Type │    │
│  │  ├─ Authentication Integration ──┼─ Guards Compatible│    │
│  │  └─ Context Preservation ────────┴─ Full User Object │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Entra Token Decorators                    │    │
│  │  ├─ Token Extraction ───────────┬─ Bearer Token     │    │
│  │  ├─ User Info Access ───────────┼─ JWT Payload      │    │
│  │  ├─ Header Validation ──────────┼─ Format Checking  │    │
│  │  └─ Dual Auth Support ──────────┴─ Epic + Entra     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Public Route Decorator                    │    │
│  │  ├─ Authentication Bypass ──────┬─ Skip Guards      │    │
│  │  ├─ Selective Application ──────┼─ Route-Level      │    │
│  │  ├─ Health Endpoints ───────────┼─ Monitoring Access│    │
│  │  └─ Metadata Storage ───────────┴─ Reflector System │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           User Identity Decorators                  │    │
│  │  ├─ LAN ID Extraction ──────────┬─ Epic Auth        │    │
│  │  ├─ Hostname Stripping ─────────┼─ Domain Removal   │    │
│  │  ├─ Case Normalization ─────────┼─ Lowercase        │    │
│  │  └─ Legacy Support ─────────────┴─ Backward Compat  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Current User Decorator**

```typescript
// File: src/decorators/current-user.decorator.ts

import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { RequestUser } from 'src/types/request-user';

/**
 * Parameter decorator that extracts the authenticated user from the request
 * Provides type-safe access to the current user's information
 */
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): RequestUser => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const user = request.user as RequestUser;
    return user;
  },
);
```

**Key Features:**
- ✅ **Type-Safe Extraction**: Strongly typed user information
- ✅ **Express Integration**: Works with Express.js request objects
- ✅ **Guard Compatible**: Integrates with authentication guards
- ✅ **Context Preservation**: Maintains full user object structure

### **2. Entra Token Decorators**

```typescript
// File: src/decorators/entra-token.decorator.ts

import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { Request } from 'express';
import { EntraUserInfo, RequestUser } from 'src/types/request-user';

/**
 * Header key for Entra ID authorization
 */
export const ENTRA_HEADER_KEY = 'authorization-entra';

/**
 * Validates and extracts the Entra authorization header
 * Ensures proper header format and content
 */
const validateHeader = (header: string | string[]): string | undefined => {
  if (!header) {
    return undefined;
  }

  if (typeof header !== 'string') {
    throw new BadRequestException(
      `'${ENTRA_HEADER_KEY}' header should be a string`,
    );
  }

  return header;
};

/**
 * Extracts the raw Entra token from the request headers
 * Handles Bearer token format and validation
 */
export const getEntraTokenFromRequest = (request: Request): string => {
  const rawHeader = request.headers[ENTRA_HEADER_KEY];
  const header = validateHeader(rawHeader);

  if (!header) {
    throw new BadRequestException(
      `'${ENTRA_HEADER_KEY}' header is missing or malformed`,
    );
  }

  // Remove 'Bearer ' prefix if present
  return header.startsWith('Bearer ') ? header.slice(7) : header;
};

/**
 * Extracts Entra token from ExecutionContext
 * Provides consistent token extraction across different contexts
 */
export const getEntraTokenFromContext = (ctx: ExecutionContext): string => {
  const request: Request = ctx.switchToHttp().getRequest();
  return getEntraTokenFromRequest(request);
};

/**
 * Parameter decorator that extracts the raw Entra bearer token
 * Returns the JWT token string for further processing
 */
export const EntraUserToken = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): string => getEntraTokenFromContext(ctx),
);

/**
 * Parameter decorator that extracts Entra user information
 * Returns the decoded JWT payload and user metadata
 */
export const EntraUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): EntraUserInfo | undefined => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const user: RequestUser = request.user;
    return user?.entraUser;
  },
);
```

**Key Features:**
- ✅ **Token Extraction**: Raw JWT token access
- ✅ **User Information**: Decoded JWT payload access
- ✅ **Header Validation**: Format and content validation
- ✅ **Bearer Support**: Automatic Bearer prefix handling
- ✅ **Type Safety**: Strongly typed Entra user information

### **3. Public Route Decorator**

```typescript
// File: src/decorators/public.decorator.ts

import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key for public route identification
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Metadata decorator that marks a route as public
 * Bypasses authentication requirements for the decorated route
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**Key Features:**
- ✅ **Authentication Bypass**: Skips authentication guards
- ✅ **Selective Application**: Route-level or controller-level
- ✅ **Metadata System**: Uses NestJS Reflector system
- ✅ **Health Endpoints**: Enables monitoring without auth

### **4. User Identity Decorators**

```typescript
// File: src/decorators/user-identity.decorator.ts

import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Parameter decorator that extracts the user LAN_ID from Epic authentication
 * Provides direct access to the authenticated user's identity
 */
export const UserIdentity = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.headers.introspect?.username?.toLowerCase();
  },
);

/**
 * Utility function to remove hostname/domain prefixes from user identifiers
 * Handles legacy MFAD domain prefixes for backward compatibility
 */
export const removeHostName = (preferred_username: string) =>
  preferred_username ? preferred_username.replace(/mfad\//gi, '') : '';
```

**Key Features:**
- ✅ **LAN ID Extraction**: Direct Epic user identity access
- ✅ **Case Normalization**: Consistent lowercase formatting
- ✅ **Domain Stripping**: Legacy hostname removal
- ✅ **Null Safety**: Handles undefined/null values gracefully

### **5. Request User Types**

```typescript
// File: src/types/request-user.d.ts

import { JwtPayload } from 'jsonwebtoken';
import { EntraAuthException } from 'src/errors/entra-auth.exception';

/**
 * Comprehensive user information attached to authenticated requests
 * Supports both Epic and Entra ID authentication methods
 */
export interface RequestUser extends Express.User {
  /**
   * Entra ID user information (when using Entra authentication)
   */
  entraUser?: EntraUserInfo;

  /**
   * Epic user information (when using Epic authentication)
   */
  epicUser?: EpicUserInfo;
}

/**
 * Epic EHR user information structure
 * Contains Epic-specific user authentication details
 */
export interface EpicUserInfo {
  /**
   * Epic user LAN_ID (unique identifier)
   */
  lanId: string;

  /**
   * Whether the user's access token is currently active
   */
  active: boolean;
}

/**
 * Microsoft Entra ID user information structure
 * Contains Azure AD authentication and authorization details
 */
export interface EntraUserInfo {
  /**
   * Original JWT payload from the access token
   */
  userTokenPayload?: JwtPayload;

  /**
   * On-Behalf-Of token for downstream API calls
   */
  oboToken?: string;

  /**
   * Any errors that occurred during token validation or OBO flow
   */
  error?: EntraAuthException;
}
```

**Type Features:**
- ✅ **Multi-Protocol Support**: Epic and Entra ID user information
- ✅ **JWT Integration**: Full JWT payload access
- ✅ **Error Handling**: Authentication error tracking
- ✅ **Token Management**: OBO token support for API calls
- ✅ **Type Safety**: Strongly typed user information

---

## 🔄 **Decorator Processing Flow**

### **1. Current User Flow**

```mermaid
graph TD
    A[Controller Method] --> B[@CurrentUser() user: RequestUser]
    B --> C[ExecutionContext Created]
    C --> D[Switch to HTTP Request]
    D --> E[Extract request.user]
    E --> F[Cast to RequestUser Type]
    F --> G[Return User Object]
    G --> H[Inject into Method Parameter]
```

### **2. Entra Token Flow**

```mermaid
graph TD
    A[Controller Method] --> B[@EntraUserToken() token: string]
    B --> C[ExecutionContext Created]
    C --> D[Switch to HTTP Request]
    D --> E[Extract authorization-entra Header]
    E --> F[Validate Header Format]
    F --> G[Remove Bearer Prefix]
    G --> H[Return Raw Token]
    H --> I[Inject into Method Parameter]
```

### **3. Public Route Flow**

```mermaid
graph TD
    A[Controller/Method] --> B[@Public()]
    B --> C[Set Metadata IS_PUBLIC_KEY = true]
    C --> D[Authentication Guard]
    D --> E[Check Reflector for IS_PUBLIC_KEY]
    E --> F{Is Public?}
    F -->|Yes| G[Skip Authentication]
    F -->|No| H[Continue Authentication]
```

### **4. User Identity Flow**

```mermaid
graph TD
    A[Controller Method] --> B[@UserIdentity() lanId: string]
    B --> C[ExecutionContext Created]
    C --> D[Switch to HTTP Request]
    D --> E[Extract introspect Header]
    E --> F[Extract username Field]
    F --> G[Convert to Lowercase]
    G --> H[Return LAN ID]
    H --> I[Inject into Method Parameter]
```

---

## 🔧 **Key Implementation Details**

### **1. Parameter Decorator Pattern**

```typescript
// Advanced parameter decorator with data transformation
@Injectable()
export class AdvancedParamDecorators {
  // Decorator with data parameter for customization
  export const CustomUser = createParamDecorator(
    (data: string, ctx: ExecutionContext) => {
      const request = ctx.switchToHttp().getRequest();
      const user = request.user as RequestUser;

      // Use data parameter to customize extraction
      switch (data) {
        case 'id':
          return user?.id;
        case 'lanId':
          return user?.lanId;
        case 'full':
        default:
          return user;
      }
    },
  );

  // Decorator with validation and transformation
  export const ValidatedParam = createParamDecorator(
    (data: ValidationOptions, ctx: ExecutionContext) => {
      const request = ctx.switchToHttp().getRequest();
      const param = request.params[data.paramName];

      // Apply validation
      if (data.required && !param) {
        throw new BadRequestException(`${data.paramName} is required`);
      }

      // Apply transformation
      if (data.transform) {
        return data.transform(param);
      }

      return param;
    },
  );

  // Usage examples
  @Get('/user/:id')
  getUser(
    @CustomUser('id') userId: string,
    @ValidatedParam({
      paramName: 'id',
      required: true,
      transform: (value: string) => parseInt(value, 10),
    }) id: number,
  ) {
    // userId is extracted from request.user.id
    // id is validated and transformed to number
  }
}
```

**Decorator Features:**
- ✅ **Data Parameters**: Customizable extraction logic
- ✅ **Validation Integration**: Built-in parameter validation
- ✅ **Transformation Support**: Data type conversion
- ✅ **Error Handling**: Comprehensive error reporting

### **2. Metadata Decorator Pattern**

```typescript
// Advanced metadata decorators for route configuration
@Injectable()
export class AdvancedMetadataDecorators {
  // Permission-based access control
  export const PERMISSIONS_KEY = 'permissions';
  export const RequirePermissions = (...permissions: string[]) =>
    SetMetadata(PERMISSIONS_KEY, permissions);

  // Rate limiting configuration
  export const RATE_LIMIT_KEY = 'rateLimit';
  export const RateLimit = (options: RateLimitOptions) =>
    SetMetadata(RATE_LIMIT_KEY, options);

  // Caching configuration
  export const CACHE_KEY = 'cache';
  export const Cache = (options: CacheOptions) =>
    SetMetadata(CACHE_KEY, options);

  // Feature flag control
  export const FEATURE_FLAG_KEY = 'featureFlag';
  export const FeatureFlag = (flagName: string) =>
    SetMetadata(FEATURE_FLAG_KEY, flagName);

  // Usage with guards/interceptors
  export class PermissionGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
      const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
        PERMISSIONS_KEY,
        [context.getHandler(), context.getClass()],
      );

      if (!requiredPermissions) {
        return true; // No permissions required
      }

      const user = context.switchToHttp().getRequest().user as RequestUser;
      return this.checkPermissions(user, requiredPermissions);
    }
  }

  // Usage examples
  @Controller('admin')
  @RequirePermissions('admin.read')
  export class AdminController {
    @Get('/users')
    @RateLimit({ windowMs: 60000, max: 10 })
    @Cache({ ttl: 300 })
    @FeatureFlag('admin-dashboard')
    async getUsers(@CurrentUser() user: RequestUser) {
      // Route requires admin.read permission
      // Rate limited to 10 requests per minute
      // Response cached for 5 minutes
      // Only available if admin-dashboard feature flag is enabled
    }
  }
}
```

**Metadata Features:**
- ✅ **Permission Control**: Role-based access control
- ✅ **Rate Limiting**: Request throttling configuration
- ✅ **Caching**: Response caching directives
- ✅ **Feature Flags**: Runtime feature toggling
- ✅ **Guard Integration**: Automatic enforcement

### **3. Context-Aware Decorators**

```typescript
// Context-aware decorators with service integration
@Injectable()
export class ContextAwareDecorators {
  constructor(
    private readonly contextService: RequestContextService,
    private readonly auditService: AuditLoggingService,
  ) {}

  // Audit logging decorator
  export const Audited = createParamDecorator(
    (operation: string, ctx: ExecutionContext) => {
      const request = ctx.switchToHttp().getRequest();
      const user = request.user as RequestUser;
      const requestId = this.contextService.get('requestId');

      // Log the operation
      this.auditService.log(user?.lanId, `operation.${operation}`, {
        requestId,
        timestamp: new Date(),
        ip: request.ip,
        userAgent: request.get('User-Agent'),
      });

      // Return the original parameter or proceed
      return null;
    },
  );

  // User preference aware decorator
  export const WithPreferences = createParamDecorator(
    async (data: unknown, ctx: ExecutionContext) => {
      const request = ctx.switchToHttp().getRequest();
      const user = request.user as RequestUser;

      if (user?.lanId) {
        // Load user preferences
        const preferences = await this.preferencesService.getDataConceptPreferences(
          user.lanId,
          'default',
          'default',
        );

        // Attach to request for later use
        request.userPreferences = preferences;
      }

      return data;
    },
  );

  // Healthcare context decorator
  export const WithPatientContext = createParamDecorator(
    async (patientId: string, ctx: ExecutionContext) => {
      const request = ctx.switchToHttp().getRequest();
      const user = request.user as RequestUser;

      if (patientId && user?.lanId) {
        // Load patient context
        const patientContext = await this.patientService.getPatientContext(
          patientId,
          user.lanId,
        );

        // Attach to request
        request.patientContext = patientContext;

        // Audit patient access
        this.auditService.log(user.lanId, 'patient.access', {
          patientId,
          timestamp: new Date(),
          context: 'decorator_access',
        });
      }

      return patientId;
    },
  );

  // Usage examples
  @Controller('clinical')
  export class ClinicalController {
    @Get('/data/:conceptId')
    async getClinicalData(
      @Param('conceptId') conceptId: string,
      @WithPreferences() _prefs: any,
      @CurrentUser() user: RequestUser,
    ) {
      // User preferences are loaded and attached to request
      const preferences = this.request.userPreferences;
      // Use preferences to filter clinical data
      return this.clinicalService.getFilteredData(conceptId, preferences);
    }

    @Get('/patient/:patientId/data')
    async getPatientData(
      @WithPatientContext() patientId: string,
      @CurrentUser() user: RequestUser,
    ) {
      // Patient context is loaded and access is audited
      const patientContext = this.request.patientContext;
      // Use patient context for authorization
      return this.patientService.getPatientData(patientId, patientContext);
    }

    @Post('/audit/:operation')
    async performAuditedOperation(
      @Param('operation') operation: string,
      @Body() data: any,
      @Audited(operation) _audit: any,
    ) {
      // Operation is automatically audited
      return this.operationService.performOperation(operation, data);
    }
  }
}
```

**Context Features:**
- ✅ **Audit Integration**: Automatic operation logging
- ✅ **Preference Loading**: User preference injection
- ✅ **Patient Context**: Healthcare-specific context loading
- ✅ **Service Integration**: Direct service method calls
- ✅ **Request Enrichment**: Additional data attachment

---

## 🔧 **Integration Points**

### **1. Guard Integration**

```typescript
// Integration with authentication guards
@Injectable()
export class DecoratorGuardIntegration {
  // Guards can use decorators to extract user information
  export class AdvancedAuthGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
      const isPublic = this.reflector.getAllAndOverride<boolean>(
        IS_PUBLIC_KEY,
        [context.getHandler(), context.getClass()],
      );

      if (isPublic) {
        return true;
      }

      // Extract user using decorator logic
      const request = context.switchToHttp().getRequest();
      const user = request.user as RequestUser;

      if (!user) {
        throw new UnauthorizedException();
      }

      // Additional validation logic
      return this.validateUserPermissions(user);
    }
  }

  // Guards can set user context for decorators
  export class UserContextGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const request = context.switchToHttp().getRequest();

      // Set user context that decorators can access
      const userContext = await this.buildUserContext(request);
      request.user = userContext;

      return true;
    }

    private async buildUserContext(request: Request): Promise<RequestUser> {
      // Extract and enrich user information
      const entraToken = request.headers['authorization-entra'];
      const introspect = request.headers['introspect'];

      // Build comprehensive user context
      return {
        id: await this.extractUserId(entraToken, introspect),
        lanId: await this.extractLanId(entraToken, introspect),
        entraUser: entraToken ? await this.buildEntraUser(entraToken) : undefined,
        epicUser: introspect ? await this.buildEpicUser(introspect) : undefined,
      };
    }
  }
}
```

### **2. Interceptor Integration**

```typescript
// Integration with request/response interceptors
@Injectable()
export class DecoratorInterceptorIntegration {
  // Interceptors can use decorators to modify behavior
  @Injectable()
  export class UserContextInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      const request = context.switchToHttp().getRequest();
      const user = request.user as RequestUser;

      // Add user context to request for downstream use
      if (user) {
        this.contextService.set('userId', user.id);
        this.contextService.set('lanId', user.lanId);
        this.contextService.set('user', user);
      }

      return next.handle().pipe(
        map((data) => {
          // Add user context to response
          if (user) {
            return {
              ...data,
              _userContext: {
                id: user.id,
                lanId: user.lanId,
              },
            };
          }
          return data;
        }),
      );
    }
  }

  // Interceptors can leverage decorator metadata
  @Injectable()
  export class MetadataAwareInterceptor implements NestInterceptor {
    constructor(private reflector: Reflector) {}

    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      const cacheOptions = this.reflector.getAllAndOverride<CacheOptions>(
        CACHE_KEY,
        [context.getHandler(), context.getClass()],
      );

      if (cacheOptions) {
        // Apply caching logic based on metadata
        return this.applyCaching(context, next, cacheOptions);
      }

      return next.handle();
    }

    private applyCaching(
      context: ExecutionContext,
      next: CallHandler,
      options: CacheOptions,
    ): Observable<any> {
      const request = context.switchToHttp().getRequest();
      const cacheKey = this.generateCacheKey(request);

      // Check cache first
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return of(cached);
      }

      // Execute and cache result
      return next.handle().pipe(
        tap((response) => {
          this.cache.set(cacheKey, response, options.ttl);
        }),
      );
    }
  }
}
```

### **3. Service Integration**

```typescript
// Integration with business logic services
@Injectable()
export class DecoratorServiceIntegration {
  // Services can use decorators for parameter extraction
  export class UserService {
    @Get('/profile')
    async getUserProfile(@CurrentUser() user: RequestUser) {
      // User information extracted automatically
      return this.userRepository.findByLanId(user.lanId);
    }

    @Post('/preferences')
    async updatePreferences(
      @CurrentUser() user: RequestUser,
      @Body() preferences: UserPreferences,
    ) {
      // User context available for authorization
      await this.validateUserAccess(user, 'preferences.update');

      return this.preferencesService.update(user.lanId, preferences);
    }
  }

  // Services can leverage decorator metadata
  export class HealthcareService {
    @Get('/patient/:patientId/data')
    async getPatientData(
      @Param('patientId') patientId: string,
      @CurrentUser() user: RequestUser,
    ) {
      // Validate healthcare access permissions
      await this.validateHealthcareAccess(user, patientId);

      // Check patient context from decorators
      const patientContext = await this.getPatientContext(patientId);

      return this.clinicalDataService.getPatientData(patientId, patientContext);
    }

    @Post('/audit/event')
    async logAuditEvent(
      @Body() event: AuditEvent,
      @CurrentUser() user: RequestUser,
    ) {
      // Automatically enrich audit event with user context
      const enrichedEvent = {
        ...event,
        userId: user.lanId,
        timestamp: new Date(),
        ipAddress: await this.getClientIp(),
        userAgent: await this.getUserAgent(),
      };

      return this.auditService.logEvent(enrichedEvent);
    }
  }
}
```

---

## 📊 **Performance & Monitoring**

### **1. Decorator Performance Metrics**

```typescript
// Performance monitoring for decorators
@Injectable()
export class DecoratorPerformanceMonitor {
  constructor(private readonly metrics: MetricsService) {}

  // Track decorator execution time
  async trackDecoratorPerformance(
    decoratorName: string,
    executionTime: number,
    success: boolean,
    metadata?: Record<string, any>,
  ): Promise<void> {
    this.metrics.histogram('decorator_execution_duration', executionTime, {
      decorator: decoratorName,
      success: success.toString(),
      ...metadata,
    });

    this.metrics.increment('decorator_execution_count', {
      decorator: decoratorName,
      success: success.toString(),
    });

    // Alert on slow decorators
    if (executionTime > 100) { // More than 100ms
      this.logger.warn(`Slow decorator execution: ${decoratorName}`, {
        decorator: decoratorName,
        executionTime,
        ...metadata,
      });
    }
  }

  // Track parameter extraction performance
  async trackParameterExtraction(
    parameterName: string,
    extractionTime: number,
    source: 'header' | 'user' | 'param' | 'query',
  ): Promise<void> {
    this.metrics.histogram('parameter_extraction_duration', extractionTime, {
      parameter: parameterName,
      source,
    });

    // Alert on slow extractions
    if (extractionTime > 50) { // More than 50ms
      this.logger.warn(`Slow parameter extraction: ${parameterName}`, {
        parameter: parameterName,
        source,
        extractionTime,
      });
    }
  }

  // Track metadata access performance
  async trackMetadataAccess(
    metadataKey: string,
    accessTime: number,
    hit: boolean,
  ): Promise<void> {
    this.metrics.histogram('metadata_access_duration', accessTime, {
      metadataKey,
      hit: hit.toString(),
    });

    this.metrics.increment('metadata_access_count', {
      metadataKey,
      hit: hit.toString(),
    });
  }

  // Overall decorator pipeline performance
  async trackDecoratorPipeline(
    decoratorCount: number,
    totalTime: number,
    requestId: string,
  ): Promise<void> {
    const avgTime = totalTime / decoratorCount;

    this.metrics.histogram('decorator_pipeline_total_duration', totalTime, {
      decoratorCount: decoratorCount.toString(),
    });

    this.metrics.histogram('decorator_pipeline_avg_duration', avgTime, {
      decoratorCount: decoratorCount.toString(),
    });

    this.logger.debug(`Decorator pipeline completed`, {
      requestId,
      decoratorCount,
      totalTime,
      avgTime,
    });
  }
}
```

### **2. Health Monitoring**

```typescript
// Decorator health monitoring
@Injectable()
export class DecoratorHealthMonitor {
  constructor(
    private readonly metrics: MetricsService,
    private readonly alerting: AlertingService,
  ) {}

  // Comprehensive health check
  async performHealthCheck(): Promise<HealthCheckResult> {
    const checks = await Promise.all([
      this.checkDecoratorPerformance(),
      this.checkMetadataSystem(),
      this.checkParameterExtraction(),
      this.checkTypeSafety(),
    ]);

    const overallStatus = this.calculateOverallStatus(checks);

    return {
      status: overallStatus,
      checks,
      recommendations: this.generateRecommendations(checks),
    };
  }

  // Decorator performance check
  private async checkDecoratorPerformance(): Promise<HealthCheck> {
    const recentMetrics = await this.getRecentDecoratorMetrics();

    const avgDuration = recentMetrics.reduce((sum, m) => sum + m.duration, 0) / recentMetrics.length;

    if (avgDuration > 200) { // More than 200ms average
      return {
        name: 'Decorator Performance',
        status: 'degraded',
        message: `High average decorator execution time: ${avgDuration}ms`,
        details: { avgDuration, sampleSize: recentMetrics.length },
      };
    }

    return {
      name: 'Decorator Performance',
      status: 'healthy',
      message: `Normal decorator performance: ${avgDuration}ms average`,
    };
  }

  // Metadata system check
  private async checkMetadataSystem(): Promise<HealthCheck> {
    try {
      // Test metadata storage and retrieval
      const testController = { testMethod: () => {} };
      const testKey = 'test_metadata_key';
      const testValue = 'test_value';

      // Simulate metadata setting
      Reflect.defineMetadata(testKey, testValue, testController.testMethod);

      // Test retrieval
      const retrieved = Reflect.getMetadata(testKey, testController.testMethod);

      if (retrieved !== testValue) {
        return {
          name: 'Metadata System',
          status: 'unhealthy',
          message: 'Metadata storage/retrieval failed',
          details: { expected: testValue, received: retrieved },
        };
      }

      return {
        name: 'Metadata System',
        status: 'healthy',
        message: 'Metadata system operational',
      };
    } catch (error) {
      return {
        name: 'Metadata System',
        status: 'unhealthy',
        message: `Metadata system error: ${error.message}`,
      };
    }
  }

  // Parameter extraction check
  private async checkParameterExtraction(): Promise<HealthCheck> {
    try {
      // Test parameter extraction decorators
      const mockRequest = {
        user: { id: 'test-user', lanId: 'test.lan' },
        headers: {
          'authorization-entra': 'Bearer test-token',
          introspect: JSON.stringify({ username: 'test.user' }),
        },
        params: { id: '123' },
        query: { filter: 'active' },
      };

      // Test CurrentUser decorator
      const currentUserResult = await this.testCurrentUserDecorator(mockRequest);
      if (!currentUserResult.success) {
        return {
          name: 'Parameter Extraction',
          status: 'degraded',
          message: 'CurrentUser decorator test failed',
          details: currentUserResult,
        };
      }

      // Test Entra token decorator
      const entraResult = await this.testEntraTokenDecorator(mockRequest);
      if (!entraResult.success) {
        return {
          name: 'Parameter Extraction',
          status: 'degraded',
          message: 'Entra token decorator test failed',
          details: entraResult,
        };
      }

      return {
        name: 'Parameter Extraction',
        status: 'healthy',
        message: 'Parameter extraction operational',
      };
    } catch (error) {
      return {
        name: 'Parameter Extraction',
        status: 'unhealthy',
        message: `Parameter extraction error: ${error.message}`,
      };
    }
  }

  // Type safety check
  private async checkTypeSafety(): Promise<HealthCheck> {
    try {
      // Test TypeScript type safety
      const testUser: RequestUser = {
        id: 'test-id',
        lanId: 'test.lan',
        entraUser: {
          userTokenPayload: {} as any,
        },
      };

      // Validate type structure
      if (!testUser.id || !testUser.lanId) {
        throw new Error('Type validation failed');
      }

      return {
        name: 'Type Safety',
        status: 'healthy',
        message: 'Type safety validation passed',
      };
    } catch (error) {
      return {
        name: 'Type Safety',
        status: 'unhealthy',
        message: `Type safety check failed: ${error.message}`,
      };
    }
  }

  // Calculate overall status
  private calculateOverallStatus(checks: HealthCheck[]): HealthStatus {
    if (checks.some(check => check.status === 'unhealthy')) {
      return 'critical';
    }

    if (checks.some(check => check.status === 'degraded' || check.status === 'warning')) {
      return 'warning';
    }

    return 'healthy';
  }

  // Generate health recommendations
  private generateRecommendations(checks: HealthCheck[]): string[] {
    const recommendations: string[] = [];

    for (const check of checks) {
      switch (check.status) {
        case 'unhealthy':
          recommendations.push(`CRITICAL: ${check.name} - ${check.message}`);
          break;
        case 'degraded':
          recommendations.push(`Review: ${check.name} - ${check.message}`);
          break;
        case 'warning':
          recommendations.push(`Monitor: ${check.name} - ${check.message}`);
          break;
      }
    }

    return recommendations;
  }
}
```

---

## 🧪 **Testing Implementation**

### **1. Unit Tests**

```typescript
// File: src/decorators/current-user.decorator.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { CurrentUser } from './current-user.decorator';

describe('CurrentUser Decorator', () => {
  let decorator: typeof CurrentUser;

  beforeEach(async () => {
    decorator = CurrentUser;
  });

  describe('CurrentUser decorator', () => {
    it('should be defined', () => {
      expect(decorator).toBeDefined();
    });

    it('should extract user from request', () => {
      const mockUser = {
        id: 'test-user-id',
        lanId: 'test.lan.id',
        entraUser: { userTokenPayload: {} },
      };

      const mockRequest = {
        user: mockUser,
      };

      const mockContext = {
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      const result = decorator(null, mockContext);

      expect(result).toEqual(mockUser);
    });

    it('should handle undefined user', () => {
      const mockRequest = {
        user: undefined,
      };

      const mockContext = {
        switchToHttp: () => ({
          getRequest: () => mockRequest,
        }),
      };

      const result = decorator(null, mockContext);

      expect(result).toBeUndefined();
    });

    it('should handle missing request', () => {
      const mockContext = {
        switchToHttp: () => ({
          getRequest: () => undefined,
        }),
      };

      expect(() => decorator(null, mockContext)).toThrow();
    });
  });
});
```

### **2. Integration Tests**

```typescript
// File: test/e2e/decorators.e2e.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('Decorators (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('CurrentUser Decorator', () => {
    it('should inject authenticated user into controller method', async () => {
      const mockUser = {
        id: 'test-user-id',
        lanId: 'test.lan.id',
        entraUser: { userTokenPayload: { unique_name: 'test@domain.com' } },
      };

      // Mock authentication that sets request.user
      const response = await request(app.getHttpServer())
        .get('/test-current-user')
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      // Verify that the user object was properly injected
      expect(response.body.user).toBeDefined();
      expect(response.body.user.id).toBe(mockUser.id);
      expect(response.body.user.lanId).toBe(mockUser.lanId);
    });

    it('should handle unauthenticated requests', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-current-user')
        .expect(401);

      // Verify proper error handling for missing authentication
      expect(response.body.statusCode).toBe(401);
    });
  });

  describe('Entra Token Decorators', () => {
    it('should extract Entra token from authorization-entra header', async () => {
      const mockToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjVCM25SeWF0QzZ';

      const response = await request(app.getHttpServer())
        .get('/test-entra-token')
        .set('authorization-entra', `Bearer ${mockToken}`)
        .set('Authorization', 'Bearer mock-auth-token')
        .expect(200);

      // Verify that the Entra token was extracted correctly
      expect(response.body.entraToken).toBe(mockToken);
    });

    it('should extract Entra user information', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-entra-user')
        .set('authorization-entra', 'Bearer mock-entra-token')
        .set('Authorization', 'Bearer mock-auth-token')
        .expect(200);

      // Verify that Entra user information was extracted
      expect(response.body.entraUser).toBeDefined();
    });

    it('should handle missing Entra header', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-entra-token')
        .set('Authorization', 'Bearer mock-auth-token')
        .expect(400);

      // Verify proper error handling for missing header
      expect(response.body.statusCode).toBe(400);
      expect(response.body.message).toContain('authorization-entra header is missing');
    });

    it('should handle malformed Entra header', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-entra-token')
        .set('authorization-entra', ['invalid', 'array'])
        .set('Authorization', 'Bearer mock-auth-token')
        .expect(400);

      // Verify proper error handling for malformed header
      expect(response.body.statusCode).toBe(400);
      expect(response.body.message).toContain('should be a string');
    });
  });

  describe('Public Decorator', () => {
    it('should allow access to public routes without authentication', async () => {
      const response = await request(app.getHttpServer())
        .get('/public-endpoint')
        .expect(200);

      // Verify that public endpoints are accessible without authentication
      expect(response.body.message).toBe('This is a public endpoint');
    });

    it('should maintain authentication for non-public routes', async () => {
      const response = await request(app.getHttpServer())
        .get('/protected-endpoint')
        .expect(401);

      // Verify that non-public endpoints still require authentication
      expect(response.body.statusCode).toBe(401);
    });
  });

  describe('UserIdentity Decorator', () => {
    it('should extract user LAN ID from introspect header', async () => {
      const mockIntrospect = {
        username: 'TEST.USER',
        active: true,
      };

      const response = await request(app.getHttpServer())
        .get('/test-user-identity')
        .set('introspect', JSON.stringify(mockIntrospect))
        .expect(200);

      // Verify that LAN ID was extracted and normalized
      expect(response.body.lanId).toBe('test.user');
    });

    it('should handle missing introspect header', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-user-identity')
        .expect(200);

      // Verify graceful handling of missing header
      expect(response.body.lanId).toBeUndefined();
    });

    it('should handle malformed introspect header', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-user-identity')
        .set('introspect', 'invalid-json')
        .expect(200);

      // Verify graceful handling of malformed JSON
      expect(response.body.lanId).toBeUndefined();
    });
  });

  describe('Combined Decorator Behavior', () => {
    it('should work with multiple decorators on the same method', async () => {
      const mockUser = {
        id: 'test-user-id',
        lanId: 'test.lan.id',
        entraUser: { userTokenPayload: { unique_name: 'test@domain.com' } },
      };

      const mockIntrospect = {
        username: 'TEST.USER',
        active: true,
      };

      const response = await request(app.getHttpServer())
        .get('/test-combined-decorators')
        .set('introspect', JSON.stringify(mockIntrospect))
        .set('authorization-entra', 'Bearer mock-entra-token')
        .set('Authorization', 'Bearer mock-auth-token')
        .expect(200);

      // Verify that all decorators worked together
      expect(response.body.user).toEqual(mockUser);
      expect(response.body.lanId).toBe('test.user');
      expect(response.body.entraToken).toBe('mock-entra-token');
    });

    it('should maintain decorator order and execution', async () => {
      // Test that decorators execute in the expected order
      const response = await request(app.getHttpServer())
        .get('/test-decorator-order')
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      // Verify execution order through response metadata
      expect(response.body.executionOrder).toEqual([
        'public-check',
        'auth-check',
        'user-extraction',
        'business-logic',
      ]);
    });
  });

  describe('Performance Tests', () => {
    it('should execute decorators quickly', async () => {
      const startTime = Date.now();

      await request(app.getHttpServer())
        .get('/test-decorator-performance')
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Decorators should add minimal overhead (< 50ms)
      expect(duration).toBeLessThan(100);
    });

    it('should handle concurrent requests with decorators', async () => {
      const requests = Array(10).fill().map(() =>
        request(app.getHttpServer())
          .get('/test-concurrent-decorators')
          .set('Authorization', 'Bearer mock-token')
          .expect(200)
      );

      const responses = await Promise.all(requests);

      responses.forEach((response) => {
        expect(response.status).toBe(200);
        // Verify each request got proper decorator processing
        expect(response.body.user).toBeDefined();
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle decorator execution errors gracefully', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-decorator-error')
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      // Verify that errors in decorators don't crash the application
      expect(response.body.errorHandled).toBe(true);
    });

    it('should provide meaningful error messages for decorator failures', async () => {
      const response = await request(app.getHttpServer())
        .get('/test-decorator-validation')
        .set('Authorization', 'Bearer mock-token')
        .expect(400);

      // Verify that validation errors from decorators are meaningful
      expect(response.body.message).toContain('validation failed');
    });
  });
});
```

---

## 🚀 **Usage Examples**

### **1. Controller Integration**

```typescript
// Example controller using various decorators
import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import {
  CurrentUser,
  EntraUserToken,
  EntraUser,
  UserIdentity,
} from '../decorators';
import { Public } from '../decorators/public.decorator';
import { UniversalAuthenticationGuard } from '../guards';

@Controller('api')
export class ApiController {
  // Public endpoint - no authentication required
  @Public()
  @Get('/health')
  getHealth() {
    return { status: 'ok', timestamp: new Date() };
  }

  // Protected endpoint with user context
  @UseGuards(UniversalAuthenticationGuard)
  @Get('/profile')
  getUserProfile(@CurrentUser() user: RequestUser) {
    return {
      id: user.id,
      lanId: user.lanId,
      source: user.entraUser ? 'entra' : 'epic',
    };
  }

  // Epic-specific endpoint
  @UseGuards(UniversalAuthenticationGuard)
  @Get('/epic-data')
  getEpicData(@UserIdentity() lanId: string) {
    return {
      lanId,
      epicSpecificData: true,
    };
  }

  // Entra-specific endpoint
  @UseGuards(UniversalAuthenticationGuard)
  @Post('/entra-action')
  performEntraAction(
    @EntraUserToken() token: string,
    @EntraUser() entraUser: EntraUserInfo,
    @Body() data: any,
  ) {
    return {
      token: token.substring(0, 20) + '...', // Mask sensitive data
      entraUserId: entraUser?.userTokenPayload?.unique_name,
      action: 'performed',
      data,
    };
  }

  // Complex endpoint with multiple decorators
  @UseGuards(UniversalAuthenticationGuard)
  @Get('/complex/:id')
  getComplexData(
    @Param('id') id: string,
    @CurrentUser() user: RequestUser,
    @UserIdentity() lanId: string,
    @EntraUser() entraUser: EntraUserInfo,
  ) {
    return {
      requestId: id,
      user: {
        id: user.id,
        lanId,
        entraEmail: entraUser?.userTokenPayload?.unique_name,
      },
      processing: {
        epicAuth: !!lanId,
        entraAuth: !!entraUser,
        dualAuth: !!(lanId && entraUser),
      },
    };
  }
}
```

### **2. Advanced Decorator Patterns**

```typescript
// Advanced decorator patterns for healthcare workflows
@Controller('healthcare')
export class HealthcareController {
  // Patient context decorator usage
  @Get('/patient/:patientId/record')
  getPatientRecord(
    @Param('patientId') patientId: string,
    @CurrentUser() user: RequestUser,
  ) {
    // Validate healthcare access
    this.validateHealthcareAccess(user, patientId);

    // Get patient record with user context
    return this.patientService.getRecord(patientId, {
      requestingUser: user.lanId,
      accessTime: new Date(),
      purpose: 'clinical_review',
    });
  }

  // Audit trail decorator usage
  @Post('/patient/:patientId/update')
  updatePatientRecord(
    @Param('patientId') patientId: string,
    @Body() updates: PatientUpdates,
    @CurrentUser() user: RequestUser,
  ) {
    // Perform update
    const result = await this.patientService.updateRecord(patientId, updates);

    // Log audit event
    await this.auditService.logEvent({
      action: 'patient_record_update',
      patientId,
      userId: user.lanId,
      changes: updates,
      timestamp: new Date(),
    });

    return result;
  }

  // Preference-aware decorator usage
  @Get('/dashboard')
  getPersonalizedDashboard(@CurrentUser() user: RequestUser) {
    // Get user preferences
    const preferences = await this.preferencesService.getDataConceptPreferences(
      user.lanId,
      'default',
      'default',
    );

    // Build personalized dashboard
    return this.dashboardService.buildPersonalizedDashboard(user.lanId, preferences);
  }

  // Multi-tenant decorator usage
  @Get('/organization/:orgId/data')
  getOrganizationData(
    @Param('orgId') orgId: string,
    @CurrentUser() user: RequestUser,
  ) {
    // Validate organization access
    this.validateOrganizationAccess(user, orgId);

    // Get organization-specific data
    return this.organizationService.getData(orgId, {
      requestingUser: user.lanId,
      userTenant: user.entraUser?.userTokenPayload?.tid,
    });
  }

  // Rate-limited decorator usage
  @Post('/api-call')
  makeRateLimitedApiCall(
    @Body() apiRequest: ApiRequest,
    @CurrentUser() user: RequestUser,
  ) {
    // Rate limiting is handled by middleware/guards
    // User context is available for additional validation
    return this.apiService.makeCall(apiRequest, {
      userId: user.lanId,
      tenantId: user.entraUser?.userTokenPayload?.tid,
    });
  }

  // Validation decorator usage
  @Post('/clinical-data')
  submitClinicalData(
    @Body() clinicalData: ClinicalData,
    @CurrentUser() user: RequestUser,
  ) {
    // Validate clinical data
    this.validateClinicalData(clinicalData);

    // Validate user permissions for data submission
    this.validateClinicalPermissions(user, clinicalData.type);

    // Submit data with user context
    return this.clinicalService.submitData(clinicalData, {
      submittedBy: user.lanId,
      submissionTime: new Date(),
      userCredentials: user.entraUser ? 'entra' : 'epic',
    });
  }

  // Error handling decorator usage
  @Get('/error-prone-operation')
  performErrorProneOperation(@CurrentUser() user: RequestUser) {
    try {
      return this.unreliableService.performOperation({
        userId: user.lanId,
        retryCount: 0,
        context: {
          userSource: user.entraUser ? 'entra' : 'epic',
          tenantId: user.entraUser?.userTokenPayload?.tid,
        },
      });
    } catch (error) {
      // Log error with full context
      await this.errorService.logError(error, {
        userId: user.lanId,
        operation: 'error_prone_operation',
        context: {
          userSource: user.entraUser ? 'entra' : 'epic',
          tenantId: user.entraUser?.userTokenPayload?.tid,
        },
      });

      throw new HttpException(
        'Operation failed, please try again',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
```

### **3. Custom Decorator Creation**

```typescript
// Custom decorators for healthcare domain
export const PatientAccess = createParamDecorator(
  async (patientId: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as RequestUser;

    // If patientId not provided as parameter, try to get from request
    const actualPatientId = patientId || request.params.patientId;

    if (!actualPatientId) {
      throw new BadRequestException('Patient ID is required');
    }

    // Validate patient access
    const hasAccess = await this.patientAccessService.validateAccess(
      user.lanId,
      actualPatientId,
    );

    if (!hasAccess) {
      throw new ForbiddenException('Access denied to patient record');
    }

    // Return patient context
    return {
      patientId: actualPatientId,
      accessValidated: true,
      accessTime: new Date(),
    };
  },
);

export const AuditOperation = (operation: string) =>
  createParamDecorator(async (_: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as RequestUser;

    // Perform audit logging
    await this.auditService.logOperation({
      operation,
      userId: user.lanId,
      timestamp: new Date(),
      ipAddress: request.ip,
      userAgent: request.get('User-Agent'),
      metadata: {
        method: request.method,
        url: request.originalUrl,
        userSource: user.entraUser ? 'entra' : 'epic',
      },
    });

    return operation;
  });

// Usage of custom decorators
@Controller('medical')
export class MedicalController {
  @Get('/patient/:patientId/chart')
  getPatientChart(
    @PatientAccess() patientAccess: any,
    @AuditOperation('view_patient_chart') _operation: string,
    @CurrentUser() user: RequestUser,
  ) {
    // Patient access already validated
    // Operation already audited
    return this.medicalService.getPatientChart(patientAccess.patientId);
  }

  @Post('/patient/:patientId/note')
  addPatientNote(
    @PatientAccess() patientAccess: any,
    @AuditOperation('add_patient_note') _operation: string,
    @Body() note: PatientNote,
    @CurrentUser() user: RequestUser,
  ) {
    // All validations and auditing already performed
    return this.medicalService.addPatientNote(
      patientAccess.patientId,
      note,
      user.lanId,
    );
  }
}
```

---

## 🎯 **Best Practices & Guidelines**

### **1. Decorator Design Principles**

```typescript
// Best practices for decorator implementation
@Injectable()
export class DecoratorBestPractises {
  // 1. Keep decorators focused and single-purpose
  @Injectable()
  export class FocusedDecorator {
    // Good: Single responsibility
    export const UserId = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): string => {
        const request = ctx.switchToHttp().getRequest();
        return request.user?.id;
      },
    );

    // Avoid: Multiple responsibilities
    export const ComplexUserDecorator = createParamDecorator(
      (options: ComplexOptions, ctx: ExecutionContext) => {
        // This decorator does too many things
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;

        // Logging, validation, transformation, etc.
        this.logger.log('User access', user);
        this.validateUser(user);
        return this.transformUser(user, options);
      },
    );
  }

  // 2. Make decorators configurable
  @Injectable()
  export class ConfigurableDecorator {
    export const ValidatedParam = createParamDecorator(
      (validationOptions: ValidationOptions, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        const value = request.params[validationOptions.paramName];

        // Apply configuration
        if (validationOptions.required && !value) {
          if (validationOptions.throwOnMissing) {
            throw new BadRequestException(`${validationOptions.paramName} is required`);
          }
          return validationOptions.defaultValue;
        }

        return value;
      },
    );

    // Usage with different configurations
    @Get('/user/:id')
    getUser(
      @ValidatedParam({
        paramName: 'id',
        required: true,
        throwOnMissing: true,
      }) id: string,
    ) {}

    @Get('/optional/:id?')
    getOptional(
      @ValidatedParam({
        paramName: 'id',
        required: false,
        defaultValue: 'default',
        throwOnMissing: false,
      }) id: string,
    ) {}
  }

  // 3. Handle errors gracefully
  @Injectable()
  export class ErrorHandlingDecorator {
    export const SafeParam = createParamDecorator(
      (fallback: any, ctx: ExecutionContext) => {
        try {
          const request = ctx.switchToHttp().getRequest();
          const value = request.user?.profile?.name;

          if (!value) {
            this.logger.warn('User profile name not found, using fallback');
            return fallback;
          }

          return value;
        } catch (error) {
          this.logger.error('Error in SafeParam decorator', error);
          return fallback;
        }
      },
    );
  }

  // 4. Use proper TypeScript typing
  @Injectable()
  export class TypedDecorator {
    export interface UserContext {
      id: string;
      name: string;
      roles: string[];
    }

    export const TypedUser = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): UserContext => {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;

        // Ensure type safety
        if (!this.isValidUser(user)) {
          throw new UnauthorizedException('Invalid user context');
        }

        return {
          id: user.id,
          name: user.name,
          roles: user.roles || [],
        };
      },
    );

    private isValidUser(user: any): user is UserContext {
      return user &&
             typeof user.id === 'string' &&
             typeof user.name === 'string' &&
             Array.isArray(user.roles);
    }
  }

  // 5. Document decorator behavior
  @Injectable()
  export class DocumentedDecorator {
    /**
     * Parameter decorator that extracts the authenticated user's permissions
     *
     * @param scope - Optional scope to filter permissions (e.g., 'read', 'write')
     * @returns Array of permission strings the user has
     *
     * @example
     * ```typescript
     * @Get('/admin')
     * getAdminData(@UserPermissions('admin') permissions: string[]) {
     *   if (!permissions.includes('admin.read')) {
     *     throw new ForbiddenException();
     *   }
     *   return this.adminService.getData();
     * }
     * ```
     *
     * @throws UnauthorizedException if user is not authenticated
     * @throws ForbiddenException if user has insufficient permissions
     */
    export const UserPermissions = createParamDecorator(
      (scope: string | undefined, ctx: ExecutionContext): string[] => {
        // Implementation with proper documentation
      },
    );
  }

  // 6. Test decorators thoroughly
  @Injectable()
  export class TestedDecorator {
    export const TestableDecorator = createParamDecorator(
      (data: unknown, ctx: ExecutionContext) => {
        // Extract dependencies for testability
        const request = ctx.switchToHttp().getRequest();

        // Use pure functions where possible
        return this.extractUserPermissions(request.user, data);
      },
    );

    // Pure function for easy testing
    extractUserPermissions(user: any, scope?: string): string[] {
      if (!user || !user.permissions) {
        return [];
      }

      let permissions = user.permissions;

      if (scope) {
        permissions = permissions.filter(p => p.startsWith(`${scope}.`));
      }

      return permissions;
    }
  }

  // 7. Avoid side effects in decorators
  @Injectable()
  export class SideEffectFreeDecorator {
    // Good: No side effects
    export const PureParam = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): string => {
        const request = ctx.switchToHttp().getRequest();
        return request.params.id;
      },
    );

    // Avoid: Side effects in decorators
    export const SideEffectParam = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): string => {
        const request = ctx.switchToHttp().getRequest();

        // Side effect: Modifying request object
        request.lastAccessed = new Date();

        // Side effect: External API call
        this.externalService.notifyAccess(request.params.id);

        return request.params.id;
      },
    );
  }
}
```

### **2. Performance Optimization**

```typescript
// Performance optimization strategies for decorators
@Injectable()
export class DecoratorPerformanceOptimization {
  // 1. Cache expensive computations
  @Injectable()
  export class CachedDecorator {
    private readonly cache = new Map<string, any>();

    export const CachedUserPermissions = createParamDecorator(
      (scope: string | undefined, ctx: ExecutionContext): string[] => {
        const request = ctx.switchToHttp().getRequest();
        const cacheKey = `${request.user?.id}:${scope}`;

        if (this.cache.has(cacheKey)) {
          return this.cache.get(cacheKey);
        }

        const permissions = this.computeUserPermissions(request.user, scope);
        this.cache.set(cacheKey, permissions);

        // Expire cache after 5 minutes
        setTimeout(() => this.cache.delete(cacheKey), 5 * 60 * 1000);

        return permissions;
      },
    );
  }

  // 2. Use lazy evaluation
  @Injectable()
  export class LazyDecorator {
    export const LazyUserData = createParamDecorator(
      (data: unknown, ctx: ExecutionContext) => {
        // Return a proxy that computes values lazily
        return new Proxy({}, {
          get: (target, property) => {
            if (!(property in target)) {
              const request = ctx.switchToHttp().getRequest();
              target[property] = this.computeUserProperty(request.user, property);
            }
            return target[property];
          },
        });
      },
    );
  }

  // 3. Batch operations
  @Injectable()
  export class BatchDecorator {
    private readonly batchQueue: any[] = [];

    export const BatchedUserLookup = createParamDecorator(
      (userIds: string[], ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();

        // Add to batch queue
        this.batchQueue.push({
          userIds,
          requestId: request.id,
          resolve: null,
          reject: null,
        });

        // Return promise that resolves when batch is processed
        return new Promise((resolve, reject) => {
          const currentBatch = this.batchQueue[this.batchQueue.length - 1];
          currentBatch.resolve = resolve;
          currentBatch.reject = reject;

          // Process batch if it's full
          if (this.batchQueue.length >= 10) {
            this.processBatch();
          }
        });
      },
    );

    private async processBatch() {
      const batch = [...this.batchQueue];
      this.batchQueue.length = 0;

      try {
        // Process all user lookups in batch
        const results = await this.userService.batchLookup(
          batch.flatMap(b => b.userIds),
        );

        // Resolve individual promises
        batch.forEach((item, index) => {
          item.resolve(results[index]);
        });
      } catch (error) {
        // Reject all promises in batch
        batch.forEach(item => item.reject(error));
      }
    }
  }

  // 4. Use streaming for large data
  @Injectable()
  export class StreamingDecorator {
    export const StreamingUserData = createParamDecorator(
      (data: unknown, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();

        // Return a readable stream
        return this.userService.streamUserData(request.user?.id);
      },
    );
  }

  // 5. Optimize memory usage
  @Injectable()
  export class MemoryOptimizedDecorator {
    private readonly weakMap = new WeakMap();

    export const WeakMapDecorator = createParamDecorator(
      (data: unknown, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();

        // Use WeakMap to avoid memory leaks
        if (!this.weakMap.has(request)) {
          this.weakMap.set(request, this.computeExpensiveData(request));
        }

        return this.weakMap.get(request);
      },
    );
  }
}
```

### **3. Security Considerations**

```typescript
// Security best practices for decorators
@Injectable()
export class DecoratorSecurityBestPractises {
  // 1. Validate input data
  @Injectable()
  export class ValidatedDecorator {
    export const ValidatedUserId = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): string => {
        const request = ctx.switchToHttp().getRequest();
        const userId = request.user?.id;

        // Validate user ID format
        if (!this.isValidUserId(userId)) {
          throw new BadRequestException('Invalid user ID format');
        }

        // Check if user ID is allowed
        if (!this.isAllowedUserId(userId)) {
          throw new ForbiddenException('User ID not allowed');
        }

        return userId;
      },
    );

    private isValidUserId(userId: string): boolean {
      // UUID format validation
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      return uuidRegex.test(userId);
    }

    private isAllowedUserId(userId: string): boolean {
      // Check against blacklist or whitelist
      return !this.blacklist.includes(userId);
    }
  }

  // 2. Sanitize output data
  @Injectable()
  export class SanitizedDecorator {
    export const SanitizedUserData = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): SanitizedUser => {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;

        return {
          id: user.id,
          name: this.sanitizeString(user.name),
          email: this.maskEmail(user.email),
          // Don't expose sensitive fields like password, tokens, etc.
        };
      },
    );

    private sanitizeString(str: string): string {
      if (!str) return str;
      // Remove potentially dangerous characters
      return str.replace(/[<>'"&]/g, '');
    }

    private maskEmail(email: string): string {
      if (!email) return email;
      const [local, domain] = email.split('@');
      const maskedLocal = local.charAt(0) + '*'.repeat(local.length - 1);
      return `${maskedLocal}@${domain}`;
    }
  }

  // 3. Implement rate limiting
  @Injectable()
  export class RateLimitedDecorator {
    private readonly requestCounts = new Map<string, number[]>();

    export const RateLimitedParam = createParamDecorator(
      (options: RateLimitOptions, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        const clientId = request.ip;

        const now = Date.now();
        const windowStart = now - (options.windowMs || 60000);

        // Get or create request timestamps for this client
        let clientRequests = this.requestCounts.get(clientId) || [];
        clientRequests = clientRequests.filter(timestamp => timestamp > windowStart);

        if (clientRequests.length >= (options.max || 10)) {
          throw new HttpException(
            'Too many requests',
            HttpStatus.TOO_MANY_REQUESTS,
          );
        }

        clientRequests.push(now);
        this.requestCounts.set(clientId, clientRequests);

        // Continue with normal processing
        return this.extractParamValue(ctx, options.paramName);
      },
    );
  }

  // 4. Add security headers
  @Injectable()
  export class SecurityHeadersDecorator {
    export const WithSecurityHeaders = createParamDecorator(
      (_: unknown, ctx: ExecutionContext) => {
        const response = ctx.switchToHttp().getResponse();

        // Add security headers
        response.setHeader('X-Content-Type-Options', 'nosniff');
        response.setHeader('X-Frame-Options', 'DENY');
        response.setHeader('X-XSS-Protection', '1; mode=block');
        response.setHeader('Strict-Transport-Security', 'max-age=31536000');
        response.setHeader('Content-Security-Policy', "default-src 'self'");

        // Return the original parameter
        return this.extractOriginalValue(ctx);
      },
    );
  }

  // 5. Log security events
  @Injectable()
  export class SecurityLoggingDecorator {
    export const SecurityLogged = createParamDecorator(
      (operation: string, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;

        // Log security event
        this.securityLogger.log({
          operation,
          userId: user?.id,
          ipAddress: request.ip,
          userAgent: request.get('User-Agent'),
          timestamp: new Date(),
          severity: 'info',
        });

        return this.extractOriginalValue(ctx);
      },
    );
  }

  // 6. Prevent information leakage
  @Injectable()
  export class LeakagePreventionDecorator {
    export const LeakageSafe = createParamDecorator(
      (_: unknown, ctx: ExecutionContext): SafeUserData => {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user;

        // Only return safe, non-sensitive data
        return {
          id: user.id,
          name: user.name,
          role: user.role,
          // Exclude: password, tokens, secrets, etc.
        };
      },
    );
  }

  // 7. Implement timeout protection
  @Injectable()
  export class TimeoutProtectedDecorator {
    export const WithTimeout = createParamDecorator(
      (timeoutMs: number, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();

        // Set request timeout
        const timeout = setTimeout(() => {
          this.logger.warn(`Request timeout after ${timeoutMs}ms`, {
            url: request.originalUrl,
            method: request.method,
            ip: request.ip,
          });

          // You might want to end the response or take other actions
        }, timeoutMs);

        // Store timeout for cleanup
        request['timeoutHandle'] = timeout;

        return this.extractOriginalValue(ctx);
      },
    );
  }
}
```

---

## 🎯 **Next Steps**

Now that you understand the Parameter & Metadata Decorators comprehensively, explore:

1. **[Entities & DTOs](./../entities-dtos.md)** - Database models and API contracts
2. **[Provider Specialty Service](./../services/provider-specialty.md)** - Healthcare provider data management
3. **[Introspect Service](./../services/introspect.md)** - Authentication token validation

Each component integrates with the decorators to provide a complete type-safe, metadata-driven application architecture that enhances developer experience and application maintainability.

**🚀 Ready to explore the database entities and data transfer objects that define the application's data contracts? Your decorator expertise will help you understand how these foundational components work together to create a robust data layer!**
