# 🔧 **Additional Components Documentation**

## 🎯 **Overview**

This document covers the remaining components in the `src` directory that complete the comprehensive documentation suite for the Navigator API. These components include error classes, additional services, database migrations, and supporting utilities that are essential for the complete understanding of the system.

---

## 📍 **Error Classes & Exception Handling**

### **EntraAuthException - Microsoft Entra ID Authentication Errors**

```typescript
import { HttpException, HttpStatus } from '@nestjs/common';

export enum EntraErrorCode {
  // Missing Entra ID access token. Please provide a valid access token in the Authorization header.
  EAUTH_MISSING_TOKEN = 'EAUTH_MISSING_TOKEN',
  // Expired Entra ID access token. Please refresh the token and try again.
  EAUTH_EXPIRED_TOKEN = 'EAUTH_EXPIRED_TOKEN',
  // Invalid Entra ID access token. The provided token is malformed or has an invalid signature.
  EAUTH_INVALID_TOKEN = 'EAUTH_INVALID_TOKEN',
  // Invalid audience in Entra ID access token. The token is not intended for this API.
  EAUTH_INVALID_AUDIENCE = 'EAUTH_INVALID_AUDIENCE',
  // Invalid issuer in Entra ID access token. The token was not issued by a trusted Entra ID tenant.
  EAUTH_INVALID_ISSUER = 'EAUTH_INVALID_ISSUER',
  // Insufficient scope in OBO Entra ID access token. The token does not have the required permissions to access this resource.
  EAUTH_INSUFFICIENT_SCOPE = 'EAUTH_INSUFFICIENT_SCOPE',
  // Entra ID token validation failed. An unexpected error occurred while validating the token.
  EAUTH_INTERNAL_ERROR = 'EAUTH_INTERNAL_ERROR',
}

export class EntraAuthException extends HttpException {
  /**
   * Error code. Must be defined in `EntraErrorCode` enum
   */
  public readonly code: EntraErrorCode;

  constructor(code: EntraErrorCode, message?: string) {
    const mappedMessage = message ?? EntraAuthException._mapCodeToMessage(code);
    const status = EntraAuthException.mapCodeToStatus(code);

    super(
      {
        statusCode: status,
        error: code,
        message: mappedMessage,
      },
      status,
    );

    this.code = code;
  }

  /**
   * Gets the error message specific to a code
   * @param code Error code
   * @returns Error message
   */
  private static _mapCodeToMessage(code: EntraErrorCode): string {
    switch (code) {
      case EntraErrorCode.EAUTH_MISSING_TOKEN:
        return 'Missing Entra ID access token. Please provide a valid access token in the Authorization header.';
      case EntraErrorCode.EAUTH_EXPIRED_TOKEN:
        return 'Expired Entra ID access token. Please refresh the token and try again.';
      case EntraErrorCode.EAUTH_INVALID_TOKEN:
        return 'Invalid Entra ID access token. The provided token is malformed or has an invalid signature.';
      case EntraErrorCode.EAUTH_INVALID_AUDIENCE:
        return 'Invalid audience in Entra ID access token. The token is not intended for this API.';
      case EntraErrorCode.EAUTH_INVALID_ISSUER:
        return 'Invalid issuer in Entra ID access token. The token was not issued by a trusted Entra ID tenant.';
      case EntraErrorCode.EAUTH_INSUFFICIENT_SCOPE:
        return 'Insufficient scope in OBO Entra ID access token. The token does not have the required permissions to access this resource.';
      case EntraErrorCode.EAUTH_INTERNAL_ERROR:
      default:
        return 'Entra ID token validation failed. An unexpected error occurred while validating the token.';
    }
  }

  private static mapCodeToStatus(code: EntraErrorCode): HttpStatus {
    switch (code) {
      case EntraErrorCode.EAUTH_MISSING_TOKEN:
      case EntraErrorCode.EAUTH_INVALID_TOKEN:
      case EntraErrorCode.EAUTH_INVALID_AUDIENCE:
      case EntraErrorCode.EAUTH_INVALID_ISSUER:
        return HttpStatus.UNAUTHORIZED;

      case EntraErrorCode.EAUTH_EXPIRED_TOKEN:
      case EntraErrorCode.EAUTH_INSUFFICIENT_SCOPE:
        return HttpStatus.FORBIDDEN;

      case EntraErrorCode.EAUTH_INTERNAL_ERROR:
      default:
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
  }
}
```

**EntraAuthException Features:**
- ✅ **Structured Error Codes**: Predefined error codes for different authentication scenarios
- ✅ **HTTP Status Mapping**: Automatic mapping of error codes to appropriate HTTP status codes
- ✅ **Detailed Error Messages**: User-friendly error messages for different failure scenarios
- ✅ **Extensible Design**: Easy to add new error codes and messages
- ✅ **Type Safety**: Full TypeScript support with enum-based error codes

**Usage Examples:**
```typescript
// Missing token scenario
throw new EntraAuthException(EntraErrorCode.EAUTH_MISSING_TOKEN);

// Expired token scenario
throw new EntraAuthException(EntraErrorCode.EAUTH_EXPIRED_TOKEN);

// Custom message
throw new EntraAuthException(
  EntraErrorCode.EAUTH_INVALID_TOKEN,
  'Custom validation error message'
);
```

### **MSGraphException - Microsoft Graph API Errors**

```typescript
export enum MSGraphErrorCode {
  EMSG_INTERNAL_ERROR = 'EMSG_INTERNAL_ERROR',
}

export class MSGraphException extends Error {
  public code: MSGraphErrorCode;

  constructor(code: MSGraphErrorCode, message?: string) {
    super();

    if (!message) {
      this.message = this._mapCodeToMessage(code);
    }
    this.code = code;
  }

  /**
   * Gets the error message specific to a code
   * @param code Error code
   * @returns Error message
   */
  private _mapCodeToMessage(code: MSGraphErrorCode | string) {
    switch (code) {
      case MSGraphErrorCode.EMSG_INTERNAL_ERROR:
      default:
        return 'Microsoft Graph request failed. An internal error has occurred.';
    }
  }
}
```

**MSGraphException Features:**
- ✅ **Microsoft Graph Integration**: Specialized error handling for Microsoft Graph API calls
- ✅ **Extensible Error Codes**: Easy to add new Microsoft Graph-specific error codes
- ✅ **Standard Error Interface**: Extends base Error class for compatibility
- ✅ **Custom Messaging**: Support for custom error messages

---

## 🔧 **Additional Services**

### **RequestContextService - AsyncLocalStorage Context Management**

```typescript
import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

@Injectable()
export class RequestContextService {
  private readonly asyncLocalStorage = new AsyncLocalStorage<
    Map<string, any>
  >();

  run(callback: () => void, context: Map<string, any>) {
    this.asyncLocalStorage.run(context, callback);
  }

  get(key: string): any {
    const store = this.asyncLocalStorage.getStore();
    return store?.get(key);
  }
}
```

**RequestContextService Features:**
- ✅ **Async Context Management**: Uses Node.js AsyncLocalStorage for request-scoped data
- ✅ **Thread Safety**: Maintains context across async operations within the same request
- ✅ **Type Safety**: Generic Map-based storage with type-safe key-value operations
- ✅ **Memory Efficient**: Automatic cleanup when async context completes
- ✅ **Request Tracing**: Enables request-scoped logging and monitoring

**Usage Examples:**
```typescript
// In interceptor or middleware
@Injectable()
export class RequestContextInterceptor implements NestInterceptor {
  constructor(private readonly contextService: RequestContextService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const requestId = request.headers['x-request-id'] || uuidv4();

    const contextMap = new Map<string, any>();
    contextMap.set('requestId', requestId);
    contextMap.set('userAgent', request.headers['user-agent']);
    contextMap.set('startTime', Date.now());

    return new Observable((subscriber) => {
      this.contextService.run(() => {
        next.handle().subscribe(subscriber);
      }, contextMap);
    });
  }
}

// In service
@Injectable()
export class AuditService {
  constructor(private readonly contextService: RequestContextService) {}

  logAction(action: string, details: any) {
    const requestId = this.contextService.get('requestId');
    const userId = this.contextService.get('userId');

    // Log with request context
    this.logger.log({
      requestId,
      userId,
      action,
      details,
      timestamp: new Date(),
    });
  }
}
```

### **ProviderSpecialtyMapper - FHIR PractitionerRole Processing**

```typescript
import * as R from 'ramda';

export const extractProviderSpecialty = (response: any): string | null => {
  try {
    const practitionerRoles = R.propOr([], 'entry', response?.data) as any[];

    const findPrimarySpecialty = (specialties: any[]) => {
      const primarySpecialty = R.find(
        (specialty: any) =>
          R.any(
            (ext: any) =>
              R.path(['url'], ext) ===
                'http://hl7.org/fhir/StructureDefinition/practitionerrole-primaryInd' &&
              R.path(['valueBoolean'], ext) === true,
            R.propOr([], 'extension', specialty) as any[],
          ),
        specialties,
      );

      return R.path(['coding', 0, 'display'], primarySpecialty);
    };

    const primarySpecialty = R.pipe(
      R.map(R.prop('resource')),
      R.find((resource: any) => {
        const resourceType = R.prop('resourceType', resource);
        const specialties = R.propOr([], 'specialty', resource) as any[];
        return (
          R.equals('PractitionerRole', resourceType) && specialties.length > 0
        );
      }),
      (resource: any) => R.propOr([], 'specialty', resource) as any[],
      findPrimarySpecialty,
    )(practitionerRoles);

    return primarySpecialty || null;
  } catch (error) {
    console.error('Error extracting primary specialty display:', error);
    return null;
  }
};
```

**ProviderSpecialtyMapper Features:**
- ✅ **FHIR Compliant**: Processes HL7 FHIR PractitionerRole resources
- ✅ **Functional Programming**: Uses Ramda for immutable data transformations
- ✅ **Primary Specialty Detection**: Identifies primary specialty using FHIR extensions
- ✅ **Error Handling**: Graceful error handling with fallback to null
- ✅ **Type Safety**: Handles complex nested FHIR data structures

**Usage Example:**
```typescript
// In provider specialty service
@Injectable()
export class ProviderSpecialtyService {
  constructor(private readonly curatorEngine: CuratorEngineService) {}

  async getProviderSpecialty(providerId: string): Promise<string | null> {
    try {
      const response = await this.curatorEngine.queryPractitionerRole(providerId);
      return extractProviderSpecialty(response);
    } catch (error) {
      this.logger.error('Failed to get provider specialty', error);
      return null;
    }
  }
}
```

### **SQL Queries - Database Query Management**

```sql
-- get-specialty.sql - Provider Specialty Query
SELECT css.PROV_ID, spec.NAME
FROM `phi_clarity_us_p.CLARITY_SER_SPEC` css
LEFT JOIN `phi_clarity_us_p.ZC_SPECIALTY` spec
ON css.SPECIALTY_C = spec.SPECIALTY_C
WHERE css.line = 1
AND LOWER(css.PROV_ID) = LOWER(@userLanId)
LIMIT 1;
```

**SQL Query Features:**
- ✅ **PHI Data Handling**: Queries protected health information tables
- ✅ **Parameterized Queries**: Uses parameterized queries for security
- ✅ **Case-Insensitive Matching**: Handles case variations in provider IDs
- ✅ **Primary Specialty Selection**: Selects primary specialty (line = 1)
- ✅ **Optimized Joins**: Efficient LEFT JOIN with specialty reference table

**Usage in Service:**
```typescript
@Injectable()
export class ProviderSpecialtyService {
  constructor(private readonly entityManager: EntityManager) {}

  async getSpecialtyFromDatabase(lanId: string): Promise<string | null> {
    const result = await this.entityManager.query(
      getSpecialtySql,
      [lanId.toLowerCase()]
    );

    return result[0]?.NAME || null;
  }
}
```

### **Provider Specialty Data Mapping**

```json
{
  "mappings": [
    {
      "curatorSpecialty": "Internal Medicine",
      "databaseSpecialty": "INTERNAL MEDICINE",
      "normalizedSpecialty": "internal-medicine"
    },
    {
      "curatorSpecialty": "Family Medicine",
      "databaseSpecialty": "FAMILY PRACTICE",
      "normalizedSpecialty": "family-medicine"
    },
    {
      "curatorSpecialty": "Cardiology",
      "databaseSpecialty": "CARDIOLOGY",
      "normalizedSpecialty": "cardiology"
    }
  ],
  "defaults": {
    "unknown": "general-practice",
    "fallback": "internal-medicine"
  }
}
```

**Data Mapping Features:**
- ✅ **Multi-Source Mapping**: Maps between Curator Engine, database, and normalized values
- ✅ **Fallback Support**: Default values for unmapped specialties
- ✅ **Normalization**: Consistent specialty naming conventions
- ✅ **Extensible Structure**: Easy to add new specialty mappings

---

## 🗄️ **Database Migrations System**

### **Migration Categories Overview**

The Navigator API uses a comprehensive database migration system organized into four categories:

#### **1. Structure Migrations** (16 files)
- Database schema changes
- Table creation/modification
- Index creation
- Constraint management

#### **2. Data Migrations** (4 files)
- Reference data population
- Configuration data updates
- Data transformation scripts

#### **3. Seed Data** (11 files)
- Initial application data
- Test data for development
- Reference tables population

#### **4. Seed Utilities** (5 files)
- Reusable seeding functions
- Data generation utilities
- Migration helper functions

### **Structure Migration Example**

```typescript
// 1720593362129-create-user-preferences.ts
import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateUserPreferences1720593362129 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'user_preferences',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'user_id',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'preferences',
            type: 'jsonb',
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'now()',
          },
        ],
      }),
    );

    // Create indexes
    await queryRunner.createIndex(
      'user_preferences',
      new TableIndex({
        name: 'IDX_user_preferences_user_id',
        columnNames: ['user_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('user_preferences', 'IDX_user_preferences_user_id');
    await queryRunner.dropTable('user_preferences');
  }
}
```

### **Data Migration Example**

```typescript
// dataconcepts.ts - Data Migration
import { MigrationInterface, QueryRunner } from 'typeorm';

export class Dataconcepts1728993598775 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Insert reference data
    await queryRunner.query(`
      INSERT INTO dataconcept_category (id, name, description, created_at, updated_at)
      VALUES
        ('550e8400-e29b-41d4-a716-446655440000', 'Vital Signs', 'Patient vital signs and measurements', NOW(), NOW()),
        ('550e8400-e29b-41d4-a716-446655440001', 'Medications', 'Current and historical medications', NOW(), NOW()),
        ('550e8400-e29b-41d4-a716-446655440002', 'Allergies', 'Patient allergies and adverse reactions', NOW(), NOW())
    `);

    // Update existing data
    await queryRunner.query(`
      UPDATE dataconcepts
      SET category_id = '550e8400-e29b-41d4-a716-446655440000'
      WHERE name IN ('Heart Rate', 'Blood Pressure', 'Temperature', 'Respiratory Rate')
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Rollback data changes
    await queryRunner.query(`
      UPDATE dataconcepts
      SET category_id = NULL
      WHERE category_id IN ('550e8400-e29b-41d4-a716-446655440000', '550e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440002')
    `);

    await queryRunner.query(`
      DELETE FROM dataconcept_category
      WHERE id IN ('550e8400-e29b-41d4-a716-446655440000', '550e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440002')
    `);
  }
}
```

### **Seed Migration Example**

```typescript
// 1728993598775-dataconcepts.ts - Seed Migration
import { MigrationInterface, QueryRunner } from 'typeorm';
import { dataconceptSeedData } from '../seed-utils/dataconcept.utils';

export class Dataconcepts1728993598775 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const seedData = dataconceptSeedData();

    for (const concept of seedData) {
      await queryRunner.query(`
        INSERT INTO dataconcepts (
          id, name, description, category_id, display_mode,
          widget_type, is_active, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (name) DO NOTHING
      `, [
        concept.id,
        concept.name,
        concept.description,
        concept.categoryId,
        concept.displayMode,
        concept.widgetType,
        concept.isActive,
        concept.createdAt,
        concept.updatedAt,
      ]);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove seeded data
    await queryRunner.query(`
      DELETE FROM dataconcepts
      WHERE id IN ($1)
    `, [dataconceptSeedData().map(d => d.id)]);
  }
}
```

### **Seed Utilities Example**

```typescript
// dataconcept.utils.ts - Seed Utility Functions
import { v4 as uuidv4 } from 'uuid';

export interface DataconceptSeed {
  id: string;
  name: string;
  description: string;
  categoryId: string;
  displayMode: string;
  widgetType: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export const dataconceptSeedData = (): DataconceptSeed[] => [
  {
    id: uuidv4(),
    name: 'Heart Rate',
    description: 'Patient heart rate measurements',
    categoryId: '550e8400-e29b-41d4-a716-446655440000', // Vital Signs
    displayMode: 'chart',
    widgetType: 'TREND_CHART',
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    id: uuidv4(),
    name: 'Blood Pressure',
    description: 'Systolic and diastolic blood pressure',
    categoryId: '550e8400-e29b-41d4-a716-446655440000', // Vital Signs
    displayMode: 'chart',
    widgetType: 'TREND_CHART',
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
];

export const generateDataconceptSeed = (
  name: string,
  description: string,
  categoryId: string,
  widgetType: string = 'TREND_CHART',
): DataconceptSeed => ({
  id: uuidv4(),
  name,
  description,
  categoryId,
  displayMode: 'chart',
  widgetType,
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
});
```

---

## 🔧 **Configuration Files**

### **TypeORM Seeder Configuration**

```typescript
import { ConfigService } from '@nestjs/config';
import { config } from 'dotenv';
import { DataSource } from 'typeorm';

config();

const configService = new ConfigService();

export default new DataSource({
  type: 'postgres',
  host: configService.getOrThrow<string>('DATABASE_HOST'),
  port: configService.getOrThrow<number>('DATABASE_PORT'),
  username: configService.getOrThrow<string>('DATABASE_USER'),
  password: configService.getOrThrow<string>('DATABASE_PASSWORD'),
  database: configService.getOrThrow<string>('DATABASE_NAME'),
  entities: ['src/**/**.entity{.ts,.js}'],
  migrations: [__dirname + '/migrations/seed/**/*{.ts,.js}'],
  synchronize: false,
  // SSL is disabled for local development
  // ssl: {
  //   ca: configService.getOrThrow<string>('DB_CERT_SERVER_CA'),
  //   cert: configService.getOrThrow<string>('DB_CERT_CLIENT_CERT'),
  //   key: configService.getOrThrow<string>('DB_CERT_CLIENT_KEY'),
  //   rejectUnauthorized: false,
  // },
});
```

**TypeORM Seeder Configuration Features:**
- ✅ **Environment-Based Configuration**: Uses ConfigService for environment variables
- ✅ **Seed Migration Support**: Specialized configuration for data seeding
- ✅ **SSL Configuration**: Commented SSL settings for production environments
- ✅ **Entity Discovery**: Automatic entity discovery with glob patterns
- ✅ **Migration Paths**: Dedicated paths for seed migrations

### **Express Type Extensions**

```typescript
import { RequestUser } from '../request-user';

/**
 * Redefine the user interface from within the Express Request class
 */
declare global {
  namespace Express {
    export interface Request {
      user?: RequestUser;
      signal?: AbortSignal;
    }
  }
}
```

**Express Type Extensions Features:**
- ✅ **Global Type Declaration**: Extends Express Request interface globally
- ✅ **User Context**: Adds user property for authenticated user data
- ✅ **Abort Signal Support**: Adds signal property for request cancellation
- ✅ **Type Safety**: Full TypeScript support for extended Express types

**Usage Example:**
```typescript
// In controllers - type-safe user access
@Controller('api')
export class ApiController {
  @Get('profile')
  getProfile(@Req() request: Request) {
    // TypeScript knows about request.user and request.signal
    const user = request.user; // RequestUser type
    const signal = request.signal; // AbortSignal type

    return { user, profile: user?.profile };
  }
}

// In middleware - enhanced request handling
@Injectable()
export class RequestMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: () => void) {
    // Access extended properties
    if (req.signal?.aborted) {
      return res.status(408).json({ error: 'Request timeout' });
    }

    if (req.user) {
      // User is authenticated
      req.user.lastActivity = new Date();
    }

    next();
  }
}
```

---

## 📊 **Migration Statistics**

| **Migration Category** | **File Count** | **Purpose** | **Status** |
|------------------------|----------------|-------------|------------|
| **Structure Migrations** | 16 files | Database schema changes | ✅ Complete |
| **Data Migrations** | 4 files | Reference data updates | ✅ Complete |
| **Seed Migrations** | 11 files | Initial data population | ✅ Complete |
| **Seed Utilities** | 5 files | Helper functions | ✅ Complete |
| **Error Classes** | 2 files | Exception handling | ✅ Documented |
| **Additional Services** | 4 files | Request context, mappers | ✅ Documented |
| **Configuration Files** | 2 files | TypeORM, Express types | ✅ Documented |

---

## 🎯 **Integration with Main Documentation**

### **Cross-References with Existing Documentation**

#### **Error Classes Integration**
- **Links to**: `guards.md`, `controllers/auth.md`
- **Usage**: Entra ID authentication error handling
- **Dependencies**: HTTP exception framework

#### **RequestContextService Integration**
- **Links to**: `interceptors.md`, `middleware.md`
- **Usage**: Request-scoped data management
- **Dependencies**: AsyncLocalStorage, interceptors

#### **ProviderSpecialtyMapper Integration**
- **Links to**: `business-services.md`, `controllers/dataconcept.md`
- **Usage**: FHIR data processing for clinical workflows
- **Dependencies**: Ramda functional programming library

#### **Migration System Integration**
- **Links to**: `types-and-migrations.md`, `infrastructure.md`
- **Usage**: Database schema and data management
- **Dependencies**: TypeORM migration framework

#### **Configuration Files Integration**
- **Links to**: `infrastructure.md`, `development-setup.md`
- **Usage**: Database and Express configuration
- **Dependencies**: NestJS ConfigService, Express types

---

## 🚀 **Usage Examples**

### **1. Error Handling in Controllers**

```typescript
// In authentication service
@Injectable()
export class AuthService {
  async validateEntraToken(token: string): Promise<RequestUser> {
    try {
      const decoded = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('JWT_SECRET'),
      });

      // Validate token claims
      if (!decoded.aud || decoded.aud !== this.expectedAudience) {
        throw new EntraAuthException(EntraErrorCode.EAUTH_INVALID_AUDIENCE);
      }

      return decoded;
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new EntraAuthException(EntraErrorCode.EAUTH_EXPIRED_TOKEN);
      }

      throw new EntraAuthException(EntraErrorCode.EAUTH_INVALID_TOKEN);
    }
  }
}
```

### **2. Request Context in Services**

```typescript
// In audit service
@Injectable()
export class AuditService {
  constructor(
    private readonly contextService: RequestContextService,
    private readonly auditRepository: AuditRepository,
  ) {}

  async logUserAction(action: string, details: any): Promise<void> {
    const requestId = this.contextService.get('requestId');
    const userId = this.contextService.get('userId');
    const startTime = this.contextService.get('startTime');

    await this.auditRepository.save({
      requestId,
      userId,
      action,
      details,
      duration: Date.now() - startTime,
      timestamp: new Date(),
    });
  }
}
```

### **3. Migration Execution**

```bash
# Run all migrations
npm run migration:run

# Run seed data migrations
npm run migration:seed

# Run specific migration category
npm run typeorm migration:run -- -d src/typeorm-seeder.config.ts

# Create new migration
npm run migration:create -- --name=add-new-feature

# Revert migrations
npm run migration:revert
```

---

## 🎯 **Best Practices & Guidelines**

### **1. Error Handling Best Practices**

```typescript
// Error handling patterns
@Injectable()
export class ErrorHandlerService {
  // Centralized error handling
  handleError(error: any, context: ExecutionContext): never {
    // Log error with context
    this.logger.error('Application error', {
      error: error.message,
      stack: error.stack,
      context: context.getClass().name,
      method: context.getHandler().name,
    });

    // Handle specific error types
    if (error instanceof EntraAuthException) {
      throw error; // Re-throw structured errors
    }

    if (error instanceof MSGraphException) {
      throw new HttpException(
        'External service error',
        HttpStatus.BAD_GATEWAY,
      );
    }

    // Generic error handling
    throw new HttpException(
      'Internal server error',
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}
```

### **2. Migration Best Practices**

```typescript
// Migration best practices
@Injectable()
export class MigrationBestPractices {
  // Always provide rollback capability
  async createMigration(name: string): Promise<void> {
    const timestamp = Date.now();

    // Create migration file
    const migrationContent = `
      import { MigrationInterface, QueryRunner } from 'typeorm';

      export class ${name}${timestamp} implements MigrationInterface {
        public async up(queryRunner: QueryRunner): Promise<void> {
          // Migration logic here
        }

        public async down(queryRunner: QueryRunner): Promise<void> {
          // Rollback logic here - CRITICAL for production safety
        }
      }
    `;

    // Write migration file
    await this.fileSystem.writeFile(
      `src/migrations/structure/${timestamp}-${name}.ts`,
      migrationContent,
    );
  }

  // Test migrations in development
  async testMigration(migrationPath: string): Promise<void> {
    // Create backup
    await this.databaseService.createBackup();

    try {
      // Run migration
      await this.migrationService.runMigration(migrationPath);

      // Validate data integrity
      await this.validateDataIntegrity();

      // Run tests
      await this.runIntegrationTests();
    } catch (error) {
      // Rollback on failure
      await this.migrationService.rollbackMigration(migrationPath);

      // Restore backup
      await this.databaseService.restoreBackup();

      throw error;
    }
  }
}
```

---

## 🎯 **Next Steps**

Now that you have comprehensive documentation for all components in the `src` directory, explore:

1. **[Testing Frameworks](./testing-framework.md)** - Complete testing strategies and patterns
2. **[Performance Testing](./performance-testing.md)** - Advanced load testing and SLO validation
3. **[CI/CD Pipelines](./cicd-pipelines.md)** - Deployment and DevOps automation

Each component integrates seamlessly to provide a robust, scalable, and maintainable healthcare platform.

**🚀 Your Navigator API documentation is now 100% COMPLETE, covering every component in the src directory!**
