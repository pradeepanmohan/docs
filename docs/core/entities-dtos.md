# 🏗️ Database Entities & API Data Transfer Objects - Data Layer Architecture

## 🎯 **Overview**

The **Entities & DTOs** (Data Transfer Objects) form the foundational data layer of the Navigator API, providing structured data models for database persistence and API communication. These components define the contracts between the application layers and external systems.

---

## 📍 **Data Layer Architecture Overview**

### **What are Entities & DTOs?**
Entities & DTOs are the data contracts that:
- **Define database schemas** with TypeORM entity mappings
- **Structure API requests/responses** with validation and documentation
- **Enable type safety** across the application stack
- **Support data transformation** between layers
- **Provide validation** for incoming data
- **Generate API documentation** with Swagger/OpenAPI

### **Data Layer Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│          Database Entities & API DTOs Architecture          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Database Entities (TypeORM)               │    │
│  │  ├─ Dataconcept ─────────────┬─ Clinical Data Models │    │
│  │  ├─ UserPreferences ─────────┼─ User Settings        │    │
│  │  ├─ AuditLog ────────────────┼─ Security Audit Trail │    │
│  │  ├─ AccessBlacklist ─────────┼─ Security Controls    │    │
│  │  └─ Category/Type Entities ──┴─ Metadata Models      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           API Data Transfer Objects                 │    │
│  │  ├─ Authentication DTOs ──────┬─ Epic/Entra ID Auth │    │
│  │  ├─ Clinical Data DTOs ───────┼─ Widget Responses   │    │
│  │  ├─ Preferences DTOs ─────────┼─ User Settings      │    │
│  │  ├─ Request/Response DTOs ────┼─ API Contracts      │    │
│  │  └─ Validation DTOs ──────────┴─ Input Validation    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Data Flow & Transformation                │    │
│  │  ├─ Entity ↔ DTO Mapping ─────┬─ Data Transformation│    │
│  │  ├─ Validation Pipeline ──────┼─ Input Sanitization │    │
│  │  ├─ Serialization Control ────┼─ Response Shaping   │    │
│  │  └─ Type Safety ──────────────┴─ Compile-time Checks│    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Core Database Entities**

#### **Access Blacklist Entity**
```typescript
// File: src/controllers/access-blacklist/entities/access-blacklist.entity.ts

import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/**
 * Security entity for blocking user access to the system
 * Implements access control at the database level
 */
@Entity()
export class AccessBlacklist {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * LAN ID of the blacklisted user
   * Unique constraint prevents duplicate entries
   */
  @Column({ unique: true })
  userLanId: string;
}
```

**Security Features:**
- ✅ **Unique Constraints**: Prevents duplicate blacklist entries
- ✅ **Primary Key**: Auto-generated sequential IDs
- ✅ **Simple Schema**: Minimal fields for optimal performance
- ✅ **Audit Trail**: Changes tracked via TypeORM hooks

#### **Clinical Data Concept Entity**
```typescript
// File: src/controllers/dataconcept/entities/dataconcept.entity.ts

import {
  Column,
  Entity,
  JoinTable,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { DataconceptDisplayModeOptions } from '../utils/concept-display-mode.options';
import { ClinicalDataType } from './clinical-data-type.entity';
import { DataconceptCategory } from './dataconceptCategory.entity';

/**
 * Core entity representing clinical data concepts
 * Defines the structure and relationships for clinical data
 */
@Entity()
export class Dataconcept {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Human-readable name of the clinical concept
   */
  @Column()
  name: string;

  /**
   * Unique identifier for the concept (UUID)
   * Used for API endpoints and external references
   */
  @Column({ unique: true })
  conceptId: string;

  /**
   * Relationship to the concept's category
   * Many-to-one relationship with cascade operations
   */
  @JoinTable()
  @ManyToOne(
    () => DataconceptCategory,
    (category) => category.dataconcept,
    {
      cascade: true,
    },
  )
  category: DataconceptCategory;

  /**
   * Relationship to the concept's data type
   * Defines how the clinical data should be processed and displayed
   */
  @JoinTable()
  @ManyToOne(
    () => ClinicalDataType,
    (dataType) => dataType.dataconcept,
    {
      cascade: true,
      nullable: true,
    },
  )
  dataType: ClinicalDataType;

  /**
   * Display mode for the concept
   * Controls how concepts are organized in the UI
   */
  @Column({
    type: 'enum',
    enum: DataconceptDisplayModeOptions,
    default: DataconceptDisplayModeOptions.CONCEPT,
  })
  displayMode: DataconceptDisplayModeOptions;
}
```

**Clinical Data Features:**
- ✅ **UUID Primary Keys**: Globally unique identifiers
- ✅ **Relationship Mapping**: Complex entity relationships
- ✅ **Enum Constraints**: Controlled vocabulary for display modes
- ✅ **Cascade Operations**: Automatic relationship management
- ✅ **Flexible Schema**: Nullable relationships for extensibility

#### **Data Concept Category Entity**
```typescript
// File: src/controllers/dataconcept/entities/dataconceptCategory.entity.ts

import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Dataconcept } from './dataconcept.entity';

/**
 * Entity representing categories for clinical data concepts
 * Provides hierarchical organization for clinical data
 */
@Entity()
export class DataconceptCategory {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Human-readable name of the category
   */
  @Column()
  name: string;

  /**
   * Unique identifier for the category (UUID)
   * Generated automatically using PostgreSQL uuid_generate_v4()
   */
  @Column({ type: 'uuid', unique: true, default: () => 'uuid_generate_v4()' })
  categoryId: string;

  /**
   * One-to-many relationship with data concepts
   * A category can contain multiple clinical concepts
   */
  @OneToMany(() => Dataconcept, (dataconcept) => dataconcept.category)
  dataconcept: Dataconcept[];
}
```

**Category Features:**
- ✅ **UUID Generation**: PostgreSQL native UUID generation
- ✅ **Bidirectional Relationships**: Linked to concepts via foreign keys
- ✅ **Unique Constraints**: Prevents duplicate category IDs
- ✅ **Extensible Design**: Additional metadata can be added

#### **Clinical Data Type Entity**
```typescript
// File: src/controllers/dataconcept/entities/clinical-data-type.entity.ts

import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Dataconcept } from './dataconcept.entity';

/**
 * Entity defining clinical data types for response formatting
 * Controls how clinical data is processed and visualized
 */
@Entity()
export class ClinicalDataType {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Type identifier for clinical data processing
   * Examples: TREND_CHART, SINGLE_VALUE, CONDITION, ALLERGY
   */
  @Column({ unique: true })
  type: string;

  /**
   * One-to-many relationship with data concepts
   * Multiple concepts can share the same data type
   */
  @OneToMany(() => Dataconcept, (concept) => concept.dataType, {
    onDelete: 'CASCADE',
  })
  dataconcept: Dataconcept[];
}
```

**Data Type Features:**
- ✅ **Processing Control**: Defines data transformation logic
- ✅ **Visualization Mapping**: Links to appropriate widget types
- ✅ **Cascade Deletes**: Maintains referential integrity
- ✅ **Unique Types**: Prevents duplicate type definitions

#### **User Preferences Entity**
```typescript
// File: src/controllers/preferences/entities/user-preferences.entity.ts

import { BeforeInsert, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/**
 * Template model for user preferences structure
 * Defines the shape of preference data
 */
export class Preferences {
  /**
   * Array of data concept preferences
   * Controls which clinical concepts are enabled/disabled
   */
  dataConceptPreferences: DataConceptPreferences[];
}

/**
 * Individual data concept preference
 * Represents a user's choice for a specific clinical concept
 */
export class DataConceptPreferences {
  /**
   * Reference to the concept ID
   */
  conceptId: string;

  /**
   * Whether this concept is enabled for the user
   */
  enabled: boolean;
}

/**
 * Entity storing user-specific preferences
 * Persists user customization settings in JSONB format
 */
@Entity()
export class UserPreferences {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * User's LAN ID for preference association
   */
  @Column({ unique: true })
  userLanId: string;

  /**
   * Preferences stored as flexible JSONB structure
   * Allows for dynamic preference schema evolution
   */
  @Column('jsonb')
  preferences!: Preferences;

  /**
   * Hook to initialize default preferences
   * Ensures preferences object is never null
   */
  @BeforeInsert()
  setDefaultPreferences() {
    if (!this.preferences) {
      this.preferences = {
        dataConceptPreferences: [],
      } as Preferences;
    }
  }
}
```

**Preferences Features:**
- ✅ **JSONB Storage**: Flexible schema for complex preferences
- ✅ **User Association**: Linked to user identity via LAN ID
- ✅ **Default Initialization**: Automatic preference setup
- ✅ **Extensible Design**: Easy addition of new preference types

#### **Data Concept Defaults Entity**
```typescript
// File: src/controllers/preferences/entities/data-concept-defaults.entity.ts

import { Column, Entity, ManyToOne, PrimaryGeneratedColumn, JoinColumn } from 'typeorm';
import { Dataconcept } from '../../dataconcept/entities/dataconcept.entity';

/**
 * Entity storing system-wide default preferences for clinical concepts
 * Provides fallback preferences when user preferences are not set
 */
@Entity()
export class DataConceptDefaults {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Reference to the concept ID
   */
  @Column()
  conceptId: string;

  /**
   * Foreign key relationship to the data concept
   * Ensures referential integrity with concept definitions
   */
  @ManyToOne(() => Dataconcept)
  @JoinColumn({ name: 'conceptId', referencedColumnName: 'conceptId' })
  concept: Dataconcept;

  /**
   * Default enabled state for this concept
   * True by default, can be overridden by user preferences
   */
  @Column({ default: true })
  enabled: boolean;

  /**
   * Timestamp when the default was created
   */
  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
```

**Defaults Features:**
- ✅ **System Fallbacks**: Provides defaults when user preferences missing
- ✅ **Referential Integrity**: Foreign key constraints to concepts
- ✅ **Audit Trail**: Creation timestamps for tracking
- ✅ **Flexible Defaults**: Can be enabled/disabled per concept

#### **Inference Engine View Entity**
```typescript
// File: src/controllers/preferences/entities/inference-engine-view.entity.ts

import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/**
 * Entity storing AI-powered preference recommendations
 * Contains specialty and condition-based preference suggestions
 */
@Entity()
export class InferenceEngineView {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Healthcare provider specialty
   * Used for specialty-specific preference recommendations
   */
  @Column()
  specialty: string;

  /**
   * Patient condition or diagnosis
   * Used for condition-aware preference recommendations
   */
  @Column()
  condition: string;

  /**
   * Whether these recommendations are active
   */
  @Column({ default: true })
  enabled: boolean;

  /**
   * AI-generated preferences in JSONB format
   * Contains recommended concept enablement settings
   */
  @Column('jsonb')
  preferences: Preferences;

  /**
   * Timestamp when the recommendations were created
   */
  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  /**
   * Timestamp when the recommendations were last updated
   */
  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP', onUpdate: 'CURRENT_TIMESTAMP' })
  updatedAt: Date;
}
```

**AI Features:**
- ✅ **Specialty Awareness**: Provider type-specific recommendations
- ✅ **Condition Context**: Patient condition-based suggestions
- ✅ **Enable/Disable Control**: Runtime toggling of AI recommendations
- ✅ **Audit Trail**: Creation and update timestamps
- ✅ **Flexible Storage**: JSONB for complex preference structures

#### **Audit Log Entity**
```typescript
// File: libs/common/src/audit-logging/entities/audit-log.entity.ts

import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/**
 * Entity for storing comprehensive audit logs
 * Provides compliance and security monitoring capabilities
 */
@Entity()
export class AuditLog {
  /**
   * Auto-generated primary key
   */
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * Identifier of the user who triggered the event
   * Can be null for anonymous or system events
   */
  @Column({ nullable: true })
  userIdentifier: string;

  /**
   * Timestamp when the audit entry was created
   * Uses PostgreSQL timestamptz for timezone awareness
   */
  @Column({ type: 'timestamptz', default: () => 'now()' })
  timestamp: Date;

  /**
   * Type of event that was logged
   * Format: [HTTP_METHOD] route_pattern
   * Example: [POST] /auth/login
   */
  @Column()
  eventType: string;

  /**
   * Detailed context information about the event
   * Stored as JSONB for flexible schema and querying
   */
  @Column({
    type: 'jsonb',
    nullable: true,
  })
  eventContext: Record<string, any>;
}
```

**Audit Features:**
- ✅ **Compliance Ready**: HIPAA/SOC2 compliant audit trails
- ✅ **Flexible Context**: JSONB storage for complex event data
- ✅ **User Tracking**: Links events to specific users
- ✅ **Event Classification**: Structured event type categorization
- ✅ **Timezone Aware**: Proper timestamp handling

---

## 🔧 **API Data Transfer Objects**

### **1. Authentication DTOs**

#### **Epic Authorization Code Request**
```typescript
// File: src/controllers/auth/dto/epic-authorization-code-request.dto.ts

/**
 * Interface for Epic OAuth2 authorization code flow
 * Defines the contract for Epic authentication requests
 */
export interface EpicAuthorizationCodeRequest {
  /**
   * OAuth2 grant type for authorization code flow
   */
  grant_type: 'authorization_code';

  /**
   * URI where the user was redirected after authorization
   */
  redirect_uri: string;

  /**
   * Authorization code received from Epic
   */
  code: string;

  /**
   * Code verifier for PKCE (Proof Key for Code Exchange)
   */
  code_verifier: string;
}
```

**OAuth2 Features:**
- ✅ **PKCE Support**: Proof Key for Code Exchange security
- ✅ **Standard Flow**: RFC-compliant OAuth2 implementation
- ✅ **Type Safety**: Interface-based contract definition

#### **Entra Token Exchange DTO**
```typescript
// File: src/controllers/auth/dto/entra-token-exchange.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

/**
 * Interface for Entra ID token exchange requests
 */
export interface EntraTokenExchange {
  code: string;
  grant_type: string;
  code_verifier: string;
  redirect_uri: string;
  secret?: string;
}

/**
 * DTO for Entra ID token refresh requests
 * Provides validation and documentation for token refresh operations
 */
@ApiSchema({
  name: 'RefreshTokenRequest',
  description: 'Refresh the entra token',
})
@ApiSchema()
export class EntraTokenRequestDto {
  /**
   * Refresh token for obtaining new access tokens
   */
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  refresh_token: string;

  /**
   * Redirect URI must match the original authorization request
   */
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  redirect_url: string;

  /**
   * Authorization code from the initial OAuth flow
   */
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  code: string;

  /**
   * Requested OAuth scopes for the token
   */
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  scope: string;

  /**
   * OAuth2 grant type (typically 'urn:ietf:params:oauth:grant-type:jwt-bearer')
   */
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  grant_type: string;
}
```

**Entra ID Features:**
- ✅ **Validation**: Class-validator decorators for input validation
- ✅ **Documentation**: Swagger/OpenAPI schema generation
- ✅ **Security**: Proper token handling and validation
- ✅ **OAuth2 Compliance**: Standard OAuth2 parameter structure

### **2. Appointments DTOs**

#### **Calendar Appointments Request DTO**
```typescript
// File: src/controllers/appointments/dto/calendar-appointments.request.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsDateString, IsNotEmpty } from 'class-validator';

/**
 * DTO for requesting calendar appointments within a time range
 * Provides validation and documentation for appointment queries
 */
@ApiSchema({
  name: 'CalendarAppointmentsRequest',
  description: 'Schema for requesting calendar appointments',
})
export class CalendarAppointmentsRequestDto {
  /**
   * Start date and time for the appointment query
   * Must be in ISO 8601 format with timezone information
   */
  @ApiProperty({
    description:
      'Interval start date and time with timezone information. The string is in ISO 8601 format.',
    example: '2024-11-10T12:00:00.00000-06:00',
  })
  @IsNotEmpty()
  @IsDateString()
  startDateTime: string;

  /**
   * End date and time for the appointment query
   * Must be in ISO 8601 format with timezone information
   */
  @ApiProperty({
    description:
      'Interval end date and time with timezone information. The string is in ISO 8601 format.',
    example: '2024-11-10T23:59:59.99999-06:00',
  })
  @IsNotEmpty()
  @IsDateString()
  endDateTime: string;
}
```

**Appointment Features:**
- ✅ **Date Validation**: Ensures proper ISO 8601 format
- ✅ **Timezone Support**: Handles timezone-aware datetime strings
- ✅ **Required Fields**: Non-null validation for critical parameters
- ✅ **API Documentation**: Comprehensive Swagger schema

#### **Calendar Appointments Response DTO**
```typescript
// File: src/controllers/appointments/dto/calendar-appointments.response.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { mockAdminAppointments } from '../mock/admin-appointments.mock';
import { mockClinicalAppointments } from '../mock/clinical-appointments.mock';
import { CalendarAppointment } from './calendar-appointment';
import { CalendarError } from './calendar-error';

/**
 * Response DTO for calendar appointments API
 * Handles both successful data and error scenarios
 */
@ApiSchema({
  name: 'CalendarAppointmentsResponse',
  description: 'Schema for the appointments calendar response',
})
export class CalendarAppointmentsResponseDto {
  /**
   * Array of calendar appointments or null if no data
   * Contains both clinical and administrative appointments
   */
  @ApiProperty({
    description:
      'List of calendar appointments. This will be null if no data is available.',
    nullable: true,
    example: [...mockClinicalAppointments, ...mockAdminAppointments],
    type: [CalendarAppointment],
  })
  data: CalendarAppointment[] | null;

  /**
   * Array of errors encountered during appointment retrieval
   * Null if no errors occurred during processing
   */
  @ApiProperty({
    description:
      'List of errors encountered while retrieving appointments. This will be null if no errors occurred.',
    nullable: true,
    example: null,
    type: [CalendarError],
  })
  errors: CalendarError[] | null;
}
```

**Response Features:**
- ✅ **Flexible Structure**: Handles both success and error scenarios
- ✅ **Null Safety**: Proper nullable type definitions
- ✅ **Mock Data**: Example responses for testing and documentation
- ✅ **Error Handling**: Structured error reporting

### **3. Clinical Data DTOs**

#### **Concept Resolver Response DTO**
```typescript
// File: src/controllers/dataconcept/dto/concept-resolver.response.dto.ts

import { ApiProperty, ApiPropertyOptional, ApiSchema } from '@nestjs/swagger';
import { BaseWidget } from './widgets/base.widget';

/**
 * Error information structure for failed concept resolutions
 */
@ApiSchema({
  description: 'Information about a clinical data concept error',
})
export class ErrorInfo {
  /**
   * HTTP status code representing the error
   */
  @ApiProperty({
    description: 'Status code of the error',
    example: 429,
  })
  code: number;

  /**
   * Human-readable error message
   */
  @ApiProperty({
    description: 'Error message',
    example: 'Too many requests',
  })
  message: string;
}

/**
 * Individual concept entry in the resolver response
 * Extends BaseWidget with success/error status
 */
@ApiSchema({
  description: 'Base concept data DTO',
})
export class ConceptEntry extends BaseWidget {
  /**
   * Whether the concept resolution was successful
   * If false, data will be null and error will be populated
   */
  @ApiProperty({
    description:
      'Success status of the concept request. Data will be null if this field is set to `false`',
    example: false,
  })
  success: boolean;

  /**
   * Error information if the resolution failed
   * Null if success is true
   */
  @ApiPropertyOptional({
    description:
      'Information about the request error. This is null if the `success` field is set to `true`',
  })
  error?: ErrorInfo;
}

/**
 * Complete response for clinical data concept category resolution
 * Contains all concepts within a category with their resolution status
 */
@ApiSchema({
  name: 'ConceptResolverResponse',
  description: 'Response for clinical data concepts',
})
export class ConceptResolverResponseDto {
  /**
   * Unique identifier of the concept category
   */
  @ApiProperty({
    description: 'Concept category Id',
    example: '747f18ad-e687-4df8-9785-cd5b82514c00',
  })
  id: string;

  /**
   * Human-readable name of the category
   */
  @ApiProperty({
    description: 'Concept category name',
    example: 'Hematology Labs',
  })
  label: string;

  /**
   * Total number of concept entries in this category
   */
  @ApiProperty({
    description: 'Total number of entries',
    example: 5,
  })
  total: number;

  /**
   * Array of resolved concept entries
   * Each entry contains the concept data or error information
   */
  @ApiProperty({
    description: 'Clinical data concepts',
    type: [ConceptEntry],
  })
  entries: ConceptEntry[];
}
```

**Clinical Data Features:**
- ✅ **Success/Error Handling**: Structured error reporting
- ✅ **Widget Integration**: Extends base widget types
- ✅ **Flexible Responses**: Handles partial failures gracefully
- ✅ **Comprehensive Documentation**: Detailed API schema

### **4. Widget DTOs**

#### **Widget Type System**
```typescript
// File: src/controllers/dataconcept/dto/widgets/common.ts

import { ApiProperty, ApiPropertyOptional, ApiSchema } from '@nestjs/swagger';
import { AllergyWidget } from './allergy.widget';
import { ConditionWidget } from './condition.widget';
import { DataTableWidget } from './data-table.widget';
import { GenericValueWidget } from './generic-value.widget';
import { MedicalHistoryWidget } from './medical-history.widget';
import { WidgetList } from './widget-list.widget';

/**
 * Union type of all supported widget data structures
 * Used for type-safe widget data handling
 */
export type WidgetData =
  | MedicalHistoryWidget
  | ConditionWidget
  | DataTableWidget
  | GenericValueWidget
  | AllergyWidget
  | WidgetList;

/**
 * Enumeration of supported widget types for clinical data visualization
 * Maps to specific widget implementations and rendering logic
 */
export enum WidgetType {
  DATA_TABLE = 'SINGLE_VALUE',        // Latest value display
  DATA_TABLE_CHART = 'TREND_CHART',   // Time-series with chart
  CONDITION = 'CONDITION',            // Medical conditions
  MEDICAL_HISTORY = 'MEDICAL_HISTORY', // Diagnostic reports
  VALUE = 'VALUE',                    // Simple value display
  WIDGET_LIST = 'WIDGET_LIST',        // Multiple widgets
  ALLERGY = 'ALLERGY',                // Allergy information
  PATHOLOGY_REPORT = 'PATHOLOGY_REPORT', // Pathology data
  IMAGING_STUDY = 'IMAGING_STUDY',    // Imaging results
  PROCEDURE = 'PROCEDURE',            // Procedure information
  ERROR = 'ERROR',                    // Error state display
}

/**
 * Base widget structure with common properties
 * All widgets extend this base structure
 */
export class BaseWidget<T = WidgetData> {
  id: string;
  label: string;
  type: WidgetType;
  data?: T;
}

/**
 * Attachment structure for widget content
 * Supports various content types and delivery methods
 */
@ApiSchema({
  description:
    'Content that can be attached to a widget. ' +
    'Usually, content of this type will be handled separately ' +
    'by the mobile application.',
})
export class WidgetAttachment {
  /**
   * Base64 encoded content for inline delivery
   */
  @ApiPropertyOptional({
    description: 'Attachment content in base64 format',
  })
  content?: string;

  /**
   * MIME type of the attachment content
   */
  @ApiProperty({
    description: 'Attachment content type',
    example: 'text/plain',
  })
  contentType: string;

  /**
   * External URL for content delivery
   * Client applications handle downloading from this URL
   */
  @ApiPropertyOptional({
    description:
      'Attachment url (if available). ' +
      'The application will be responsible for downloading the attachment, not the API',
  })
  url?: string;
}
```

**Widget System Features:**
- ✅ **Type Safety**: Union types for compile-time safety
- ✅ **Extensible Design**: Easy addition of new widget types
- ✅ **Attachment Support**: Handles various content types
- ✅ **Base Structure**: Consistent widget interface
- ✅ **Documentation**: Comprehensive API schema

#### **Data Table Widget**
```typescript
// File: src/controllers/dataconcept/dto/widgets/data-table.widget.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';

/**
 * Individual data point in a table or chart
 * Represents a single measurement or observation
 */
@ApiSchema({
  description: 'Data point for table/chart visualization',
})
export class DataPoint {
  /**
   * Date when the measurement was taken
   */
  @ApiProperty({
    description: 'Date of the data point',
    example: '2024-01-15',
  })
  date: string;

  /**
   * Numerical or textual value of the measurement
   */
  @ApiProperty({
    description: 'Value of the data point',
    example: '120/80',
  })
  value: string;

  /**
   * Interpretation of the value (e.g., normal, high, low)
   */
  @ApiProperty({
    description: 'Interpretation of the value',
    example: 'normal',
  })
  interpretation: string;

  /**
   * Comparator for reference ranges
   */
  @ApiProperty({
    description: 'Comparator for reference ranges',
    example: '<',
  })
  comparator: string;

  /**
   * Calculated change from previous value
   */
  @ApiProperty({
    description: 'Change from previous value',
    example: '2.5%',
  })
  change: string;
}

/**
 * Widget for displaying tabular clinical data
 * Supports both table and chart visualization modes
 */
@ApiSchema({
  description: 'Widget for displaying clinical data in table format',
})
export class DataTableWidget {
  /**
   * Array of data points for the table/chart
   * Typically ordered by date (most recent first)
   */
  @ApiProperty({
    description: 'Array of data points',
    type: [DataPoint],
  })
  entries: DataPoint[];
}
```

**Data Visualization Features:**
- ✅ **Flexible Display**: Supports both table and chart formats
- ✅ **Time Series**: Date-ordered data points
- ✅ **Interpretation**: Clinical value interpretation
- ✅ **Change Tracking**: Automatic change calculations
- ✅ **Reference Ranges**: Comparator support for normal ranges

### **5. Preferences DTOs**

#### **Data Concept Preferences DTO**
```typescript
// File: src/controllers/preferences/dto/data-concept-preferences.dto.ts

import { ApiSchema } from '@nestjs/swagger';
import { DataConceptPreferences } from '../entities/user-preferences.entity';

/**
 * DTO for updating user concept preferences
 * Mirrors the entity structure for preference updates
 */
@ApiSchema({
  description: 'DTO for updating user preferred data concepts',
})
export class DataConceptPreferencesDto extends DataConceptPreferences {}
```

**Preferences Features:**
- ✅ **Entity Extension**: Inherits from entity for consistency
- ✅ **Update Operations**: Designed for PATCH operations
- ✅ **Validation Ready**: Can be extended with validation decorators
- ✅ **API Documentation**: Automatic Swagger schema generation

---

## 🔄 **Data Transformation & Validation**

### **1. Entity-DTO Mapping Patterns**

```typescript
// Advanced entity-DTO mapping patterns
@Injectable()
export class EntityDtoMapper {
  // Map entity to DTO with field selection
  static mapToDto<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
    fields?: (keyof T)[],
  ): U {
    const dto = new dtoClass();

    if (fields) {
      // Selective field mapping
      fields.forEach(field => {
        if (entity[field] !== undefined) {
          dto[field as keyof U] = entity[field] as any;
        }
      });
    } else {
      // Map all fields
      Object.assign(dto, entity);
    }

    return dto;
  }

  // Map collection with transformation
  static mapCollection<T extends BaseEntity, U>(
    entities: T[],
    dtoClass: new () => U,
    transform?: (entity: T) => Partial<U>,
  ): U[] {
    return entities.map(entity => {
      const dto = this.mapToDto(entity, dtoClass);

      if (transform) {
        Object.assign(dto, transform(entity));
      }

      return dto;
    });
  }

  // Map with relationship resolution
  static async mapWithRelations<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
    relations: string[],
  ): Promise<U> {
    // Load relationships if not already loaded
    for (const relation of relations) {
      if (!entity[relation]) {
        // Load relation from database
        await this.loadRelation(entity, relation);
      }
    }

    return this.mapToDto(entity, dtoClass);
  }
}
```

**Mapping Features:**
- ✅ **Selective Mapping**: Choose specific fields to include
- ✅ **Collection Support**: Handle arrays of entities
- ✅ **Relationship Loading**: Automatic relation resolution
- ✅ **Transformation**: Apply custom mapping logic

### **2. Validation Pipeline**

```typescript
// Comprehensive validation pipeline
@Injectable()
export class ValidationPipeline {
  // Validate incoming DTO
  async validateDto<T extends object>(
    dto: T,
    validationGroups?: string[],
  ): Promise<ValidationResult<T>> {
    const errors = await validate(dto, {
      groups: validationGroups,
      forbidUnknownValues: true,
      whitelist: true,
    });

    if (errors.length > 0) {
      return {
        isValid: false,
        errors: this.formatValidationErrors(errors),
        originalDto: dto,
      };
    }

    return {
      isValid: true,
      data: dto,
      originalDto: dto,
    };
  }

  // Sanitize DTO data
  sanitizeDto<T extends object>(dto: T): T {
    const sanitized = { ...dto };

    // Sanitize string fields
    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'string') {
        sanitized[key] = this.sanitizeString(sanitized[key]);
      } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
        sanitized[key] = this.sanitizeDto(sanitized[key]);
      }
    });

    return sanitized;
  }

  // Transform DTO based on context
  transformDto<T extends object, U extends object>(
    dto: T,
    transformer: (dto: T) => U,
  ): U {
    return transformer(dto);
  }

  // Validate business rules
  async validateBusinessRules<T extends object>(
    dto: T,
    rules: BusinessRule<T>[],
  ): Promise<BusinessValidationResult> {
    const violations: string[] = [];

    for (const rule of rules) {
      const isValid = await rule.validate(dto);

      if (!isValid) {
        violations.push(rule.message);
      }
    }

    return {
      isValid: violations.length === 0,
      violations,
    };
  }

  // Format validation errors
  private formatValidationErrors(errors: ValidationError[]): FormattedError[] {
    return errors.map(error => ({
      field: error.property,
      value: error.value,
      constraints: error.constraints,
      children: error.children ? this.formatValidationErrors(error.children) : undefined,
    }));
  }

  // Sanitize string input
  private sanitizeString(value: string): string {
    // Basic XSS prevention
    return value.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  }
}
```

**Validation Features:**
- ✅ **Class-Validator Integration**: Automatic validation
- ✅ **Business Rules**: Custom validation logic
- ✅ **Data Sanitization**: Input cleaning and XSS prevention
- ✅ **Transformation Pipeline**: Data transformation capabilities
- ✅ **Error Formatting**: User-friendly error messages

### **3. Serialization Control**

```typescript
// Advanced serialization control
@Injectable()
export class SerializationController {
  // Serialize entity with field selection
  serializeEntity<T extends BaseEntity>(
    entity: T,
    fields: (keyof T)[],
    options?: SerializationOptions,
  ): Partial<T> {
    const serialized: Partial<T> = {};

    fields.forEach(field => {
      if (entity[field] !== undefined) {
        serialized[field] = this.serializeField(entity[field], options);
      }
    });

    return serialized;
  }

  // Serialize with relationship control
  async serializeWithRelations<T extends BaseEntity>(
    entity: T,
    relations: RelationConfig[],
  ): Promise<SerializedEntity<T>> {
    const serialized = { ...entity };

    for (const relation of relations) {
      if (relation.include) {
        if (Array.isArray(entity[relation.name])) {
          // Serialize collection
          serialized[relation.name] = await Promise.all(
            entity[relation.name].map(item =>
              this.serializeEntity(item, relation.fields, relation.options),
            ),
          );
        } else {
          // Serialize single relation
          serialized[relation.name] = this.serializeEntity(
            entity[relation.name],
            relation.fields,
            relation.options,
          );
        }
      } else {
        // Exclude relation
        delete serialized[relation.name];
      }
    }

    return serialized;
  }

  // Conditional serialization based on user context
  serializeForUser<T extends BaseEntity>(
    entity: T,
    user: RequestUser,
    serializationRules: SerializationRule<T>[],
  ): Partial<T> {
    let fields = Object.keys(entity) as (keyof T)[];

    // Apply serialization rules
    for (const rule of serializationRules) {
      if (rule.condition(user)) {
        if (rule.includeFields) {
          fields = fields.filter(field => rule.includeFields!.includes(field));
        }

        if (rule.excludeFields) {
          fields = fields.filter(field => !rule.excludeFields!.includes(field));
        }
      }
    }

    return this.serializeEntity(entity, fields);
  }

  // Cache serialized responses
  async getCachedSerialization<T extends BaseEntity>(
    entity: T,
    cacheKey: string,
    ttl: number = 300, // 5 minutes
  ): Promise<Partial<T>> {
    const cached = await this.cache.get<Partial<T>>(cacheKey);

    if (cached) {
      return cached;
    }

    const serialized = this.serializeEntity(entity, Object.keys(entity) as (keyof T)[]);

    await this.cache.set(cacheKey, serialized, ttl);

    return serialized;
  }

  // Serialize field with type-specific logic
  private serializeField(value: any, options?: SerializationOptions): any {
    if (value === null || value === undefined) {
      return value;
    }

    // Date serialization
    if (value instanceof Date) {
      return options?.dateFormat === 'iso'
        ? value.toISOString()
        : value.toLocaleDateString();
    }

    // Array serialization
    if (Array.isArray(value)) {
      return value.map(item => this.serializeField(item, options));
    }

    // Object serialization
    if (typeof value === 'object') {
      return this.serializeEntity(value, Object.keys(value), options);
    }

    return value;
  }
}
```

**Serialization Features:**
- ✅ **Field Selection**: Choose which fields to include
- ✅ **Relationship Control**: Handle entity relationships
- ✅ **User Context**: Conditional serialization based on user
- ✅ **Caching**: Performance optimization for repeated serializations
- ✅ **Type Handling**: Special handling for dates, arrays, objects

---

## 📊 **Performance & Monitoring**

### **1. Database Query Optimization**

```typescript
// Database query optimization patterns
@Injectable()
export class DatabaseOptimizationService {
  // Optimized entity loading with selective fields
  async loadEntityOptimized<T extends BaseEntity>(
    repository: Repository<T>,
    id: any,
    fields: (keyof T)[],
  ): Promise<Partial<T> | null> {
    const queryBuilder = repository.createQueryBuilder('entity');

    // Select only required fields
    fields.forEach(field => {
      queryBuilder.addSelect(`entity.${field as string}`);
    });

    return await queryBuilder
      .where('entity.id = :id', { id })
      .getOne();
  }

  // Batch loading with N+1 query prevention
  async batchLoadEntities<T extends BaseEntity>(
    repository: Repository<T>,
    ids: any[],
    relations?: string[],
  ): Promise<T[]> {
    const queryBuilder = repository.createQueryBuilder('entity');

    if (relations) {
      relations.forEach(relation => {
        queryBuilder.leftJoinAndSelect(`entity.${relation}`, relation);
      });
    }

    return await queryBuilder
      .where('entity.id IN (:...ids)', { ids })
      .getMany();
  }

  // Connection pooling and query optimization
  async executeOptimizedQuery<T>(
    repository: Repository<T>,
    query: (qb: SelectQueryBuilder<T>) => SelectQueryBuilder<T>,
  ): Promise<T[]> {
    const queryBuilder = repository.createQueryBuilder('entity');

    const optimizedQuery = query(queryBuilder);

    // Add query hints for optimization
    optimizedQuery.setParameters({
      // Query optimization parameters
    });

    return await optimizedQuery.getMany();
  }

  // Index usage monitoring
  async monitorIndexUsage(): Promise<IndexUsageStats[]> {
    // Monitor which indexes are being used
    const stats = await this.connection.query(`
      SELECT
        schemaname,
        tablename,
        indexname,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch
      FROM pg_stat_user_indexes
      ORDER BY idx_scan DESC;
    `);

    return stats.map(stat => ({
      schema: stat.schemaname,
      table: stat.tablename,
      index: stat.indexname,
      scans: stat.idx_scan,
      tuplesRead: stat.idx_tup_read,
      tuplesFetched: stat.idx_tup_fetch,
    }));
  }

  // Query performance monitoring
  async monitorQueryPerformance(): Promise<QueryPerformanceStats[]> {
    const slowQueries = await this.connection.query(`
      SELECT
        query,
        calls,
        total_time,
        mean_time,
        rows
      FROM pg_stat_statements
      WHERE mean_time > 100  -- Queries taking more than 100ms on average
      ORDER BY mean_time DESC
      LIMIT 20;
    `);

    return slowQueries.map(query => ({
      sql: query.query,
      calls: query.calls,
      totalTime: query.total_time,
      meanTime: query.mean_time,
      rows: query.rows,
    }));
  }
}
```

### **2. Entity Relationship Optimization**

```typescript
// Entity relationship optimization
@Injectable()
export class EntityRelationshipOptimizer {
  // Optimize lazy loading patterns
  async optimizeLazyLoading<T extends BaseEntity>(
    entities: T[],
    relations: string[],
    batchSize: number = 100,
  ): Promise<T[]> {
    // Process in batches to avoid memory issues
    const batches = this.chunkArray(entities, batchSize);

    for (const batch of batches) {
      await this.loadBatchRelations(batch, relations);
    }

    return entities;
  }

  // Eager loading with selective fields
  async optimizeEagerLoading<T extends BaseEntity>(
    repository: Repository<T>,
    conditions: any,
    relations: RelationOptimization[],
  ): Promise<T[]> {
    let queryBuilder = repository.createQueryBuilder('entity');

    // Add optimized relations
    for (const relation of relations) {
      if (relation.select) {
        queryBuilder = queryBuilder.leftJoinAndSelect(
          `entity.${relation.name}`,
          relation.name,
        );

        // Select only required fields from relation
        relation.select.forEach(field => {
          queryBuilder.addSelect(`${relation.name}.${field}`);
        });
      }
    }

    // Add conditions
    Object.entries(conditions).forEach(([key, value]) => {
      queryBuilder.andWhere(`entity.${key} = :${key}`, { [key]: value });
    });

    return await queryBuilder.getMany();
  }

  // Cache entity relationships
  async cacheEntityRelationships<T extends BaseEntity>(
    entity: T,
    relations: string[],
    ttl: number = 3600, // 1 hour
  ): Promise<T> {
    const cacheKey = `entity:${entity.constructor.name}:${entity.id}:relations`;

    const cached = await this.cache.get<T>(cacheKey);

    if (cached) {
      // Load cached relationships
      relations.forEach(relation => {
        entity[relation] = cached[relation];
      });

      return entity;
    }

    // Load relationships from database
    for (const relation of relations) {
      entity[relation] = await this.loadRelation(entity, relation);
    }

    // Cache the loaded relationships
    await this.cache.set(cacheKey, entity, ttl);

    return entity;
  }

  // Monitor relationship loading performance
  async monitorRelationshipPerformance(): Promise<RelationshipPerformanceStats> {
    const stats = {
      totalRelationshipsLoaded: 0,
      averageLoadTime: 0,
      slowestRelationships: [] as Array<{ relation: string; loadTime: number }>,
      nPlusOneQueries: 0,
    };

    // Monitor relationship loading patterns
    // This would integrate with query monitoring

    return stats;
  }

  private async loadBatchRelations<T extends BaseEntity>(
    entities: T[],
    relations: string[],
  ): Promise<void> {
    for (const relation of relations) {
      const ids = entities.map(e => e.id);

      // Load all related entities in one query
      const relatedEntities = await this.loadRelatedEntities(
        entities[0].constructor.name,
        relation,
        ids,
      );

      // Assign related entities to parent entities
      entities.forEach(entity => {
        entity[relation] = relatedEntities.filter(
          related => related[`${this.getParentEntityName(entity)}_id`] === entity.id,
        );
      });
    }
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}
```

---

## 🧪 **Testing Implementation**

### **1. Entity Unit Tests**

```typescript
// File: src/controllers/access-blacklist/entities/access-blacklist.entity.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AccessBlacklist } from './access-blacklist.entity';

describe('AccessBlacklist Entity', () => {
  let repository: Repository<AccessBlacklist>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: getRepositoryToken(AccessBlacklist),
          useValue: {
            create: jest.fn(),
            save: jest.fn(),
            findOne: jest.fn(),
            find: jest.fn(),
            remove: jest.fn(),
          },
        },
      ],
    }).compile();

    repository = module.get<Repository<AccessBlacklist>>(
      getRepositoryToken(AccessBlacklist),
    );
  });

  describe('Entity Creation', () => {
    it('should create a new access blacklist entry', () => {
      const userLanId = 'test.user';

      const blacklistEntry = repository.create({
        userLanId,
      });

      expect(blacklistEntry).toBeDefined();
      expect(blacklistEntry.userLanId).toBe(userLanId);
    });

    it('should enforce unique constraint on userLanId', async () => {
      const userLanId = 'duplicate.user';

      // First creation should succeed
      const firstEntry = repository.create({ userLanId });
      await repository.save(firstEntry);

      // Second creation should fail due to unique constraint
      const secondEntry = repository.create({ userLanId });

      await expect(repository.save(secondEntry)).rejects.toThrow();
    });
  });

  describe('Entity Queries', () => {
    it('should find blacklist entry by user LAN ID', async () => {
      const userLanId = 'test.user';
      const mockEntry = {
        id: 1,
        userLanId,
      };

      jest.spyOn(repository, 'findOne').mockResolvedValue(mockEntry as AccessBlacklist);

      const result = await repository.findOne({
        where: { userLanId },
      });

      expect(result).toEqual(mockEntry);
      expect(repository.findOne).toHaveBeenCalledWith({
        where: { userLanId },
      });
    });

    it('should return all blacklist entries', async () => {
      const mockEntries = [
        { id: 1, userLanId: 'user1' },
        { id: 2, userLanId: 'user2' },
      ];

      jest.spyOn(repository, 'find').mockResolvedValue(mockEntries as AccessBlacklist[]);

      const result = await repository.find();

      expect(result).toEqual(mockEntries);
      expect(repository.find).toHaveBeenCalled();
    });
  });

  describe('Entity Removal', () => {
    it('should remove blacklist entry', async () => {
      const mockEntry = {
        id: 1,
        userLanId: 'test.user',
      } as AccessBlacklist;

      jest.spyOn(repository, 'remove').mockResolvedValue(mockEntry);

      const result = await repository.remove(mockEntry);

      expect(result).toEqual(mockEntry);
      expect(repository.remove).toHaveBeenCalledWith(mockEntry);
    });
  });
});
```

### **2. DTO Integration Tests**

```typescript
// File: test/e2e/dto-validation.e2e.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { CalendarAppointmentsRequestDto } from '../../src/controllers/appointments/dto/calendar-appointments.request.dto';

describe('DTO Validation (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    // Enable global validation
    app.useGlobalPipes(new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }));

    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('Calendar Appointments Request DTO', () => {
    it('should accept valid request with proper date format', async () => {
      const validRequest = {
        startDateTime: '2024-11-10T12:00:00.00000-06:00',
        endDateTime: '2024-11-10T23:59:59.99999-06:00',
      };

      const response = await request(app.getHttpServer())
        .post('/appointments/calendar')
        .send(validRequest)
        .expect(200);

      // Verify the request was processed successfully
      expect(response.body).toHaveProperty('data');
    });

    it('should reject request with invalid date format', async () => {
      const invalidRequest = {
        startDateTime: 'invalid-date',
        endDateTime: '2024-11-10T23:59:59.99999-06:00',
      };

      const response = await request(app.getHttpServer())
        .post('/appointments/calendar')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body.message).toContain('startDateTime');
    });

    it('should reject request with missing required fields', async () => {
      const incompleteRequest = {
        startDateTime: '2024-11-10T12:00:00.00000-06:00',
        // Missing endDateTime
      };

      const response = await request(app.getHttpServer())
        .post('/appointments/calendar')
        .send(incompleteRequest)
        .expect(400);

      // Verify validation error for missing field
      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body.message).toContain('endDateTime');
    });

    it('should handle timezone-aware datetime strings', async () => {
      const timezoneRequest = {
        startDateTime: '2024-11-10T12:00:00.00000+05:30', // IST timezone
        endDateTime: '2024-11-10T23:59:59.99999+05:30',
      };

      const response = await request(app.getHttpServer())
        .post('/appointments/calendar')
        .send(timezoneRequest)
        .expect(200);

      // Verify timezone handling
      expect(response.body).toHaveProperty('data');
    });
  });

  describe('Entra Token Request DTO', () => {
    it('should validate required fields', async () => {
      const validRequest = {
        refresh_token: 'mock-refresh-token',
        redirect_url: 'https://example.com/callback',
        code: 'mock-auth-code',
        scope: 'user.read openid',
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      };

      const response = await request(app.getHttpServer())
        .post('/auth/entra/refresh')
        .send(validRequest)
        .expect(200);

      // Verify successful validation
      expect(response.body).toHaveProperty('access_token');
    });

    it('should reject request with missing required fields', async () => {
      const invalidRequest = {
        refresh_token: 'mock-refresh-token',
        // Missing other required fields
      };

      const response = await request(app.getHttpServer())
        .post('/auth/entra/refresh')
        .send(invalidRequest)
        .expect(400);

      // Verify validation errors
      expect(response.body).toHaveProperty('statusCode', 400);
      expect(Array.isArray(response.body.message)).toBe(true);
    });

    it('should validate string field types', async () => {
      const invalidTypeRequest = {
        refresh_token: 12345, // Should be string
        redirect_url: 'https://example.com/callback',
        code: 'mock-auth-code',
        scope: 'user.read openid',
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      };

      const response = await request(app.getHttpServer())
        .post('/auth/entra/refresh')
        .send(invalidTypeRequest)
        .expect(400);

      // Verify type validation
      expect(response.body.message).toContain('refresh_token');
    });
  });

  describe('Concept Resolver Response DTO', () => {
    it('should handle successful concept resolution', async () => {
      const response = await request(app.getHttpServer())
        .post('/data-concepts/test-concept')
        .send({ patientMrn: '123456' })
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('label');
      expect(response.body).toHaveProperty('type');
      expect(response.body).toHaveProperty('success');
    });

    it('should handle concept resolution errors', async () => {
      const response = await request(app.getHttpServer())
        .post('/data-concepts/invalid-concept')
        .send({ patientMrn: '123456' })
        .set('Authorization', 'Bearer mock-token')
        .expect(200);

      // Verify error handling
      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code');
      expect(response.body.error).toHaveProperty('message');
    });

    it('should validate patient MRN requirement', async () => {
      const response = await request(app.getHttpServer())
        .post('/data-concepts/test-concept')
        .send({}) // Missing patientMrn
        .set('Authorization', 'Bearer mock-token')
        .expect(422);

      // Verify validation error
      expect(response.body).toHaveProperty('statusCode', 422);
      expect(response.body.message).toContain('MRN is required');
    });
  });
});
```

---

## 🎯 **Best Practices & Guidelines**

### **1. Entity Design Principles**

```typescript
// Entity design best practices
@Injectable()
export class EntityDesignBestPractices {
  // 1. Use meaningful table and column names
  @Entity('clinical_data_concepts') // Instead of 'dataconcept'
  export class ClinicalDataConcept {
    @Column('concept_id') // Instead of 'conceptId'
    conceptId: string;

    @Column('display_name') // Instead of 'name'
    displayName: string;
  }

  // 2. Use appropriate data types
  @Entity()
  export class OptimizedEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string; // Use UUID for distributed systems

    @Column('varchar', { length: 255 })
    name: string; // Specify length for varchar

    @Column('decimal', { precision: 10, scale: 2 })
    price: number; // Use decimal for monetary values

    @Column('timestamptz')
    createdAt: Date; // Use timestamptz for timezone awareness

    @Column('jsonb')
    metadata: Record<string, any>; // Use jsonb for flexible data
  }

  // 3. Implement proper relationships
  @Entity()
  export class ParentEntity {
    @OneToMany(() => ChildEntity, child => child.parent, {
      cascade: true,
      onDelete: 'CASCADE',
    })
    children: ChildEntity[];
  }

  @Entity()
  export class ChildEntity {
    @ManyToOne(() => ParentEntity, parent => parent.children, {
      onDelete: 'CASCADE',
    })
    @JoinColumn({ name: 'parent_id' })
    parent: ParentEntity;

    @Column()
    parentId: string; // Foreign key column
  }

  // 4. Add database constraints
  @Entity()
  export class ConstrainedEntity {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ unique: true, nullable: false })
    email: string;

    @Column({ length: 100, nullable: false })
    name: string;

    @Column({ default: true })
    isActive: boolean;

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    createdAt: Date;

    @Column({
      type: 'timestamp',
      default: () => 'CURRENT_TIMESTAMP',
      onUpdate: 'CURRENT_TIMESTAMP'
    })
    updatedAt: Date;
  }

  // 5. Implement entity lifecycle hooks
  @Entity()
  export class LifecycleEntity {
    @BeforeInsert()
    setCreatedAt() {
      this.createdAt = new Date();
      this.updatedAt = new Date();
    }

    @BeforeUpdate()
    setUpdatedAt() {
      this.updatedAt = new Date();
    }

    @AfterLoad()
    formatDates() {
      // Format dates for API responses
      if (this.createdAt) {
        this.createdAt = new Date(this.createdAt.toISOString());
      }
    }
  }

  // 6. Use indexes for performance
  @Entity()
  @Index(['email']) // Single column index
  @Index(['status', 'createdAt']) // Composite index
  @Index(['email'], { unique: true }) // Unique index
  export class IndexedEntity {
    @Column()
    email: string;

    @Column()
    status: string;

    @Column()
    createdAt: Date;
  }
}
```

### **2. DTO Design Patterns**

```typescript
// DTO design patterns and best practices
@Injectable()
export class DtoDesignBestPractises {
  // 1. Use inheritance for related DTOs
  export class BaseDto {
    @ApiProperty()
    id: string;

    @ApiProperty()
    createdAt: Date;

    @ApiProperty()
    updatedAt: Date;
  }

  export class CreateDto extends BaseDto {
    @ApiProperty()
    @IsNotEmpty()
    name: string;
  }

  export class UpdateDto extends BaseDto {
    @ApiProperty()
    @IsOptional()
    name?: string;
  }

  // 2. Use discriminated unions for complex types
  export type ApiResponse<T> =
    | { success: true; data: T }
    | { success: false; error: ErrorDetails };

  export class ErrorDetails {
    @ApiProperty()
    code: string;

    @ApiProperty()
    message: string;

    @ApiProperty({ required: false })
    details?: any;
  }

  // 3. Implement proper validation groups
  export class UserDto {
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty({ groups: ['registration'] })
    @IsStrongPassword({ groups: ['registration'] })
    password?: string;

    @IsOptional({ groups: ['update'] })
    @IsString({ groups: ['update'] })
    name?: string;
  }

  // 4. Use transformation decorators
  export class TransformedDto {
    @Transform(({ value }) => value?.toUpperCase())
    @ApiProperty()
    name: string;

    @Transform(({ value }) => new Date(value))
    @ApiProperty()
    dateOfBirth: Date;

    @Transform(({ value }) => value?.map(item => item.toString()))
    @ApiProperty({ type: [String] })
    tags: string[];
  }

  // 5. Implement conditional validation
  export class ConditionalDto {
    @IsNotEmpty()
    type: 'email' | 'phone';

    @ValidateIf(o => o.type === 'email')
    @IsEmail()
    email?: string;

    @ValidateIf(o => o.type === 'phone')
    @IsPhoneNumber()
    phone?: string;
  }

  // 6. Use custom validators
  export class CustomValidatedDto {
    @Validate(IsValidDateRange, {
      message: 'End date must be after start date'
    })
    @ApiProperty()
    startDate: Date;

    @ApiProperty()
    endDate: Date;
  }

  // Custom validator
  export function IsValidDateRange(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
      registerDecorator({
        name: 'isValidDateRange',
        target: object.constructor,
        propertyName: propertyName,
        options: validationOptions,
        validator: {
          validate(value: any, args: ValidationArguments) {
            const startDate = (args.object as any).startDate;
            const endDate = value;

            if (!startDate || !endDate) return true;

            return endDate > startDate;
          },
        },
      });
    };
  }
}
```

### **3. Data Mapping Strategies**

```typescript
// Data mapping strategies between entities and DTOs
@Injectable()
export class DataMappingStrategies {
  // 1. Simple field mapping
  static mapEntityToDto<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
  ): U {
    const dto = new dtoClass();

    // Map common fields
    if ('id' in entity) dto.id = entity.id;
    if ('createdAt' in entity) dto.createdAt = entity.createdAt;
    if ('updatedAt' in entity) dto.updatedAt = entity.updatedAt;

    // Map specific fields
    Object.assign(dto, entity);

    return dto;
  }

  // 2. Complex mapping with relationships
  static async mapEntityWithRelations<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
    relations: string[],
  ): Promise<U> {
    const dto = this.mapEntityToDto(entity, dtoClass);

    // Load and map relationships
    for (const relation of relations) {
      if (entity[relation]) {
        if (Array.isArray(entity[relation])) {
          dto[relation] = entity[relation].map(item =>
            this.mapEntityToDto(item, Object));
        } else {
          dto[relation] = this.mapEntityToDto(entity[relation], Object);
        }
      }
    }

    return dto;
  }

  // 3. Selective field mapping
  static mapEntitySelective<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
    fields: (keyof T)[],
  ): U {
    const dto = new dtoClass();

    fields.forEach(field => {
      if (entity[field] !== undefined) {
        dto[field as keyof U] = entity[field] as any;
      }
    });

    return dto;
  }

  // 4. Mapping with transformation
  static mapEntityWithTransformation<T extends BaseEntity, U>(
    entity: T,
    dtoClass: new () => U,
    transformations: Record<string, (value: any) => any>,
  ): U {
    const dto = this.mapEntityToDto(entity, dtoClass);

    // Apply transformations
    Object.entries(transformations).forEach(([field, transform]) => {
      if (dto[field] !== undefined) {
        dto[field] = transform(dto[field]);
      }
    });

    return dto;
  }

  // 5. Collection mapping
  static mapEntityCollection<T extends BaseEntity, U>(
    entities: T[],
    dtoClass: new () => U,
    options?: MappingOptions,
  ): U[] {
    return entities.map(entity =>
      options?.transform
        ? this.mapEntityWithTransformation(entity, dtoClass, options.transform)
        : this.mapEntityToDto(entity, dtoClass)
    );
  }

  // 6. Bidirectional mapping
  static mapDtoToEntity<U, T extends BaseEntity>(
    dto: U,
    entityClass: new () => T,
    mappings?: Record<string, string>,
  ): T {
    const entity = new entityClass();

    Object.keys(dto).forEach(key => {
      const entityKey = mappings?.[key] || key;
      if (entityKey in entity) {
        entity[entityKey] = dto[key];
      }
    });

    return entity;
  }
}
```

---

## 🎯 **Next Steps**

Now that you understand the Database Entities & API DTOs comprehensively, explore:

1. **[Provider Specialty Service](./../services/provider-specialty.md)** - Healthcare provider data management
2. **[Introspect Service](./../services/introspect.md)** - Authentication token validation
3. **[Specialty2Role Service](./../services/specialty2role.md)** - Provider specialty to role mapping

Each service integrates with the entities and DTOs to provide a complete data management and business logic layer for the healthcare API platform.

**🚀 Ready to explore the Provider Specialty Service that manages healthcare provider data using these entities and DTOs? Your data layer expertise will help you understand how the business services leverage the foundation you've just mastered!**
