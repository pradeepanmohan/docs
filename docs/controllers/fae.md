# 🔍 FAE (Find An Expert) Controller - Healthcare Specialist Discovery System

## 🎯 **Overview**

The **FAE (Find An Expert) Controller** provides an intelligent healthcare specialist discovery and consultation system. This controller enables healthcare providers to find and connect with medical specialists based on patient conditions, medical expertise, geographic location, and availability. It integrates with provider directories and scheduling systems to facilitate specialist referrals and consultations.

---

## 📍 **FAE Architecture Overview**

### **What is Find An Expert?**
Find An Expert (FAE) is an intelligent healthcare provider discovery system that:
- **Searches medical specialists** by specialty, location, and expertise
- **Provides availability information** for scheduling consultations
- **Offers typeahead search** for real-time provider discovery
- **Facilitates specialist referrals** with direct communication channels
- **Integrates with provider directories** and credentialing systems
- **Supports telemedicine consultations** and in-person visits

### **FAE System Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│       Find An Expert (FAE) System Architecture             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           FAE Controller                            │    │
│  │  ├─ Expert Search ───────────────┬─ Specialty Match │    │
│  │  ├─ Availability Check ──────────┼─ Scheduling      │    │
│  │  ├─ Typeahead Search ────────────┼─ Real-time Search│    │
│  │  └─ Referral Coordination ───────┴─ Communication   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           FAE Service                              │    │
│  │  ├─ Provider Directory Integration─┬─ Expert DB     │    │
│  │  ├─ Search Algorithm ──────────────┼─ Matching Logic │    │
│  │  ├─ Availability Engine ───────────┼─ Scheduling     │    │
│  │  └─ Communication Bridge ──────────┴─ Secure Chat    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Provider Data Integration                 │    │
│  │  ├─ Specialist Database ──────────┬─ Credentials    │    │
│  │  ├─ Geographic Mapping ───────────┼─ Location       │    │
│  │  ├─ Specialty Classification ─────┼─ Expertise      │    │
│  │  └─ Availability Calendar ────────┴─ Scheduling     │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. FAE Controller**

```typescript
// File: src/controllers/fae/fae.controller.ts

import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';
import { FaeAvailabilityRequestDto } from './dto/fae-availability-request.dto';
import { FaeAvailabilityResponseDto } from './dto/fae-availability-response.dto';
import { FaeSearchRequestDto } from './dto/fae-search-request.dto';
import { FaeSearchResponseDto } from './dto/fae-search-response.dto';
import { FaeTypeaheadSearchRequestDto } from './dto/fae-typeahead-search-request.dto';
import { FaeTypeaheadSearchResponseDto } from './dto/fae-typeahead-search-response.dto';
import { FaeExpertDetailsRequestDto } from './dto/fae-user-details-request.dto';
import { FaeExpertDetailsResponseDto } from './dto/fae-user-details-response.dto';
import { FaeService } from './fae.service';
import { FaeSendMailRequestDto } from './dto/fae-send-mail.request.dto';
import { FaeSendMailResponseDto } from './dto/fae-send-mail.response.dto';
import { CurrentUser } from 'src/decorators/current-user.decorator';

@ApiTags('Find An Expert')
@ApiBearerAuth()
@Controller('clinical-experts')
export class FaeController {
  constructor(private readonly faeService: FaeService) {}

  /**
   * Search for healthcare experts by specialty and criteria
   */
  @ApiOperation({
    summary: 'Search for experts',
    description:
      'Returns the top 50 expert results based on the search criteria',
  })
  @ApiResponse({
    status: 200,
    description: 'List of experts with search term (if autocorrected)',
    type: FaeSearchResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Malformed request body',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
  @ApiHeader({
    name: 'authorization-entra',
    description:
      'Microsoft Entra user access token. Make sure you have set the right permissions',
  })
  @Post('search')
  @HttpCode(HttpStatus.OK)
  async searchExperts(
    @CurrentUser() user: any,
    @Body() searchRequest: FaeSearchRequestDto,
  ): Promise<FaeSearchResponseDto> {
    const { specialty, location, searchTerm } = searchRequest;

    // Validate required parameters
    if (!specialty && !searchTerm) {
      throw new BadRequestException(
        'Either specialty or searchTerm must be provided',
      );
    }

    try {
      return await this.faeService.searchExperts(user, searchRequest);
    } catch (error) {
      throw new BadRequestException(
        `Failed to search experts: ${error.message}`,
      );
    }
  }

  /**
   * Get real-time typeahead search suggestions
   */
  @ApiOperation({
    summary: 'Typeahead search for experts',
    description:
      'Returns up to 10 expert suggestions based on partial search input',
  })
  @ApiResponse({
    status: 200,
    description: 'List of expert suggestions',
    type: FaeTypeaheadSearchResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid search input',
  })
  @ApiHeader({
    name: 'authorization-entra',
    description:
      'Microsoft Entra user access token. Make sure you have set the right permissions',
  })
  @Post('typeahead')
  @HttpCode(HttpStatus.OK)
  async typeaheadSearch(
    @CurrentUser() user: any,
    @Body() typeaheadRequest: FaeTypeaheadSearchRequestDto,
  ): Promise<FaeTypeaheadSearchResponseDto> {
    const { query, specialty } = typeaheadRequest;

    // Validate query parameter
    if (!query || query.trim().length < 2) {
      throw new BadRequestException(
        'Query must be at least 2 characters long',
      );
    }

    try {
      return await this.faeService.typeaheadSearch(user, typeaheadRequest);
    } catch (error) {
      throw new BadRequestException(
        `Typeahead search failed: ${error.message}`,
      );
    }
  }

  /**
   * Check expert availability for consultations
   */
  @ApiOperation({
    summary: 'Check expert availability',
    description:
      'Returns availability information for a specific expert within a date range',
  })
  @ApiResponse({
    status: 200,
    description: 'Expert availability information',
    type: FaeAvailabilityResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request parameters',
  })
  @ApiResponse({
    status: 404,
    description: 'Expert not found',
  })
  @ApiHeader({
    name: 'authorization-entra',
    description:
      'Microsoft Entra user access token. Make sure you have set the right permissions',
  })
  @Post('availability')
  @HttpCode(HttpStatus.OK)
  async checkAvailability(
    @CurrentUser() user: any,
    @Body() availabilityRequest: FaeAvailabilityRequestDto,
  ): Promise<FaeAvailabilityResponseDto> {
    const { expertId, startDate, endDate } = availabilityRequest;

    // Validate date range
    if (!expertId) {
      throw new BadRequestException('Expert ID is required');
    }

    if (!startDate || !endDate) {
      throw new BadRequestException('Start date and end date are required');
    }

    const start = new Date(startDate);
    const end = new Date(endDate);

    if (start >= end) {
      throw new BadRequestException('Start date must be before end date');
    }

    if (end.getTime() - start.getTime() > 90 * 24 * 60 * 60 * 1000) {
      throw new BadRequestException('Date range cannot exceed 90 days');
    }

    try {
      return await this.faeService.checkAvailability(user, availabilityRequest);
    } catch (error) {
      if (error.message.includes('not found')) {
        throw new BadRequestException(`Expert not found: ${expertId}`);
      }
      throw new BadRequestException(
        `Failed to check availability: ${error.message}`,
      );
    }
  }

  /**
   * Get detailed information about a specific expert
   */
  @ApiOperation({
    summary: 'Get expert details',
    description:
      'Returns comprehensive information about a specific healthcare expert',
  })
  @ApiResponse({
    status: 200,
    description: 'Expert details',
    type: FaeExpertDetailsResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Expert not found',
  })
  @ApiHeader({
    name: 'authorization-entra',
    description:
      'Microsoft Entra user access token. Make sure you have set the right permissions',
  })
  @Post('details')
  @HttpCode(HttpStatus.OK)
  async getExpertDetails(
    @CurrentUser() user: any,
    @Body() detailsRequest: FaeExpertDetailsRequestDto,
  ): Promise<FaeExpertDetailsResponseDto> {
    const { expertId } = detailsRequest;

    if (!expertId) {
      throw new BadRequestException('Expert ID is required');
    }

    try {
      return await this.faeService.getExpertDetails(user, detailsRequest);
    } catch (error) {
      if (error.message.includes('not found')) {
        throw new BadRequestException(`Expert not found: ${expertId}`);
      }
      throw new BadRequestException(
        `Failed to get expert details: ${error.message}`,
      );
    }
  }

  /**
   * Send consultation request email to expert
   */
  @ApiOperation({
    summary: 'Send consultation request',
    description:
      'Sends a consultation request email to the selected expert',
  })
  @ApiResponse({
    status: 200,
    description: 'Consultation request sent successfully',
    type: FaeSendMailResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request parameters',
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to send consultation request',
  })
  @ApiHeader({
    name: 'authorization-entra',
    description:
      'Microsoft Entra user access token. Make sure you have set the right permissions',
  })
  @Post('contact')
  @HttpCode(HttpStatus.OK)
  async sendConsultationRequest(
    @CurrentUser() user: any,
    @Body() mailRequest: FaeSendMailRequestDto,
  ): Promise<FaeSendMailResponseDto> {
    const { expertId, patientId, urgency, message } = mailRequest;

    // Validate required parameters
    if (!expertId) {
      throw new BadRequestException('Expert ID is required');
    }

    if (!patientId) {
      throw new BadRequestException('Patient ID is required');
    }

    if (!message || message.trim().length === 0) {
      throw new BadRequestException('Message cannot be empty');
    }

    try {
      return await this.faeService.sendConsultationRequest(user, mailRequest);
    } catch (error) {
      throw new BadRequestException(
        `Failed to send consultation request: ${error.message}`,
      );
    }
  }
}
```

**Key Features:**
- ✅ **Expert Search**: Multi-criteria specialist discovery
- ✅ **Typeahead Search**: Real-time search suggestions
- ✅ **Availability Checking**: Scheduling integration
- ✅ **Expert Details**: Comprehensive provider profiles
- ✅ **Consultation Requests**: Direct communication facilitation
- ✅ **Geographic Filtering**: Location-based search capabilities
- ✅ **Specialty Classification**: Medical specialty matching

### **2. FAE Data Transfer Objects**

#### **Expert Search Request DTO**
```typescript
// File: src/controllers/fae/dto/fae-search-request.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsOptional, IsString, IsNumber, Min, Max, IsEnum } from 'class-validator';
import { Type } from 'class-transformer';

@ApiSchema({
  name: 'FaeSearchRequest',
  description: 'Request payload for searching healthcare experts',
})
export class FaeSearchRequestDto {
  /**
   * Medical specialty to search for
   */
  @ApiProperty({
    description: 'Medical specialty (e.g., cardiology, oncology, neurology)',
    example: 'cardiology',
    required: false,
  })
  @IsOptional()
  @IsString()
  specialty?: string;

  /**
   * Geographic location for search
   */
  @ApiProperty({
    description: 'Geographic location (city, state, or zip code)',
    example: 'Rochester, MN',
    required: false,
  })
  @IsOptional()
  @IsString()
  location?: string;

  /**
   * Free-text search term
   */
  @ApiProperty({
    description: 'Free-text search term for expert discovery',
    example: 'heart specialist',
    required: false,
  })
  @IsOptional()
  @IsString()
  searchTerm?: string;

  /**
   * Maximum number of results to return
   */
  @ApiProperty({
    description: 'Maximum number of results to return (1-100)',
    example: 50,
    default: 50,
    minimum: 1,
    maximum: 100,
    required: false,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 50;

  /**
   * Search radius in miles (for location-based search)
   */
  @ApiProperty({
    description: 'Search radius in miles from specified location',
    example: 50,
    default: 25,
    minimum: 1,
    maximum: 500,
    required: false,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(500)
  radius?: number = 25;

  /**
   * Sort order for results
   */
  @ApiProperty({
    description: 'Sort order for search results',
    example: 'relevance',
    enum: ['relevance', 'distance', 'rating', 'availability'],
    default: 'relevance',
    required: false,
  })
  @IsOptional()
  @IsEnum(['relevance', 'distance', 'rating', 'availability'])
  sortBy?: string = 'relevance';

  /**
   * Insurance acceptance filter
   */
  @ApiProperty({
    description: 'Filter by insurance acceptance',
    example: 'accepts_medicare',
    enum: ['accepts_medicare', 'accepts_medicaid', 'private_insurance'],
    required: false,
  })
  @IsOptional()
  @IsEnum(['accepts_medicare', 'accepts_medicaid', 'private_insurance'])
  insuranceFilter?: string;

  /**
   * Telemedicine capability filter
   */
  @ApiProperty({
    description: 'Filter by telemedicine capability',
    example: true,
    required: false,
  })
  @IsOptional()
  telemedicineEnabled?: boolean;
}
```

#### **Expert Search Response DTO**
```typescript
// File: src/controllers/fae/dto/fae-search-response.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';

@ApiSchema({
  name: 'FaeSearchResponse',
  description: 'Response payload for expert search results',
})
export class FaeSearchResponseDto {
  /**
   * Array of expert search results
   */
  @ApiProperty({
    description: 'List of healthcare experts matching search criteria',
    type: [ExpertResult],
  })
  experts: ExpertResult[];

  /**
   * Total number of experts found
   */
  @ApiProperty({
    description: 'Total number of experts found (may exceed returned results)',
    example: 125,
  })
  totalCount: number;

  /**
   * Search term used (may be autocorrected)
   */
  @ApiProperty({
    description: 'Search term used for the query (may be autocorrected)',
    example: 'cardiology',
  })
  searchTerm: string;

  /**
   * Whether search term was autocorrected
   */
  @ApiProperty({
    description: 'Whether the search term was autocorrected',
    example: false,
  })
  autocorrected: boolean;

  /**
   * Original search term (if autocorrected)
   */
  @ApiProperty({
    description: 'Original search term (if autocorrected)',
    example: 'heart doctor',
    required: false,
  })
  originalTerm?: string;

  /**
   * Search execution time in milliseconds
   */
  @ApiProperty({
    description: 'Search execution time in milliseconds',
    example: 245,
  })
  executionTime: number;

  /**
   * Geographic bounds used for search
   */
  @ApiProperty({
    description: 'Geographic bounds used for location-based search',
    required: false,
  })
  bounds?: GeographicBounds;
}

/**
 * Individual expert search result
 */
class ExpertResult {
  @ApiProperty({
    description: 'Unique identifier for the expert',
    example: 'exp_123456',
  })
  id: string;

  @ApiProperty({
    description: 'Expert full name',
    example: 'Dr. Sarah Johnson',
  })
  name: string;

  @ApiProperty({
    description: 'Primary medical specialty',
    example: 'Cardiology',
  })
  specialty: string;

  @ApiProperty({
    description: 'Subspecialties or areas of expertise',
    example: ['Interventional Cardiology', 'Echocardiography'],
  })
  subspecialties: string[];

  @ApiProperty({
    description: 'Medical credentials and certifications',
    example: 'MD, FACC, FSCAI',
  })
  credentials: string;

  @ApiProperty({
    description: 'Healthcare facility or practice name',
    example: 'Mayo Clinic Cardiology',
  })
  facility: string;

  @ApiProperty({
    description: 'Geographic location',
  })
  location: LocationInfo;

  @ApiProperty({
    description: 'Distance from search location in miles',
    example: 2.3,
  })
  distance?: number;

  @ApiProperty({
    description: 'Average patient rating (1-5 scale)',
    example: 4.8,
  })
  rating: number;

  @ApiProperty({
    description: 'Number of patient reviews',
    example: 127,
  })
  reviewCount: number;

  @ApiProperty({
    description: 'Whether telemedicine consultations are available',
    example: true,
  })
  telemedicineAvailable: boolean;

  @ApiProperty({
    description: 'Next available appointment date/time',
    example: '2024-01-15T14:30:00Z',
  })
  nextAvailable?: string;

  @ApiProperty({
    description: 'Insurance plans accepted',
    example: ['Medicare', 'Blue Cross Blue Shield', 'UnitedHealthcare'],
  })
  acceptedInsurance: string[];
}

/**
 * Geographic bounds for search area
 */
class GeographicBounds {
  @ApiProperty({
    description: 'Northeast corner coordinates',
  })
  northeast: Coordinate;

  @ApiProperty({
    description: 'Southwest corner coordinates',
  })
  southwest: Coordinate;
}

/**
 * Geographic coordinate
 */
class Coordinate {
  @ApiProperty({
    description: 'Latitude',
    example: 44.0234,
  })
  latitude: number;

  @ApiProperty({
    description: 'Longitude',
    example: -92.4630,
  })
  longitude: number;
}

/**
 * Location information for expert
 */
class LocationInfo {
  @ApiProperty({
    description: 'Street address',
    example: '200 1st St SW',
  })
  address: string;

  @ApiProperty({
    description: 'City',
    example: 'Rochester',
  })
  city: string;

  @ApiProperty({
    description: 'State/province',
    example: 'MN',
  })
  state: string;

  @ApiProperty({
    description: 'ZIP/postal code',
    example: '55905',
  })
  zipCode: string;

  @ApiProperty({
    description: 'Country',
    example: 'USA',
  })
  country: string;

  @ApiProperty({
    description: 'Geographic coordinates',
  })
  coordinates: Coordinate;
}
```

#### **Typeahead Search Request DTO**
```typescript
// File: src/controllers/fae/dto/fae-typeahead-search-request.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional, MinLength, MaxLength } from 'class-validator';

@ApiSchema({
  name: 'FaeTypeaheadSearchRequest',
  description: 'Request payload for typeahead expert search',
})
export class FaeTypeaheadSearchRequestDto {
  /**
   * Partial search query for real-time suggestions
   */
  @ApiProperty({
    description: 'Partial search query (minimum 2 characters)',
    example: 'card',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(2, { message: 'Query must be at least 2 characters long' })
  @MaxLength(100, { message: 'Query cannot exceed 100 characters' })
  query: string;

  /**
   * Optional specialty filter for typeahead results
   */
  @ApiProperty({
    description: 'Optional specialty filter to narrow results',
    example: 'cardiology',
    required: false,
  })
  @IsOptional()
  @IsString()
  specialty?: string;

  /**
   * Maximum number of suggestions to return
   */
  @ApiProperty({
    description: 'Maximum number of suggestions to return',
    example: 10,
    default: 10,
    minimum: 1,
    maximum: 20,
    required: false,
  })
  @IsOptional()
  limit?: number = 10;
}
```

#### **Availability Request DTO**
```typescript
// File: src/controllers/fae/dto/fae-availability-request.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsDateString, IsOptional } from 'class-validator';

@ApiSchema({
  name: 'FaeAvailabilityRequest',
  description: 'Request payload for checking expert availability',
})
export class FaeAvailabilityRequestDto {
  /**
   * Unique identifier of the expert
   */
  @ApiProperty({
    description: 'Unique identifier of the healthcare expert',
    example: 'exp_123456',
  })
  @IsNotEmpty()
  @IsString()
  expertId: string;

  /**
   * Start date for availability check (ISO 8601 format)
   */
  @ApiProperty({
    description: 'Start date for availability check (ISO 8601 format)',
    example: '2024-01-15',
  })
  @IsNotEmpty()
  @IsDateString()
  startDate: string;

  /**
   * End date for availability check (ISO 8601 format)
   */
  @ApiProperty({
    description: 'End date for availability check (ISO 8601 format)',
    example: '2024-01-22',
  })
  @IsNotEmpty()
  @IsDateString()
  endDate: string;

  /**
   * Preferred consultation type
   */
  @ApiProperty({
    description: 'Preferred consultation type',
    example: 'in_person',
    enum: ['in_person', 'telemedicine', 'both'],
    default: 'both',
    required: false,
  })
  @IsOptional()
  @IsString()
  consultationType?: string = 'both';

  /**
   * Required consultation duration in minutes
   */
  @ApiProperty({
    description: 'Required consultation duration in minutes',
    example: 30,
    default: 30,
    minimum: 15,
    maximum: 120,
    required: false,
  })
  @IsOptional()
  durationMinutes?: number = 30;
}
```

#### **Consultation Request DTO**
```typescript
// File: src/controllers/fae/dto/fae-send-mail.request.dto.ts

import { ApiProperty, ApiSchema } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional, IsEnum, MaxLength } from 'class-validator';

@ApiSchema({
  name: 'FaeSendMailRequest',
  description: 'Request payload for sending consultation requests',
})
export class FaeSendMailRequestDto {
  /**
   * Unique identifier of the expert to contact
   */
  @ApiProperty({
    description: 'Unique identifier of the healthcare expert',
    example: 'exp_123456',
  })
  @IsNotEmpty()
  @IsString()
  expertId: string;

  /**
   * Unique identifier of the patient requiring consultation
   */
  @ApiProperty({
    description: 'Unique identifier of the patient',
    example: 'pat_789012',
  })
  @IsNotEmpty()
  @IsString()
  patientId: string;

  /**
   * Urgency level of the consultation request
   */
  @ApiProperty({
    description: 'Urgency level of the consultation request',
    example: 'routine',
    enum: ['routine', 'urgent', 'emergency'],
    default: 'routine',
  })
  @IsOptional()
  @IsEnum(['routine', 'urgent', 'emergency'])
  urgency?: string = 'routine';

  /**
   * Preferred consultation date/time (ISO 8601 format)
   */
  @ApiProperty({
    description: 'Preferred consultation date/time (ISO 8601 format)',
    example: '2024-01-20T10:00:00Z',
    required: false,
  })
  @IsOptional()
  @IsString()
  preferredDateTime?: string;

  /**
   * Consultation request message
   */
  @ApiProperty({
    description: 'Detailed consultation request message',
    example: 'Patient presents with chest pain and EKG changes suggestive of STEMI. Please assess for urgent cardiac catheterization.',
  })
  @IsNotEmpty()
  @IsString()
  @MaxLength(2000, { message: 'Message cannot exceed 2000 characters' })
  message: string;

  /**
   * Additional clinical context or attachments
   */
  @ApiProperty({
    description: 'Additional clinical context or special instructions',
    example: 'Recent labs show troponin elevation. Patient has history of CAD.',
    required: false,
  })
  @IsOptional()
  @IsString()
  @MaxLength(1000, { message: 'Clinical context cannot exceed 1000 characters' })
  clinicalContext?: string;

  /**
   * Requesting provider's contact information
   */
  @ApiProperty({
    description: 'Requesting provider contact information',
    example: 'Dr. John Smith, Cardiology Fellow, ext. 12345',
    required: false,
  })
  @IsOptional()
  @IsString()
  @MaxLength(200, { message: 'Contact info cannot exceed 200 characters' })
  requesterContact?: string;
}
```

**DTO Features:**
- ✅ **Comprehensive Validation**: Input validation with detailed error messages
- ✅ **API Documentation**: Complete Swagger/OpenAPI schema generation
- ✅ **Geographic Support**: Location-based search and filtering
- ✅ **Scheduling Integration**: Availability checking and appointment booking
- ✅ **Communication Facilitation**: Direct consultation request capabilities
- ✅ **Flexible Search**: Multiple search criteria and filtering options

### **3. FAE Service Implementation**

```typescript
// File: src/controllers/fae/fae.service.ts

import { Injectable, Logger, BadRequestException, NotFoundException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigType } from '@nestjs/config';
import { lastValueFrom } from 'rxjs';
import faeConfig from '@app/common/config/fae.config';
import { FaeSearchRequestDto } from './dto/fae-search-request.dto';
import { FaeSearchResponseDto } from './dto/fae-search-response.dto';
import { FaeTypeaheadSearchRequestDto } from './dto/fae-typeahead-search-request.dto';
import { FaeTypeaheadSearchResponseDto } from './dto/fae-typeahead-search-response.dto';
import { FaeAvailabilityRequestDto } from './dto/fae-availability-request.dto';
import { FaeAvailabilityResponseDto } from './dto/fae-availability-response.dto';
import { FaeExpertDetailsRequestDto } from './dto/fae-user-details-request.dto';
import { FaeExpertDetailsResponseDto } from './dto/fae-user-details-response.dto';
import { FaeSendMailRequestDto } from './dto/fae-send-mail.request.dto';
import { FaeSendMailResponseDto } from './dto/fae-send-mail.response.dto';

@Injectable()
export class FaeService {
  private readonly logger = new Logger(FaeService.name);

  constructor(
    private readonly httpService: HttpService,
    @Inject(faeConfig.KEY)
    private readonly config: ConfigType<typeof faeConfig>,
  ) {}

  /**
   * Search for healthcare experts based on criteria
   */
  async searchExperts(
    user: any,
    searchRequest: FaeSearchRequestDto,
  ): Promise<FaeSearchResponseDto> {
    try {
      const startTime = Date.now();

      // Build search query parameters
      const searchParams = this.buildSearchParams(searchRequest);

      // Call expert search API
      const response = await lastValueFrom(
        this.httpService.post(
          `${this.config.apiUrl}/experts/search`,
          searchParams,
          {
            headers: {
              'Content-Type': 'application/json',
              // Authentication headers would be added here
            },
            timeout: this.config.timeout || 30000,
          },
        ),
      );

      const executionTime = Date.now() - startTime;

      // Process and format response
      return {
        experts: this.processExpertResults(response.data.experts || []),
        totalCount: response.data.totalCount || 0,
        searchTerm: response.data.searchTerm || searchRequest.searchTerm || '',
        autocorrected: response.data.autocorrected || false,
        originalTerm: response.data.originalTerm,
        executionTime,
        bounds: response.data.bounds,
      };
    } catch (error) {
      this.logger.error('Expert search failed', {
        userId: user?.lanId,
        searchCriteria: searchRequest,
        error: error.message,
      });

      throw new BadRequestException(`Expert search failed: ${error.message}`);
    }
  }

  /**
   * Perform typeahead search for real-time suggestions
   */
  async typeaheadSearch(
    user: any,
    typeaheadRequest: FaeTypeaheadSearchRequestDto,
  ): Promise<FaeTypeaheadSearchResponseDto> {
    try {
      const response = await lastValueFrom(
        this.httpService.get(
          `${this.config.apiUrl}/experts/typeahead`,
          {
            params: {
              q: typeaheadRequest.query,
              specialty: typeaheadRequest.specialty,
              limit: typeaheadRequest.limit || 10,
            },
            timeout: 5000, // Shorter timeout for typeahead
          },
        ),
      );

      return {
        suggestions: response.data.suggestions || [],
        query: typeaheadRequest.query,
        specialty: typeaheadRequest.specialty,
        totalSuggestions: response.data.totalSuggestions || 0,
      };
    } catch (error) {
      this.logger.error('Typeahead search failed', {
        userId: user?.lanId,
        query: typeaheadRequest.query,
        error: error.message,
      });

      // Return empty suggestions on error for better UX
      return {
        suggestions: [],
        query: typeaheadRequest.query,
        specialty: typeaheadRequest.specialty,
        totalSuggestions: 0,
      };
    }
  }

  /**
   * Check expert availability for consultations
   */
  async checkAvailability(
    user: any,
    availabilityRequest: FaeAvailabilityRequestDto,
  ): Promise<FaeAvailabilityResponseDto> {
    try {
      const response = await lastValueFrom(
        this.httpService.post(
          `${this.config.apiUrl}/experts/${availabilityRequest.expertId}/availability`,
          {
            startDate: availabilityRequest.startDate,
            endDate: availabilityRequest.endDate,
            consultationType: availabilityRequest.consultationType || 'both',
            durationMinutes: availabilityRequest.durationMinutes || 30,
          },
          {
            headers: {
              'Content-Type': 'application/json',
            },
            timeout: 15000,
          },
        ),
      );

      return {
        expertId: availabilityRequest.expertId,
        availability: response.data.availability || [],
        nextAvailable: response.data.nextAvailable,
        consultationTypes: response.data.consultationTypes || [],
        timezone: response.data.timezone || 'UTC',
        lastUpdated: response.data.lastUpdated,
      };
    } catch (error) {
      if (error.response?.status === 404) {
        throw new NotFoundException(`Expert not found: ${availabilityRequest.expertId}`);
      }

      this.logger.error('Availability check failed', {
        expertId: availabilityRequest.expertId,
        userId: user?.lanId,
        error: error.message,
      });

      throw new BadRequestException(`Availability check failed: ${error.message}`);
    }
  }

  /**
   * Get detailed information about a specific expert
   */
  async getExpertDetails(
    user: any,
    detailsRequest: FaeExpertDetailsRequestDto,
  ): Promise<FaeExpertDetailsResponseDto> {
    try {
      const response = await lastValueFrom(
        this.httpService.get(
          `${this.config.apiUrl}/experts/${detailsRequest.expertId}`,
          {
            timeout: 10000,
          },
        ),
      );

      return {
        expert: response.data,
        lastUpdated: response.data.lastUpdated,
        dataSource: response.data.dataSource || 'provider_directory',
      };
    } catch (error) {
      if (error.response?.status === 404) {
        throw new NotFoundException(`Expert not found: ${detailsRequest.expertId}`);
      }

      this.logger.error('Expert details retrieval failed', {
        expertId: detailsRequest.expertId,
        userId: user?.lanId,
        error: error.message,
      });

      throw new BadRequestException(`Expert details retrieval failed: ${error.message}`);
    }
  }

  /**
   * Send consultation request to expert
   */
  async sendConsultationRequest(
    user: any,
    mailRequest: FaeSendMailRequestDto,
  ): Promise<FaeSendMailResponseDto> {
    try {
      // Get expert details for email address
      const expertDetails = await this.getExpertDetails(user, {
        expertId: mailRequest.expertId,
      });

      // Prepare email content
      const emailContent = this.prepareConsultationEmail(
        user,
        expertDetails.expert,
        mailRequest,
      );

      // Send consultation request email
      const response = await lastValueFrom(
        this.httpService.post(
          `${this.config.apiUrl}/communication/send-email`,
          emailContent,
          {
            headers: {
              'Content-Type': 'application/json',
            },
            timeout: 20000,
          },
        ),
      );

      // Log consultation request for audit purposes
      this.logger.log('Consultation request sent', {
        expertId: mailRequest.expertId,
        patientId: mailRequest.patientId,
        userId: user?.lanId,
        urgency: mailRequest.urgency,
        messageLength: mailRequest.message.length,
      });

      return {
        success: true,
        messageId: response.data.messageId,
        deliveredAt: response.data.deliveredAt,
        expertNotified: true,
      };
    } catch (error) {
      this.logger.error('Consultation request failed', {
        expertId: mailRequest.expertId,
        patientId: mailRequest.patientId,
        userId: user?.lanId,
        error: error.message,
      });

      throw new BadRequestException(`Consultation request failed: ${error.message}`);
    }
  }

  /**
   * Build search parameters for expert search
   */
  private buildSearchParams(searchRequest: FaeSearchRequestDto): any {
    const params: any = {};

    if (searchRequest.specialty) {
      params.specialty = searchRequest.specialty;
    }

    if (searchRequest.location) {
      params.location = searchRequest.location;
    }

    if (searchRequest.searchTerm) {
      params.searchTerm = searchRequest.searchTerm;
    }

    if (searchRequest.limit) {
      params.limit = Math.min(searchRequest.limit, 100);
    }

    if (searchRequest.radius) {
      params.radius = searchRequest.radius;
    }

    if (searchRequest.sortBy) {
      params.sortBy = searchRequest.sortBy;
    }

    if (searchRequest.insuranceFilter) {
      params.insuranceFilter = searchRequest.insuranceFilter;
    }

    if (searchRequest.telemedicineEnabled !== undefined) {
      params.telemedicineEnabled = searchRequest.telemedicineEnabled;
    }

    return params;
  }

  /**
   * Process expert search results
   */
  private processExpertResults(rawExperts: any[]): any[] {
    return rawExperts.map(expert => ({
      id: expert.id,
      name: expert.name,
      specialty: expert.specialty,
      subspecialties: expert.subspecialties || [],
      credentials: expert.credentials,
      facility: expert.facility,
      location: expert.location,
      distance: expert.distance,
      rating: expert.rating || 0,
      reviewCount: expert.reviewCount || 0,
      telemedicineAvailable: expert.telemedicineAvailable || false,
      nextAvailable: expert.nextAvailable,
      acceptedInsurance: expert.acceptedInsurance || [],
    }));
  }

  /**
   * Prepare consultation email content
   */
  private prepareConsultationEmail(
    user: any,
    expert: any,
    mailRequest: FaeSendMailRequestDto,
  ): any {
    const urgencyIndicators = {
      routine: '📅 Routine Consultation Request',
      urgent: '⚡ Urgent Consultation Request',
      emergency: '🚨 Emergency Consultation Request',
    };

    const subject = `${urgencyIndicators[mailRequest.urgency || 'routine']} - ${user.name}`;

    const messageBody = `
Dear ${expert.name},

${user.name} (${user.credentials || 'Healthcare Provider'}) is requesting a consultation regarding a patient.

**Patient Information:**
- Patient ID: ${mailRequest.patientId}
- Urgency: ${mailRequest.urgency || 'routine'}

**Preferred Date/Time:**
${mailRequest.preferredDateTime || 'As soon as possible'}

**Clinical Context:**
${mailRequest.clinicalContext || 'Please see consultation message below.'}

**Consultation Request:**
${mailRequest.message}

**Contact Information:**
${mailRequest.requesterContact || `${user.name} - ${user.email || user.lanId}`}

Please respond at your earliest convenience to coordinate the consultation.

Best regards,
${user.name}
Mayo Care Team Navigator
    `.trim();

    return {
      to: expert.email,
      from: user.email || `${user.lanId}@mayo.edu`,
      subject,
      body: messageBody,
      priority: mailRequest.urgency === 'emergency' ? 'high' : 'normal',
      metadata: {
        patientId: mailRequest.patientId,
        requesterId: user.lanId,
        urgency: mailRequest.urgency,
        expertId: mailRequest.expertId,
      },
    };
  }
}
```

**Service Features:**
- ✅ **Expert Discovery**: Multi-criteria specialist search with ranking
- ✅ **Real-time Search**: Typeahead functionality for instant suggestions
- ✅ **Availability Integration**: Calendar and scheduling system integration
- ✅ **Profile Management**: Comprehensive expert profile data
- ✅ **Communication Facilitation**: Secure consultation request system
- ✅ **Geographic Intelligence**: Location-based search and distance calculation
- ✅ **Performance Optimization**: Efficient search algorithms and caching

---

## 🔄 **FAE Processing Flow**

### **1. Expert Search Flow**

```mermaid
graph TD
    A[Healthcare Provider] --> B[POST /clinical-experts/search]
    B --> C[Validate Search Criteria]
    C --> D[Build Search Parameters]
    D --> E[Query Expert Database/API]
    E --> F[Apply Filters & Ranking]
    F --> G[Format Expert Results]
    G --> H[Return FaeSearchResponseDto]
```

### **2. Typeahead Search Flow**

```mermaid
graph TD
    A[User Types Query] --> B[POST /clinical-experts/typeahead]
    B --> C[Validate Query Length]
    C --> D[Execute Real-time Search]
    D --> E[Limit to 10 Results]
    E --> F[Return Suggestions]
    F --> G[Display in UI]
```

### **3. Availability Check Flow**

```mermaid
graph TD
    A[Select Expert] --> B[POST /clinical-experts/availability]
    B --> C[Validate Date Range]
    C --> D[Query Expert Calendar]
    D --> E[Check Consultation Types]
    E --> F[Calculate Available Slots]
    F --> G[Return Availability Data]
```

### **4. Consultation Request Flow**

```mermaid
graph TD
    A[Provider] --> B[POST /clinical-experts/contact]
    B --> C[Validate Request Data]
    C --> D[Get Expert Details]
    D --> E[Prepare Email Content]
    E --> F[Send Consultation Email]
    F --> G[Log Communication]
    G --> H[Return Success Confirmation]
```

---

## 🔧 **Key Implementation Details**

### **1. Expert Search Algorithm**

```typescript
// Advanced expert search and ranking algorithm
@Injectable()
export class ExpertSearchAlgorithm {
  constructor(
    private readonly expertDatabase: ExpertDatabaseService,
    private readonly geoService: GeographicService,
  ) {}

  /**
   * Execute comprehensive expert search with ranking
   */
  async searchExperts(criteria: SearchCriteria): Promise<RankedExpert[]> {
    // Phase 1: Initial filtering
    const candidates = await this.initialFilter(criteria);

    // Phase 2: Scoring and ranking
    const scoredExperts = await this.scoreExperts(candidates, criteria);

    // Phase 3: Geographic sorting
    const geographicallySorted = await this.applyGeographicSorting(
      scoredExperts,
      criteria.location,
    );

    // Phase 4: Availability filtering
    const availabilityFiltered = await this.filterByAvailability(
      geographicallySorted,
      criteria.availabilityPreferences,
    );

    // Phase 5: Final ranking and pagination
    return this.finalRankingAndPagination(
      availabilityFiltered,
      criteria.pagination,
    );
  }

  /**
   * Initial filtering based on basic criteria
   */
  private async initialFilter(criteria: SearchCriteria): Promise<Expert[]> {
    const query = this.buildInitialQuery(criteria);

    // Specialty matching
    if (criteria.specialty) {
      query.where('specialty', 'ILIKE', `%${criteria.specialty}%`);
    }

    // Location-based filtering
    if (criteria.location) {
      const coordinates = await this.geoService.geocodeLocation(criteria.location);
      const radiusInMeters = (criteria.radius || 25) * 1609.34; // Convert miles to meters

      query.whereRaw(
        'ST_DWithin(coordinates, ST_MakePoint(?, ?), ?)',
        [coordinates.longitude, coordinates.latitude, radiusInMeters]
      );
    }

    // Free-text search
    if (criteria.searchTerm) {
      query.where(function() {
        this.where('name', 'ILIKE', `%${criteria.searchTerm}%`)
            .orWhere('specialty', 'ILIKE', `%${criteria.searchTerm}%`)
            .orWhere('facility', 'ILIKE', `%${criteria.searchTerm}%`)
            .orWhere('bio', 'ILIKE', `%${criteria.searchTerm}%`);
      });
    }

    return query.limit(1000).select(); // Broad initial selection
  }

  /**
   * Score experts based on relevance criteria
   */
  private async scoreExperts(
    experts: Expert[],
    criteria: SearchCriteria,
  ): Promise<ScoredExpert[]> {
    const scoredExperts: ScoredExpert[] = [];

    for (const expert of experts) {
      const score = await this.calculateExpertScore(expert, criteria);
      scoredExperts.push({
        ...expert,
        relevanceScore: score.relevance,
        qualityScore: score.quality,
        availabilityScore: score.availability,
        totalScore: score.total,
      });
    }

    return scoredExperts.sort((a, b) => b.totalScore - a.totalScore);
  }

  /**
   * Calculate comprehensive expert score
   */
  private async calculateExpertScore(
    expert: Expert,
    criteria: SearchCriteria,
  ): Promise<ExpertScore> {
    const relevanceScore = this.calculateRelevanceScore(expert, criteria);
    const qualityScore = this.calculateQualityScore(expert);
    const availabilityScore = await this.calculateAvailabilityScore(expert, criteria);

    // Weighted total score
    const totalScore =
      relevanceScore * 0.5 +
      qualityScore * 0.3 +
      availabilityScore * 0.2;

    return {
      relevance: relevanceScore,
      quality: qualityScore,
      availability: availabilityScore,
      total: totalScore,
    };
  }

  /**
   * Calculate relevance score based on search criteria match
   */
  private calculateRelevanceScore(expert: Expert, criteria: SearchCriteria): number {
    let score = 0;

    // Specialty match
    if (criteria.specialty &&
        expert.specialty.toLowerCase().includes(criteria.specialty.toLowerCase())) {
      score += 0.4;
    }

    // Subspecialty match
    if (criteria.specialty &&
        expert.subspecialties?.some(sub =>
          sub.toLowerCase().includes(criteria.specialty!.toLowerCase())
        )) {
      score += 0.3;
    }

    // Name/facility match for search terms
    if (criteria.searchTerm) {
      const searchTerm = criteria.searchTerm.toLowerCase();
      if (expert.name.toLowerCase().includes(searchTerm)) score += 0.2;
      if (expert.facility.toLowerCase().includes(searchTerm)) score += 0.1;
    }

    return Math.min(score, 1);
  }

  /**
   * Calculate quality score based on credentials and reputation
   */
  private calculateQualityScore(expert: Expert): number {
    let score = 0.5; // Base score

    // Board certification bonus
    if (expert.boardCertified) score += 0.2;

    // Rating bonus
    if (expert.rating && expert.rating >= 4.5) score += 0.2;
    else if (expert.rating && expert.rating >= 4.0) score += 0.1;

    // Review count bonus
    if (expert.reviewCount && expert.reviewCount >= 50) score += 0.1;
    else if (expert.reviewCount && expert.reviewCount >= 20) score += 0.05;

    // Years of experience bonus
    if (expert.yearsExperience && expert.yearsExperience >= 20) score += 0.1;
    else if (expert.yearsExperience && expert.yearsExperience >= 10) score += 0.05;

    return Math.min(score, 1);
  }

  /**
   * Calculate availability score based on scheduling
   */
  private async calculateAvailabilityScore(
    expert: Expert,
    criteria: SearchCriteria,
  ): Promise<number> {
    if (!criteria.preferredDateTime) return 0.5; // Neutral score if no preference

    try {
      const availability = await this.getExpertAvailability(
        expert.id,
        criteria.preferredDateTime,
      );

      if (availability.hasImmediateSlot) return 1.0;
      if (availability.hasSameDaySlot) return 0.8;
      if (availability.hasNextDaySlot) return 0.6;
      if (availability.hasThisWeekSlot) return 0.4;

      return 0.2; // Limited availability
    } catch (error) {
      // Return neutral score on availability check failure
      return 0.5;
    }
  }

  /**
   * Apply geographic sorting to results
   */
  private async applyGeographicSorting(
    experts: ScoredExpert[],
    userLocation?: string,
  ): Promise<ScoredExpert[]> {
    if (!userLocation) return experts;

    const userCoordinates = await this.geoService.geocodeLocation(userLocation);

    return experts.map(expert => ({
      ...expert,
      distance: this.geoService.calculateDistance(
        userCoordinates,
        expert.coordinates,
      ),
    })).sort((a, b) => (a.distance || Infinity) - (b.distance || Infinity));
  }

  /**
   * Filter experts by availability preferences
   */
  private async filterByAvailability(
    experts: ScoredExpert[],
    availabilityPrefs?: AvailabilityPreferences,
  ): Promise<ScoredExpert[]> {
    if (!availabilityPrefs) return experts;

    const filteredExperts: ScoredExpert[] = [];

    for (const expert of experts) {
      const availability = await this.getExpertAvailability(
        expert.id,
        availabilityPrefs.preferredDateTime,
      );

      if (this.matchesAvailabilityPreferences(availability, availabilityPrefs)) {
        filteredExperts.push(expert);
      }
    }

    return filteredExperts;
  }

  /**
   * Apply final ranking and pagination
   */
  private finalRankingAndPagination(
    experts: ScoredExpert[],
    pagination: PaginationOptions,
  ): RankedExpert[] {
    // Apply final sorting (may combine multiple factors)
    const finalSorted = experts.sort((a, b) => {
      // Primary sort by total score
      if (b.totalScore !== a.totalScore) {
        return b.totalScore - a.totalScore;
      }

      // Secondary sort by distance
      if (a.distance !== undefined && b.distance !== undefined) {
        return a.distance - b.distance;
      }

      // Tertiary sort by rating
      return (b.rating || 0) - (a.rating || 0);
    });

    // Apply pagination
    const startIndex = (pagination.page - 1) * pagination.pageSize;
    const endIndex = startIndex + pagination.pageSize;

    return finalSorted
      .slice(startIndex, endIndex)
      .map((expert, index) => ({
        ...expert,
        rank: startIndex + index + 1,
      }));
  }

  /**
   * Build initial database query
   */
  private buildInitialQuery(criteria: SearchCriteria) {
    return this.expertDatabase
      .query('experts')
      .select([
        'id',
        'name',
        'specialty',
        'subspecialties',
        'credentials',
        'facility',
        'location',
        'coordinates',
        'rating',
        'review_count',
        'years_experience',
        'board_certified',
        'telemedicine_available',
        'accepted_insurance',
      ])
      .where('active', true);
  }

  /**
   * Get expert availability for specific time
   */
  private async getExpertAvailability(expertId: string, dateTime: string) {
    // Implementation would query scheduling system
    return {
      hasImmediateSlot: false,
      hasSameDaySlot: true,
      hasNextDaySlot: true,
      hasThisWeekSlot: true,
    };
  }

  /**
   * Check if availability matches user preferences
   */
  private matchesAvailabilityPreferences(
    availability: any,
    preferences: AvailabilityPreferences,
  ): boolean {
    if (preferences.acceptSameDay && availability.hasSameDaySlot) return true;
    if (preferences.acceptNextDay && availability.hasNextDaySlot) return true;
    if (preferences.acceptThisWeek && availability.hasThisWeekSlot) return true;

    return preferences.acceptAnyTime;
  }
}
```

**Search Features:**
- ✅ **Multi-Criteria Matching**: Specialty, location, insurance, telemedicine
- ✅ **Relevance Scoring**: Intelligent ranking based on multiple factors
- ✅ **Geographic Intelligence**: Distance calculation and location-based filtering
- ✅ **Quality Assessment**: Board certification, ratings, experience evaluation
- ✅ **Availability Integration**: Real-time scheduling system integration
- ✅ **Pagination & Performance**: Efficient result handling and database queries

### **2. Typeahead Search Implementation**

```typescript
// Real-time typeahead search implementation
@Injectable()
export class TypeaheadSearchEngine {
  constructor(
    private readonly expertIndex: ExpertSearchIndex,
    private readonly cache: CacheService,
  ) {}

  /**
   * Execute typeahead search with performance optimizations
   */
  async performTypeaheadSearch(
    query: string,
    specialty?: string,
    limit: number = 10,
  ): Promise<TypeaheadSuggestion[]> {
    const cacheKey = `typeahead:${query}:${specialty || 'all'}:${limit}`;

    // Check cache first
    const cached = await this.cache.get<TypeaheadSuggestion[]>(cacheKey);
    if (cached) {
      return cached;
    }

    // Perform search
    const suggestions = await this.executeSearch(query, specialty, limit);

    // Cache results for short duration (typeahead queries are frequent)
    await this.cache.set(cacheKey, suggestions, 300); // 5 minutes

    return suggestions;
  }

  /**
   * Execute the actual search against expert index
   */
  private async executeSearch(
    query: string,
    specialty?: string,
    limit: number = 10,
  ): Promise<TypeaheadSuggestion[]> {
    const normalizedQuery = this.normalizeQuery(query);

    if (normalizedQuery.length < 2) {
      return [];
    }

    // Search different fields with different priorities
    const nameMatches = await this.searchField('name', normalizedQuery, specialty);
    const specialtyMatches = await this.searchField('specialty', normalizedQuery);
    const facilityMatches = await this.searchField('facility', normalizedQuery, specialty);

    // Combine and deduplicate results
    const allMatches = [...nameMatches, ...specialtyMatches, ...facilityMatches];
    const uniqueMatches = this.deduplicateMatches(allMatches);

    // Apply relevance scoring and sorting
    const scoredMatches = this.scoreAndSortMatches(uniqueMatches, normalizedQuery);

    // Limit results and format
    return scoredMatches
      .slice(0, limit)
      .map(match => this.formatSuggestion(match));
  }

  /**
   * Search specific field with fuzzy matching
   */
  private async searchField(
    field: string,
    query: string,
    specialty?: string,
  ): Promise<ExpertMatch[]> {
    const searchOptions = {
      field,
      query,
      fuzzy: true,
      prefix: true,
      specialty,
      limit: 50, // Internal limit before deduplication
    };

    return this.expertIndex.search(searchOptions);
  }

  /**
   * Normalize query for better search results
   */
  private normalizeQuery(query: string): string {
    return query
      .toLowerCase()
      .trim()
      .replace(/[^\w\s]/g, '') // Remove special characters
      .replace(/\s+/g, ' '); // Normalize whitespace
  }

  /**
   * Remove duplicate matches while preserving highest scored instances
   */
  private deduplicateMatches(matches: ExpertMatch[]): ExpertMatch[] {
    const seen = new Map<string, ExpertMatch>();
    const unique: ExpertMatch[] = [];

    for (const match of matches) {
      const existing = seen.get(match.expertId);

      if (!existing || match.score > existing.score) {
        seen.set(match.expertId, match);
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Score and sort matches by relevance
   */
  private scoreAndSortMatches(
    matches: ExpertMatch[],
    originalQuery: string,
  ): ExpertMatch[] {
    return matches
      .map(match => ({
        ...match,
        finalScore: this.calculateFinalScore(match, originalQuery),
      }))
      .sort((a, b) => b.finalScore - a.finalScore);
  }

  /**
   * Calculate final relevance score
   */
  private calculateFinalScore(match: ExpertMatch, query: string): number {
    let score = match.score;

    // Boost exact prefix matches
    if (match.fieldValue.toLowerCase().startsWith(query)) {
      score += 0.3;
    }

    // Boost shorter matches (more specific)
    if (match.fieldValue.length <= query.length + 5) {
      score += 0.2;
    }

    // Boost name matches over facility matches
    if (match.field === 'name') {
      score += 0.1;
    }

    return Math.min(score, 1);
  }

  /**
   * Format match as typeahead suggestion
   */
  private formatSuggestion(match: ExpertMatch): TypeaheadSuggestion {
    return {
      id: match.expertId,
      text: this.formatSuggestionText(match),
      subtext: this.formatSuggestionSubtext(match),
      type: match.field,
      specialty: match.specialty,
      score: match.finalScore,
    };
  }

  /**
   * Format main suggestion text
   */
  private formatSuggestionText(match: ExpertMatch): string {
    switch (match.field) {
      case 'name':
        return `${match.fieldValue} (${match.specialty})`;
      case 'specialty':
        return match.fieldValue;
      case 'facility':
        return `${match.fieldValue} - ${match.specialty}`;
      default:
        return match.fieldValue;
    }
  }

  /**
   * Format secondary suggestion text
   */
  private formatSuggestionSubtext(match: ExpertMatch): string {
    switch (match.field) {
      case 'name':
        return match.facility;
      case 'specialty':
        return 'Specialty';
      case 'facility':
        return 'Healthcare Facility';
      default:
        return '';
    }
  }
}
```

**Typeahead Features:**
- ✅ **Real-time Performance**: Sub-second response times
- ✅ **Fuzzy Matching**: Approximate string matching for typos
- ✅ **Multi-Field Search**: Search across names, specialties, facilities
- ✅ **Relevance Scoring**: Intelligent ranking of suggestions
- ✅ **Caching Strategy**: Short-term caching for frequent queries
- ✅ **Deduplication**: Remove duplicate suggestions intelligently

### **3. Availability Integration**

```typescript
// Expert availability and scheduling integration
@Injectable()
export class AvailabilityIntegrationService {
  constructor(
    private readonly schedulingApi: SchedulingApiService,
    private readonly calendarService: CalendarService,
  ) {}

  /**
   * Get comprehensive availability information for expert
   */
  async getExpertAvailability(
    expertId: string,
    startDate: string,
    endDate: string,
    preferences: AvailabilityPreferences = {},
  ): Promise<ExpertAvailability> {
    const start = new Date(startDate);
    const end = new Date(endDate);

    // Get different types of availability
    const [inPersonSlots, telemedicineSlots, blockedSlots] = await Promise.all([
      this.getInPersonAvailability(expertId, start, end),
      this.getTelemedicineAvailability(expertId, start, end),
      this.getBlockedTimeSlots(expertId, start, end),
    ]);

    // Filter and combine slots
    const availableSlots = this.combineAndFilterSlots(
      inPersonSlots,
      telemedicineSlots,
      blockedSlots,
      preferences,
    );

    // Find next available slot
    const nextAvailable = this.findNextAvailableSlot(availableSlots, start);

    // Calculate availability statistics
    const stats = this.calculateAvailabilityStats(availableSlots, start, end);

    return {
      expertId,
      timeRange: { start: startDate, end: endDate },
      availableSlots,
      nextAvailable,
      statistics: stats,
      preferences: preferences,
      lastUpdated: new Date().toISOString(),
    };
  }

  /**
   * Get in-person consultation availability
   */
  private async getInPersonAvailability(
    expertId: string,
    start: Date,
    end: Date,
  ): Promise<TimeSlot[]> {
    try {
      const response = await this.schedulingApi.getProviderSchedule(
        expertId,
        start,
        end,
        'in_person',
      );

      return response.availableSlots.map(slot => ({
        startTime: slot.startTime,
        endTime: slot.endTime,
        type: 'in_person' as const,
        location: slot.location,
        duration: slot.duration,
      }));
    } catch (error) {
      this.logger.warn('Failed to get in-person availability', {
        expertId,
        error: error.message,
      });
      return [];
    }
  }

  /**
   * Get telemedicine consultation availability
   */
  private async getTelemedicineAvailability(
    expertId: string,
    start: Date,
    end: Date,
  ): Promise<TimeSlot[]> {
    try {
      const response = await this.schedulingApi.getProviderSchedule(
        expertId,
        start,
        end,
        'telemedicine',
      );

      return response.availableSlots.map(slot => ({
        startTime: slot.startTime,
        endTime: slot.endTime,
        type: 'telemedicine' as const,
        platform: slot.platform,
        duration: slot.duration,
      }));
    } catch (error) {
      this.logger.warn('Failed to get telemedicine availability', {
        expertId,
        error: error.message,
      });
      return [];
    }
  }

  /**
   * Get blocked time slots (vacation, meetings, etc.)
   */
  private async getBlockedTimeSlots(
    expertId: string,
    start: Date,
    end: Date,
  ): Promise<TimeSlot[]> {
    try {
      const blockedTimes = await this.calendarService.getBlockedTimes(
        expertId,
        start,
        end,
      );

      return blockedTimes.map(block => ({
        startTime: block.startTime,
        endTime: block.endTime,
        type: 'blocked' as const,
        reason: block.reason,
      }));
    } catch (error) {
      this.logger.warn('Failed to get blocked time slots', {
        expertId,
        error: error.message,
      });
      return [];
    }
  }

  /**
   * Combine and filter available slots based on preferences
   */
  private combineAndFilterSlots(
    inPersonSlots: TimeSlot[],
    telemedicineSlots: TimeSlot[],
    blockedSlots: TimeSlot[],
    preferences: AvailabilityPreferences,
  ): TimeSlot[] {
    // Start with all potential slots
    let allSlots = [...inPersonSlots, ...telemedicineSlots];

    // Remove blocked times
    allSlots = this.removeBlockedSlots(allSlots, blockedSlots);

    // Apply consultation type preferences
    if (preferences.consultationType === 'in_person') {
      allSlots = allSlots.filter(slot => slot.type === 'in_person');
    } else if (preferences.consultationType === 'telemedicine') {
      allSlots = allSlots.filter(slot => slot.type === 'telemedicine');
    }

    // Apply duration preferences
    if (preferences.minDuration) {
      allSlots = allSlots.filter(slot =>
        slot.duration >= preferences.minDuration!
      );
    }

    // Apply time preferences
    if (preferences.preferredTimes) {
      allSlots = this.filterByPreferredTimes(allSlots, preferences.preferredTimes);
    }

    // Sort by start time
    return allSlots.sort((a, b) =>
      new Date(a.startTime).getTime() - new Date(b.startTime).getTime()
    );
  }

  /**
   * Remove slots that conflict with blocked times
   */
  private removeBlockedSlots(
    availableSlots: TimeSlot[],
    blockedSlots: TimeSlot[],
  ): TimeSlot[] {
    return availableSlots.filter(slot => {
      const slotStart = new Date(slot.startTime);
      const slotEnd = new Date(slot.endTime);

      // Check if slot overlaps with any blocked time
      return !blockedSlots.some(blocked => {
        const blockedStart = new Date(blocked.startTime);
        const blockedEnd = new Date(blocked.endTime);

        return slotStart < blockedEnd && slotEnd > blockedStart;
      });
    });
  }

  /**
   * Filter slots by preferred time ranges
   */
  private filterByPreferredTimes(
    slots: TimeSlot[],
    preferredTimes: TimePreference[],
  ): TimeSlot[] {
    return slots.filter(slot => {
      const slotTime = new Date(slot.startTime);
      const slotHour = slotTime.getHours();

      return preferredTimes.some(pref => {
        if (pref.dayOfWeek !== undefined &&
            slotTime.getDay() !== pref.dayOfWeek) {
          return false;
        }

        return slotHour >= pref.startHour && slotHour <= pref.endHour;
      });
    });
  }

  /**
   * Find next available slot from given time
   */
  private findNextAvailableSlot(
    slots: TimeSlot[],
    fromTime: Date,
  ): TimeSlot | null {
    const futureSlots = slots.filter(slot =>
      new Date(slot.startTime) > fromTime
    );

    if (futureSlots.length === 0) return null;

    return futureSlots.reduce((earliest, current) =>
      new Date(current.startTime) < new Date(earliest.startTime) ? current : earliest
    );
  }

  /**
   * Calculate availability statistics
   */
  private calculateAvailabilityStats(
    slots: TimeSlot[],
    startDate: Date,
    endDate: Date,
  ): AvailabilityStatistics {
    const totalDays = Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));

    const inPersonSlots = slots.filter(slot => slot.type === 'in_person');
    const telemedicineSlots = slots.filter(slot => slot.type === 'telemedicine');

    const slotsByDay = this.groupSlotsByDay(slots);

    return {
      totalSlots: slots.length,
      inPersonSlots: inPersonSlots.length,
      telemedicineSlots: telemedicineSlots.length,
      averageSlotsPerDay: slots.length / totalDays,
      daysWithAvailability: Object.keys(slotsByDay).length,
      totalDays: totalDays,
      utilizationRate: this.calculateUtilizationRate(slots, startDate, endDate),
    };
  }

  /**
   * Group slots by day for statistical analysis
   */
  private groupSlotsByDay(slots: TimeSlot[]): Record<string, TimeSlot[]> {
    const grouped: Record<string, TimeSlot[]> = {};

    slots.forEach(slot => {
      const dayKey = new Date(slot.startTime).toDateString();

      if (!grouped[dayKey]) {
        grouped[dayKey] = [];
      }

      grouped[dayKey].push(slot);
    });

    return grouped;
  }

  /**
   * Calculate utilization rate (available vs total possible time)
   */
  private calculateUtilizationRate(
    slots: TimeSlot[],
    startDate: Date,
    endDate: Date,
  ): number {
    const totalPossibleMinutes = (endDate.getTime() - startDate.getTime()) / (1000 * 60);
    const totalAvailableMinutes = slots.reduce(
      (total, slot) => total + slot.duration,
      0,
    );

    return Math.min(totalAvailableMinutes / totalPossibleMinutes, 1);
  }
}
```

**Availability Features:**
- ✅ **Multi-Modal Support**: In-person and telemedicine availability
- ✅ **Conflict Resolution**: Automatic blocking of unavailable times
- ✅ **Preference Filtering**: User-defined availability preferences
- ✅ **Statistical Analysis**: Comprehensive availability metrics
- ✅ **Intelligent Scheduling**: Next available slot detection
- ✅ **Cross-System Integration**: Multiple scheduling system support

---

## 📊 **Performance & Monitoring**

### **1. FAE Performance Metrics**

```typescript
// Performance monitoring for FAE operations
@Injectable()
export class FaePerformanceMonitor {
  constructor(private readonly metrics: MetricsService) {}

  // Track expert search performance
  async trackExpertSearch(
    duration: number,
    resultCount: number,
    hasFilters: boolean,
    cacheHit: boolean,
  ): Promise<void> {
    this.metrics.histogram('fae_expert_search_duration', duration, {
      hasFilters: hasFilters.toString(),
      cacheHit: cacheHit.toString(),
    });

    this.metrics.increment('fae_expert_search_count');
    this.metrics.gauge('fae_search_results_count', resultCount);

    // Alert on slow searches
    if (duration > 5000) { // More than 5 seconds
      this.logger.warn('Slow expert search', {
        duration,
        resultCount,
        hasFilters,
        cacheHit,
      });
    }
  }

  // Track typeahead search performance
  async trackTypeaheadSearch(
    queryLength: number,
    resultCount: number,
    duration: number,
    cacheHit: boolean,
  ): Promise<void> {
    this.metrics.histogram('fae_typeahead_duration', duration, {
      queryLength: queryLength.toString(),
      cacheHit: cacheHit.toString(),
    });

    this.metrics.increment('fae_typeahead_count');
    this.metrics.gauge('fae_typeahead_results', resultCount);

    // Alert on slow typeahead
    if (duration > 1000) { // More than 1 second
      this.logger.warn('Slow typeahead search', {
        queryLength,
        resultCount,
        duration,
      });
    }
  }

  // Track availability check performance
  async trackAvailabilityCheck(
    expertId: string,
    duration: number,
    slotCount: number,
    success: boolean,
  ): Promise<void> {
    this.metrics.histogram('fae_availability_check_duration', duration, {
      success: success.toString(),
    });

    this.metrics.increment('fae_availability_check_count');
    this.metrics.gauge('fae_availability_slots_found', slotCount);

    // Alert on slow availability checks
    if (duration > 3000) { // More than 3 seconds
      this.logger.warn('Slow availability check', {
        expertId,
        duration,
        slotCount,
      });
    }
  }

  // Track consultation request performance
  async trackConsultationRequest(
    duration: number,
    success: boolean,
    urgency: string,
    messageLength: number,
  ): Promise<void> {
    this.metrics.histogram('fae_consultation_request_duration', duration, {
      success: success.toString(),
      urgency,
    });

    this.metrics.increment('fae_consultation_request_count');
    this.metrics.histogram('fae_consultation_message_length', messageLength);

    // Alert on failed requests
    if (!success) {
      this.logger.warn('Consultation request failed', {
        duration,
        urgency,
        messageLength,
      });
    }
  }

  // Track API call performance
  async trackApiCall(
    endpoint: string,
    method: string,
    duration: number,
    statusCode: number,
    responseSize: number,
  ): Promise<void> {
    this.metrics.histogram('fae_api_call_duration', duration, {
      endpoint,
      method,
      statusCode: statusCode.toString(),
    });

    this.metrics.histogram('fae_api_response_size', responseSize);

    // Alert on API errors
    if (statusCode >= 400) {
      this.logger.warn('FAE API error', {
        endpoint,
        method,
        statusCode,
        duration,
      });
    }
  }

  // Monitor search quality metrics
  async trackSearchQuality(
    query: string,
    resultCount: number,
    userClicked: boolean,
    timeToClick?: number,
  ): Promise<void> {
    this.metrics.increment('fae_search_query_count');
    this.metrics.gauge('fae_search_result_count', resultCount);

    if (userClicked) {
      this.metrics.increment('fae_search_click_count');
      if (timeToClick) {
        this.metrics.histogram('fae_time_to_click', timeToClick);
      }
    }

    // Track search effectiveness
    const effectiveness = userClicked ? 1 : 0;
    this.metrics.gauge('fae_search_effectiveness', effectiveness, {
      resultCount: resultCount.toString(),
    });
  }
}
```

### **2. Health Monitoring**

```typescript
// Health monitoring for FAE system
@Injectable()
export class FaeHealthMonitor {
  constructor(
    private readonly httpService: HttpService,
    @Inject(faeConfig.KEY)
    private readonly config: ConfigType<typeof faeConfig>,
  ) {}

  // Comprehensive health check
  async performHealthCheck(): Promise<HealthCheckResult> {
    const checks = await Promise.all([
      this.checkExpertSearchApi(),
      this.checkTypeaheadApi(),
      this.checkAvailabilityApi(),
      this.checkExpertDatabase(),
      this.checkGeographicService(),
    ]);

    const overallStatus = this.calculateOverallStatus(checks);

    return {
      status: overallStatus,
      checks,
      recommendations: this.generateRecommendations(checks),
    };
  }

  // Expert search API health check
  private async checkExpertSearchApi(): Promise<HealthCheck> {
    try {
      const startTime = Date.now();

      // Test with a simple search query
      const response = await this.httpService.post(
        `${this.config.apiUrl}/experts/search`,
        { specialty: 'cardiology', limit: 1 },
        { timeout: 5000 },
      );

      const duration = Date.now() - startTime;

      if (response.data?.experts && Array.isArray(response.data.experts)) {
        return {
          name: 'Expert Search API',
          status: 'healthy',
          responseTime: duration,
          message: 'Expert search API is operational',
        };
      } else {
        return {
          name: 'Expert Search API',
          status: 'degraded',
          responseTime: duration,
          message: 'Expert search API returned unexpected response format',
        };
      }
    } catch (error) {
      return {
        name: 'Expert Search API',
        status: 'unhealthy',
        message: `Expert search API error: ${error.message}`,
      };
    }
  }

  // Typeahead API health check
  private async checkTypeaheadApi(): Promise<HealthCheck> {
    try {
      const startTime = Date.now();

      // Test typeahead with a simple query
      const response = await this.httpService.post(
        `${this.config.apiUrl}/experts/typeahead`,
        { query: 'car', limit: 5 },
        { timeout: 2000 },
      );

      const duration = Date.now() - startTime;

      return {
        name: 'Typeahead API',
        status: 'healthy',
        responseTime: duration,
        message: 'Typeahead API is operational',
      };
    } catch (error) {
      return {
        name: 'Typeahead API',
        status: 'unhealthy',
        message: `Typeahead API error: ${error.message}`,
      };
    }
  }

  // Availability API health check
  private async checkAvailabilityApi(): Promise<HealthCheck> {
    try {
      const startTime = Date.now();

      // Test availability check with mock data
      const testExpertId = 'test-expert-id';
      const response = await this.httpService.post(
        `${this.config.apiUrl}/experts/${testExpertId}/availability`,
        {
          startDate: new Date().toISOString().split('T')[0],
          endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        },
        { timeout: 3000 },
      );

      const duration = Date.now() - startTime;

      return {
        name: 'Availability API',
        status: 'healthy',
        responseTime: duration,
        message: 'Availability API is operational',
      };
    } catch (error) {
      // Availability API might return 404 for test expert, which is OK
      if (error.response?.status === 404) {
        return {
          name: 'Availability API',
          status: 'healthy',
          message: 'Availability API responded correctly (test expert not found)',
        };
      }

      return {
        name: 'Availability API',
        status: 'unhealthy',
        message: `Availability API error: ${error.message}`,
      };
    }
  }

  // Expert database health check
  private async checkExpertDatabase(): Promise<HealthCheck> {
    try {
      // Test database connectivity by checking expert count
      const expertCount = await this.expertRepository.count({
        where: { active: true },
      });

      return {
        name: 'Expert Database',
        status: 'healthy',
        message: `Expert database healthy (${expertCount} active experts)`,
      };
    } catch (error) {
      return {
        name: 'Expert Database',
        status: 'unhealthy',
        message: `Expert database error: ${error.message}`,
      };
    }
  }

  // Geographic service health check
  private async checkGeographicService(): Promise<HealthCheck> {
    try {
      // Test geocoding with a known location
      const testLocation = 'Rochester, MN';
      const coordinates = await this.geographicService.geocodeLocation(testLocation);

      if (coordinates && coordinates.latitude && coordinates.longitude) {
        return {
          name: 'Geographic Service',
          status: 'healthy',
          message: 'Geographic service is operational',
        };
      } else {
        return {
          name: 'Geographic Service',
          status: 'degraded',
          message: 'Geographic service returned invalid coordinates',
        };
      }
    } catch (error) {
      return {
        name: 'Geographic Service',
        status: 'unhealthy',
        message: `Geographic service error: ${error.message}`,
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

  // Generate recommendations
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
// File: src/controllers/fae/fae.service.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { FaeService } from './fae.service';
import { Expert } from './entities/expert.entity';
import faeConfig from '@app/common/config/fae.config';

describe('FaeService', () => {
  let service: FaeService;
  let expertRepository: Repository<Expert>;

  const mockRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    count: jest.fn(),
  };

  const mockConfig = {
    apiUrl: 'https://api.test.com/fae',
    timeout: 30000,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FaeService,
        {
          provide: getRepositoryToken(Expert),
          useValue: mockRepository,
        },
        {
          provide: faeConfig.KEY,
          useValue: mockConfig,
        },
      ],
    }).compile();

    service = module.get<FaeService>(FaeService);
    expertRepository = module.get<Repository<Expert>>(
      getRepositoryToken(Expert),
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('searchExperts', () => {
    it('should return formatted expert search results', async () => {
      const mockUser = {
        lanId: 'test-user',
        entraUser: { unique_name: 'test@example.com' },
      };

      const searchRequest = {
        specialty: 'cardiology',
        location: 'Rochester, MN',
        limit: 10,
      };

      const mockExperts = [
        {
          id: 'exp1',
          name: 'Dr. John Smith',
          specialty: 'Cardiology',
          facility: 'Mayo Clinic',
          rating: 4.8,
        },
      ];

      // Mock HTTP service call
      jest.spyOn(service['httpService'], 'post').mockResolvedValue({
        data: { experts: mockExperts, totalCount: 1 },
      });

      const result = await service.searchExperts(mockUser, searchRequest);

      expect(result.experts).toHaveLength(1);
      expect(result.experts[0]).toHaveProperty('id', 'exp1');
      expect(result.experts[0]).toHaveProperty('name', 'Dr. John Smith');
      expect(result.totalCount).toBe(1);
    });

    it('should handle API errors gracefully', async () => {
      const mockUser = { lanId: 'test-user' };
      const searchRequest = { specialty: 'cardiology' };

      jest.spyOn(service['httpService'], 'post').mockRejectedValue(
        new Error('API unavailable'),
      );

      await expect(
        service.searchExperts(mockUser, searchRequest),
      ).rejects.toThrow('Expert search failed');
    });

    it('should validate required search parameters', async () => {
      const mockUser = { lanId: 'test-user' };
      const invalidRequest = {}; // No specialty or searchTerm

      await expect(
        service.searchExperts(mockUser, invalidRequest as any),
      ).rejects.toThrow('Either specialty or searchTerm must be provided');
    });
  });

  describe('typeaheadSearch', () => {
    it('should return typeahead suggestions', async () => {
      const mockUser = { lanId: 'test-user' };
      const typeaheadRequest = {
        query: 'card',
        specialty: 'cardiology',
        limit: 5,
      };

      const mockSuggestions = [
        {
          id: 'exp1',
          text: 'Dr. John Smith (Cardiology)',
          type: 'name',
        },
      ];

      jest.spyOn(service['httpService'], 'get').mockResolvedValue({
        data: { suggestions: mockSuggestions, totalSuggestions: 1 },
      });

      const result = await service.typeaheadSearch(mockUser, typeaheadRequest);

      expect(result.suggestions).toHaveLength(1);
      expect(result.suggestions[0]).toHaveProperty('id', 'exp1');
      expect(result.query).toBe('card');
    });

    it('should validate query length', async () => {
      const mockUser = { lanId: 'test-user' };
      const invalidRequest = {
        query: 'c', // Too short
        limit: 5,
      };

      await expect(
        service.typeaheadSearch(mockUser, invalidRequest),
      ).rejects.toThrow('Query must be at least 2 characters long');
    });
  });

  describe('checkAvailability', () => {
    it('should return expert availability information', async () => {
      const mockUser = { lanId: 'test-user' };
      const availabilityRequest = {
        expertId: 'exp1',
        startDate: '2024-01-15',
        endDate: '2024-01-22',
      };

      const mockAvailability = {
        availableSlots: [
          {
            startTime: '2024-01-15T09:00:00Z',
            endTime: '2024-01-15T10:00:00Z',
            type: 'in_person',
          },
        ],
        nextAvailable: '2024-01-15T09:00:00Z',
      };

      jest.spyOn(service['httpService'], 'post').mockResolvedValue({
        data: mockAvailability,
      });

      const result = await service.checkAvailability(mockUser, availabilityRequest);

      expect(result.expertId).toBe('exp1');
      expect(result.availableSlots).toHaveLength(1);
      expect(result.nextAvailable).toBe('2024-01-15T09:00:00Z');
    });

    it('should validate date range', async () => {
      const mockUser = { lanId: 'test-user' };
      const invalidRequest = {
        expertId: 'exp1',
        startDate: '2024-01-22',
        endDate: '2024-01-15', // End before start
      };

      await expect(
        service.checkAvailability(mockUser, invalidRequest),
      ).rejects.toThrow('Start date must be before end date');
    });

    it('should enforce date range limits', async () => {
      const mockUser = { lanId: 'test-user' };
      const invalidRequest = {
        expertId: 'exp1',
        startDate: '2024-01-01',
        endDate: '2024-03-01', // More than 90 days
      };

      await expect(
        service.checkAvailability(mockUser, invalidRequest),
      ).rejects.toThrow('Date range cannot exceed 90 days');
    });
  });

  describe('getExpertDetails', () => {
    it('should return expert details', async () => {
      const mockUser = { lanId: 'test-user' };
      const detailsRequest = { expertId: 'exp1' };

      const mockExpertDetails = {
        id: 'exp1',
        name: 'Dr. John Smith',
        specialty: 'Cardiology',
        email: 'john.smith@mayo.edu',
        phone: '+1-507-123-4567',
        bio: 'Board-certified cardiologist with 15 years of experience',
      };

      jest.spyOn(service['httpService'], 'get').mockResolvedValue({
        data: mockExpertDetails,
      });

      const result = await service.getExpertDetails(mockUser, detailsRequest);

      expect(result.expert.id).toBe('exp1');
      expect(result.expert.name).toBe('Dr. John Smith');
      expect(result.expert.specialty).toBe('Cardiology');
    });

    it('should handle expert not found', async () => {
      const mockUser = { lanId: 'test-user' };
      const detailsRequest = { expertId: 'non-existent' };

      jest.spyOn(service['httpService'], 'get').mockRejectedValue({
        response: { status: 404 },
      });

      await expect(
        service.getExpertDetails(mockUser, detailsRequest),
      ).rejects.toThrow('Expert not found: non-existent');
    });
  });

  describe('sendConsultationRequest', () => {
    it('should send consultation request successfully', async () => {
      const mockUser = {
        lanId: 'test-user',
        name: 'Dr. Jane Doe',
        email: 'jane.doe@hospital.org',
      };

      const mailRequest = {
        expertId: 'exp1',
        patientId: 'pat123',
        message: 'Patient needs cardiology consultation',
        urgency: 'urgent',
      };

      // Mock expert details
      jest.spyOn(service, 'getExpertDetails').mockResolvedValue({
        expert: {
          id: 'exp1',
          name: 'Dr. John Smith',
          email: 'john.smith@mayo.edu',
        },
      });

      // Mock email sending
      jest.spyOn(service['httpService'], 'post').mockResolvedValue({
        data: { messageId: 'msg123', deliveredAt: new Date().toISOString() },
      });

      const result = await service.sendConsultationRequest(mockUser, mailRequest);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg123');
      expect(result.expertNotified).toBe(true);
    });

    it('should validate required fields', async () => {
      const mockUser = { lanId: 'test-user' };
      const invalidRequest = {
        expertId: 'exp1',
        patientId: 'pat123',
        message: '', // Empty message
      };

      await expect(
        service.sendConsultationRequest(mockUser, invalidRequest),
      ).rejects.toThrow('Message cannot be empty');
    });

    it('should handle email sending failures', async () => {
      const mockUser = { lanId: 'test-user' };
      const mailRequest = {
        expertId: 'exp1',
        patientId: 'pat123',
        message: 'Test message',
      };

      jest.spyOn(service, 'getExpertDetails').mockResolvedValue({
        expert: { id: 'exp1', name: 'Dr. Smith', email: 'smith@mayo.edu' },
      });

      jest.spyOn(service['httpService'], 'post').mockRejectedValue(
        new Error('Email service unavailable'),
      );

      await expect(
        service.sendConsultationRequest(mockUser, mailRequest),
      ).rejects.toThrow('Failed to send consultation request');
    });
  });
});
```

### **2. Integration Tests**

```typescript
// File: test/e2e/fae.e2e.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('FAE (e2e)', () => {
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

  describe('POST /clinical-experts/search', () => {
    it('should search for experts successfully', async () => {
      const searchRequest = {
        specialty: 'cardiology',
        location: 'Rochester, MN',
        limit: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('experts');
      expect(response.body).toHaveProperty('totalCount');
      expect(response.body).toHaveProperty('searchTerm');
      expect(Array.isArray(response.body.experts)).toBe(true);
    });

    it('should validate required search parameters', async () => {
      const invalidRequest = {
        location: 'Rochester, MN',
        // Missing specialty and searchTerm
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body.message).toContain('Either specialty or searchTerm must be provided');
    });

    it('should handle search with free text', async () => {
      const searchRequest = {
        searchTerm: 'heart specialist',
        limit: 5,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(200);

      expect(response.body).toHaveProperty('experts');
      expect(response.body.searchTerm).toBe('heart specialist');
    });

    it('should apply geographic filtering', async () => {
      const searchRequest = {
        specialty: 'cardiology',
        location: 'Rochester, MN',
        radius: 50,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(200);

      // Verify geographic filtering is applied
      expect(response.body).toHaveProperty('experts');
    });
  });

  describe('POST /clinical-experts/typeahead', () => {
    it('should return typeahead suggestions', async () => {
      const typeaheadRequest = {
        query: 'card',
        specialty: 'cardiology',
        limit: 5,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/typeahead')
        .set('Authorization', 'Bearer mock-token')
        .send(typeaheadRequest)
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('suggestions');
      expect(response.body).toHaveProperty('query', 'card');
      expect(Array.isArray(response.body.suggestions)).toBe(true);
    });

    it('should validate query length', async () => {
      const invalidRequest = {
        query: 'c', // Too short
        limit: 5,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/typeahead')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body.message).toContain('Query must be at least 2 characters long');
    });

    it('should handle typeahead without specialty filter', async () => {
      const typeaheadRequest = {
        query: 'john',
        limit: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/typeahead')
        .set('Authorization', 'Bearer mock-token')
        .send(typeaheadRequest)
        .expect(200);

      expect(response.body).toHaveProperty('suggestions');
      expect(response.body.query).toBe('john');
    });
  });

  describe('POST /clinical-experts/availability', () => {
    it('should check expert availability', async () => {
      const availabilityRequest = {
        expertId: 'exp123',
        startDate: '2024-01-15',
        endDate: '2024-01-22',
        consultationType: 'both',
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/availability')
        .set('Authorization', 'Bearer mock-token')
        .send(availabilityRequest)
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('expertId', 'exp123');
      expect(response.body).toHaveProperty('availableSlots');
      expect(response.body).toHaveProperty('timeRange');
      expect(Array.isArray(response.body.availableSlots)).toBe(true);
    });

    it('should validate date range', async () => {
      const invalidRequest = {
        expertId: 'exp123',
        startDate: '2024-01-22',
        endDate: '2024-01-15', // End before start
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/availability')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body.message).toContain('Start date must be before end date');
    });

    it('should validate required fields', async () => {
      const invalidRequest = {
        startDate: '2024-01-15',
        endDate: '2024-01-22',
        // Missing expertId
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/availability')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body.message).toContain('Expert ID is required');
    });

    it('should enforce date range limits', async () => {
      const invalidRequest = {
        expertId: 'exp123',
        startDate: '2024-01-01',
        endDate: '2024-04-01', // More than 90 days
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/availability')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify date range limit
      expect(response.body.message).toContain('Date range cannot exceed 90 days');
    });
  });

  describe('POST /clinical-experts/details', () => {
    it('should return expert details', async () => {
      const detailsRequest = {
        expertId: 'exp123',
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/details')
        .set('Authorization', 'Bearer mock-token')
        .send(detailsRequest)
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('expert');
      expect(response.body.expert).toHaveProperty('id', 'exp123');
    });

    it('should validate expert ID requirement', async () => {
      const invalidRequest = {
        // Missing expertId
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/details')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body.message).toContain('Expert ID is required');
    });
  });

  describe('POST /clinical-experts/contact', () => {
    it('should send consultation request', async () => {
      const contactRequest = {
        expertId: 'exp123',
        patientId: 'pat456',
        message: 'Patient requires cardiology consultation for chest pain evaluation',
        urgency: 'urgent',
        clinicalContext: 'Recent EKG shows ST elevation, troponin elevated',
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/contact')
        .set('Authorization', 'Bearer mock-token')
        .send(contactRequest)
        .expect(200);

      // Verify response structure
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('messageId');
      expect(response.body).toHaveProperty('expertNotified', true);
    });

    it('should validate required fields', async () => {
      const invalidRequest = {
        expertId: 'exp123',
        patientId: 'pat456',
        message: '', // Empty message
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/contact')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify validation error
      expect(response.body.message).toContain('Message cannot be empty');
    });

    it('should validate message length', async () => {
      const longMessage = 'a'.repeat(2001); // Exceeds 2000 character limit

      const invalidRequest = {
        expertId: 'exp123',
        patientId: 'pat456',
        message: longMessage,
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/contact')
        .set('Authorization', 'Bearer mock-token')
        .send(invalidRequest)
        .expect(400);

      // Verify message length validation
      expect(response.body.message).toContain('cannot exceed 2000 characters');
    });
  });

  describe('Security Tests', () => {
    it('should require authentication', async () => {
      const searchRequest = {
        specialty: 'cardiology',
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .send(searchRequest)
        .expect(401);

      // Verify authentication requirement
      expect(response.body).toHaveProperty('statusCode', 401);
    });

    it('should validate input sanitization', async () => {
      const maliciousRequest = {
        specialty: 'cardiology',
        searchTerm: '<script>alert("xss")</script>',
      };

      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(maliciousRequest)
        .expect(200);

      // Should handle potentially malicious input safely
      expect(response.status).toBe(200);
    });
  });

  describe('Performance Tests', () => {
    it('should respond to expert search within acceptable time', async () => {
      const searchRequest = {
        specialty: 'cardiology',
        limit: 10,
      };

      const startTime = Date.now();

      await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(200);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Expert search should complete within 5 seconds
      expect(duration).toBeLessThan(5000);
    });

    it('should handle typeahead requests quickly', async () => {
      const typeaheadRequest = {
        query: 'card',
        limit: 10,
      };

      const startTime = Date.now();

      await request(app.getHttpServer())
        .post('/clinical-experts/typeahead')
        .set('Authorization', 'Bearer mock-token')
        .send(typeaheadRequest)
        .expect(200);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Typeahead should be very fast (< 1 second)
      expect(duration).toBeLessThan(1000);
    });

    it('should handle concurrent expert searches', async () => {
      const searchRequest = {
        specialty: 'cardiology',
        limit: 5,
      };

      const requests = Array(5).fill().map(() =>
        request(app.getHttpServer())
          .post('/clinical-experts/search')
          .set('Authorization', 'Bearer mock-token')
          .send(searchRequest)
          .expect(200)
      );

      const responses = await Promise.all(requests);

      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('experts');
      });
    });
  });

  describe('Error Handling Tests', () => {
    it('should handle API unavailability gracefully', async () => {
      const searchRequest = {
        specialty: 'cardiology',
      };

      // This test would require mocking API unavailability
      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(400);

      // Should provide meaningful error message
      expect(response.body).toHaveProperty('message');
    });

    it('should handle malformed responses', async () => {
      const searchRequest = {
        specialty: 'cardiology',
      };

      // This test would require mocking malformed API responses
      const response = await request(app.getHttpServer())
        .post('/clinical-experts/search')
        .set('Authorization', 'Bearer mock-token')
        .send(searchRequest)
        .expect(500);

      // Should handle malformed responses gracefully
      expect(response.body).toHaveProperty('statusCode', 500);
    });
  });
});
```

---

## 🎯 **Usage Examples**

### **1. Expert Search and Discovery**

```typescript
// Healthcare provider searches for cardiology specialists
const searchCriteria = {
  specialty: 'cardiology',
  location: 'Rochester, MN',
  radius: 50,
  telemedicineEnabled: true,
  limit: 20,
};

const searchResults = await api.post('/clinical-experts/search', searchCriteria);
// Returns ranked list of cardiologists with availability and ratings
```

### **2. Real-time Typeahead Search**

```typescript
// Real-time expert discovery as user types
const typeaheadQuery = {
  query: 'john', // Partial name
  specialty: 'neurology', // Optional specialty filter
  limit: 8,
};

const suggestions = await api.post('/clinical-experts/typeahead', typeaheadQuery);
// Returns instant suggestions: "Dr. John Smith (Neurology)", "Dr. Johnny Martinez (Cardiology)", etc.
```

### **3. Availability Checking and Scheduling**

```typescript
// Check expert availability for consultation
const availabilityCheck = {
  expertId: 'exp_12345',
  startDate: '2024-01-15',
  endDate: '2024-01-22',
  consultationType: 'telemedicine',
  durationMinutes: 30,
};

const availability = await api.post('/clinical-experts/availability', availabilityCheck);
// Returns available time slots, next available appointment, and booking options
```

### **4. Expert Profile and Details**

```typescript
// Get comprehensive expert information
const expertDetails = await api.post('/clinical-experts/details', {
  expertId: 'exp_12345',
});
// Returns full profile: credentials, experience, specializations, contact info, reviews
```

### **5. Consultation Request and Communication**

```typescript
// Send consultation request to expert
const consultationRequest = {
  expertId: 'exp_12345',
  patientId: 'pat_67890',
  urgency: 'urgent',
  message: 'Patient presents with acute chest pain, EKG shows STEMI. Please assess urgently for cardiac catheterization.',
  preferredDateTime: '2024-01-15T14:00:00Z',
  clinicalContext: 'Troponin elevated at 15.2 ng/mL, patient stable but symptomatic.',
  requesterContact: 'Dr. Sarah Johnson, ER Physician, ext. 4567',
};

const requestResult = await api.post('/clinical-experts/contact', consultationRequest);
// Sends formatted consultation request via secure email/SMS
```

### **6. Integration with Clinical Workflow**

```typescript
// Complete clinical workflow integration
const patientReferral = {
  patientId: 'pat_67890',
  requiredSpecialty: 'cardiology',
  urgency: 'urgent',
  reason: 'Suspected acute coronary syndrome',
  preferredLocation: 'Rochester, MN',
};

// 1. Search for appropriate specialists
const specialists = await api.post('/clinical-experts/search', {
  specialty: patientReferral.requiredSpecialty,
  location: patientReferral.preferredLocation,
  telemedicineEnabled: true,
});

// 2. Check top specialist availability
const topSpecialist = specialists.experts[0];
const availability = await api.post('/clinical-experts/availability', {
  expertId: topSpecialist.id,
  startDate: new Date().toISOString().split('T')[0],
  endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
});

// 3. Send consultation request
if (availability.availableSlots.length > 0) {
  await api.post('/clinical-experts/contact', {
    expertId: topSpecialist.id,
    patientId: patientReferral.patientId,
    urgency: patientReferral.urgency,
    message: `Patient requires ${patientReferral.requiredSpecialty} consultation for ${patientReferral.reason}`,
  });
}
```

---

## 🎯 **Best Practices & Guidelines**

### **1. Search Optimization**

```typescript
// Expert search optimization best practices
@Injectable()
export class ExpertSearchOptimization {
  // Optimize search queries for better results
  optimizeSearchCriteria(criteria: SearchCriteria): OptimizedSearchCriteria {
    return {
      ...criteria,
      // Normalize specialty names
      specialty: this.normalizeSpecialty(criteria.specialty),

      // Optimize location queries
      location: criteria.location ? this.optimizeLocation(criteria.location) : undefined,

      // Add relevant search terms
      enhancedQuery: this.enhanceSearchQuery(criteria),

      // Determine optimal search strategy
      searchStrategy: this.determineSearchStrategy(criteria),
    };
  }

  // Normalize specialty names for consistent searching
  private normalizeSpecialty(specialty?: string): string | undefined {
    if (!specialty) return undefined;

    const specialtyMappings = {
      'heart': 'cardiology',
      'lung': 'pulmonology',
      'kidney': 'nephrology',
      'brain': 'neurology',
      'mental health': 'psychiatry',
      'cancer': 'oncology',
    };

    return specialtyMappings[specialty.toLowerCase()] || specialty;
  }

  // Optimize location queries
  private optimizeLocation(location: string): OptimizedLocation {
    // Parse and standardize location format
    const parsed = this.parseLocation(location);

    return {
      original: location,
      standardized: this.standardizeLocationFormat(parsed),
      coordinates: parsed.coordinates,
      searchRadius: this.calculateOptimalRadius(parsed),
    };
  }

  // Enhance search queries with synonyms and related terms
  private enhanceSearchQuery(criteria: SearchCriteria): EnhancedQuery {
    const enhancements = {
      baseQuery: criteria.searchTerm || '',
      synonyms: this.findSynonyms(criteria.searchTerm),
      relatedTerms: this.findRelatedTerms(criteria.specialty, criteria.searchTerm),
      medicalAbbreviations: this.expandAbbreviations(criteria.searchTerm),
    };

    return {
      original: criteria.searchTerm || '',
      enhanced: this.combineQueryTerms(enhancements),
      queryType: this.classifyQueryType(criteria),
    };
  }

  // Determine optimal search strategy
  private determineSearchStrategy(criteria: SearchCriteria): SearchStrategy {
    // Specialty-specific search
    if (criteria.specialty && !criteria.searchTerm) {
      return 'specialty_focused';
    }

    // Location-based search
    if (criteria.location && criteria.radius) {
      return 'location_focused';
    }

    // Free-text search
    if (criteria.searchTerm && !criteria.specialty) {
      return 'text_focused';
    }

    // Combined search
    return 'balanced';
  }

  // Find synonyms for medical terms
  private findSynonyms(term?: string): string[] {
    if (!term) return [];

    const synonymMap = {
      'heart doctor': ['cardiologist', 'cardiac specialist'],
      'lung doctor': ['pulmonologist', 'respiratory specialist'],
      'kidney doctor': ['nephrologist', 'renal specialist'],
      'brain doctor': ['neurologist', 'neurospecialist'],
    };

    return synonymMap[term.toLowerCase()] || [];
  }

  // Find related medical terms
  private findRelatedTerms(specialty?: string, term?: string): string[] {
    if (!specialty) return [];

    const relatedTermsMap = {
      cardiology: ['cardiac', 'heart', 'cardiovascular', 'echocardiogram', 'ekg'],
      oncology: ['cancer', 'tumor', 'chemotherapy', 'radiation', 'biopsy'],
      neurology: ['brain', 'nervous system', 'stroke', 'seizure', 'mri'],
    };

    return relatedTermsMap[specialty.toLowerCase()] || [];
  }

  // Expand medical abbreviations
  private expandAbbreviations(text: string): MedicalAbbreviation[] {
    const abbreviations = [
      { abbr: 'MI', full: 'myocardial infarction', context: 'cardiology' },
      { abbr: 'COPD', full: 'chronic obstructive pulmonary disease', context: 'pulmonology' },
      { abbr: 'DM', full: 'diabetes mellitus', context: 'endocrinology' },
      { abbr: 'HTN', full: 'hypertension', context: 'cardiology' },
    ];

    return abbreviations.filter(abbr =>
      text.toLowerCase().includes(abbr.abbr.toLowerCase())
    );
  }

  private combineQueryTerms(enhancements: any): string {
    const terms = [
      enhancements.baseQuery,
      ...enhancements.synonyms,
      ...enhancements.relatedTerms,
      ...enhancements.medicalAbbreviations.map((abbr: any) => abbr.full),
    ];

    return [...new Set(terms)].join(' ');
  }

  private classifyQueryType(criteria: SearchCriteria): QueryType {
    if (criteria.specialty && criteria.searchTerm) return 'specialty_and_text';
    if (criteria.specialty) return 'specialty_only';
    if (criteria.searchTerm) return 'text_only';
    if (criteria.location) return 'location_based';

    return 'general';
  }
}
```

### **2. Availability Management**

```typescript
// Expert availability management best practices
@Injectable()
export class ExpertAvailabilityManagement {
  // Intelligent availability analysis
  analyzeExpertAvailability(
    expertId: string,
    timeRange: TimeRange,
    preferences: AvailabilityPreferences,
  ): AvailabilityAnalysis {
    return {
      expertId,
      timeRange,
      analysis: {
        availabilityScore: this.calculateAvailabilityScore(expertId, timeRange),
        bookingPatterns: this.analyzeBookingPatterns(expertId),
        optimalBookingTimes: this.findOptimalBookingTimes(expertId, timeRange),
        constraints: this.identifySchedulingConstraints(expertId),
      },
      recommendations: this.generateAvailabilityRecommendations(expertId, preferences),
    };
  }

  // Calculate availability score (0-100)
  private calculateAvailabilityScore(expertId: string, timeRange: TimeRange): number {
    const totalSlots = this.getTotalAvailableSlots(expertId, timeRange);
    const bookedSlots = this.getBookedSlots(expertId, timeRange);
    const totalPossibleSlots = this.calculateTotalPossibleSlots(timeRange);

    if (totalPossibleSlots === 0) return 0;

    const availabilityRatio = (totalSlots - bookedSlots) / totalPossibleSlots;
    return Math.min(100, Math.max(0, Math.round(availabilityRatio * 100)));
  }

  // Analyze booking patterns
  private analyzeBookingPatterns(expertId: string): BookingPatterns {
    const recentBookings = this.getRecentBookings(expertId, 30); // Last 30 days

    return {
      peakHours: this.identifyPeakHours(recentBookings),
      popularDays: this.identifyPopularDays(recentBookings),
      averageBookingLeadTime: this.calculateAverageLeadTime(recentBookings),
      cancellationRate: this.calculateCancellationRate(recentBookings),
      noShowRate: this.calculateNoShowRate(recentBookings),
    };
  }

  // Find optimal booking times
  private findOptimalBookingTimes(
    expertId: string,
    timeRange: TimeRange,
  ): OptimalBookingTime[] {
    const availabilityData = this.getDetailedAvailability(expertId, timeRange);

    return availabilityData
      .filter(slot => slot.availability > 0.5) // More than 50% available
      .sort((a, b) => b.availability - a.availability)
      .slice(0, 5) // Top 5 optimal times
      .map(slot => ({
        dateTime: slot.dateTime,
        availability: slot.availability,
        competitionLevel: this.calculateCompetitionLevel(slot),
        recommendationScore: this.calculateRecommendationScore(slot),
      }));
  }

  // Identify scheduling constraints
  private identifySchedulingConstraints(expertId: string): SchedulingConstraint[] {
    const constraints: SchedulingConstraint[] = [];
    const expertSchedule = this.getExpertSchedule(expertId);

    // Check for blocked time periods
    if (expertSchedule.blockedPeriods?.length > 0) {
      constraints.push({
        type: 'blocked_periods',
        description: 'Expert has blocked time periods',
        details: expertSchedule.blockedPeriods,
      });
    }

    // Check for specialty-specific constraints
    const specialtyConstraints = this.getSpecialtyConstraints(expertSchedule.specialty);
    if (specialtyConstraints.length > 0) {
      constraints.push({
        type: 'specialty_constraints',
        description: 'Specialty-specific scheduling requirements',
        details: specialtyConstraints,
      });
    }

    // Check for emergency availability
    if (!expertSchedule.emergencyAvailable) {
      constraints.push({
        type: 'emergency_availability',
        description: 'Limited emergency consultation availability',
        details: ['Emergency consultations may have extended wait times'],
      });
    }

    return constraints;
  }

  // Generate availability recommendations
  private generateAvailabilityRecommendations(
    expertId: string,
    preferences: AvailabilityPreferences,
  ): AvailabilityRecommendation[] {
    const recommendations: AvailabilityRecommendation[] = [];
    const analysis = this.analyzeExpertAvailability(expertId, preferences.timeRange, preferences);

    // Time preference recommendations
    if (preferences.preferredTimes) {
      const bestMatches = this.findBestTimeMatches(analysis, preferences.preferredTimes);
      if (bestMatches.length > 0) {
        recommendations.push({
          type: 'time_preference',
          priority: 'high',
          title: 'Consider adjusting your preferred times',
          description: `Based on this expert's schedule, these times may work better: ${bestMatches.join(', ')}`,
        });
      }
    }

    // Urgency-based recommendations
    if (preferences.urgency === 'urgent') {
      recommendations.push({
        type: 'urgency_consideration',
        priority: 'high',
        title: 'Urgent consultation requested',
        description: 'Consider telemedicine options for faster availability',
      });
    }

    // Location-based recommendations
    if (preferences.location && analysis.distance > 50) {
      recommendations.push({
        type: 'location_consideration',
        priority: 'medium',
        title: 'Consider telemedicine',
        description: 'Expert is located far from preferred location. Telemedicine may be more convenient.',
      });
    }

    return recommendations;
  }

  // Helper methods (implementations would depend on actual data sources)
  private getTotalAvailableSlots(expertId: string, timeRange: TimeRange): number {
    // Implementation would query scheduling system
    return 20; // Placeholder
  }

  private getBookedSlots(expertId: string, timeRange: TimeRange): number {
    // Implementation would query appointment system
    return 8; // Placeholder
  }

  private calculateTotalPossibleSlots(timeRange: TimeRange): number {
    // Calculate based on working hours and time range
    const days = Math.ceil((timeRange.end.getTime() - timeRange.start.getTime()) / (1000 * 60 * 60 * 24));
    const workingHoursPerDay = 8; // Assume 8-hour workdays
    const slotsPerHour = 2; // Assume 30-minute slots

    return days * workingHoursPerDay * slotsPerHour;
  }

  private getRecentBookings(expertId: string, days: number): Booking[] {
    // Implementation would query booking history
    return []; // Placeholder
  }

  private identifyPeakHours(bookings: Booking[]): TimeRange[] {
    // Analyze booking data to find peak hours
    return []; // Placeholder
  }

  private identifyPopularDays(bookings: Booking[]): string[] {
    // Analyze booking data to find popular days
    return []; // Placeholder
  }

  private calculateAverageLeadTime(bookings: Booking[]): number {
    // Calculate average time between booking request and appointment
    return 0; // Placeholder
  }

  private calculateCancellationRate(bookings: Booking[]): number {
    // Calculate percentage of cancelled appointments
    return 0; // Placeholder
  }

  private calculateNoShowRate(bookings: Booking[]): number {
    // Calculate percentage of no-show appointments
    return 0; // Placeholder
  }

  private getDetailedAvailability(expertId: string, timeRange: TimeRange): AvailabilitySlot[] {
    // Get detailed availability data
    return []; // Placeholder
  }

  private calculateCompetitionLevel(slot: AvailabilitySlot): CompetitionLevel {
    // Calculate how competitive this time slot is
    return 'low'; // Placeholder
  }

  private calculateRecommendationScore(slot: AvailabilitySlot): number {
    // Calculate overall recommendation score
    return 0; // Placeholder
  }

  private getExpertSchedule(expertId: string): ExpertSchedule {
    // Get expert's scheduling preferences and constraints
    return {
      blockedPeriods: [],
      specialty: 'general',
      emergencyAvailable: true,
    }; // Placeholder
  }

  private getSpecialtyConstraints(specialty: string): SpecialtyConstraint[] {
    // Get specialty-specific scheduling constraints
    return []; // Placeholder
  }

  private findBestTimeMatches(analysis: AvailabilityAnalysis, preferredTimes: TimePreference[]): string[] {
    // Find best matches for preferred times
    return []; // Placeholder
  }
}
```

---

## 🎯 **Next Steps**

Now that you understand the FAE (Find An Expert) system comprehensively, explore:

1. **[Infrastructure Components](./../infrastructure/)** - Main application bootstrap, error handling, and configuration systems
2. **[Deployment Guide](./../deployment/)** - Production deployment and scaling strategies
3. **[API Reference](./../api/)** - Complete API documentation and integration guides

Each component integrates with the broader healthcare ecosystem to provide specialized functionality for different clinical use cases and user requirements.

**🚀 Ready to explore the infrastructure components that power this entire healthcare platform? Your FAE expertise will help you understand how all these systems work together in a production environment!**
