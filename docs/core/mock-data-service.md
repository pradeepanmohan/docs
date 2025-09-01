# 🎭 **Mock Data Service - Development & Testing Data Management**

## 🎯 **Overview**

The **Mock Data Service** provides comprehensive mock data generation and management for development, testing, and demonstration purposes in the Navigator API. It enables realistic testing scenarios without relying on production data or external services.

---

## 📍 **Mock Data Service Architecture**

### **What is Mock Data Service?**
Mock data service provides:
- **Realistic Test Data**: Production-like data structures and values
- **User Identity Management**: Mock user profiles with healthcare identifiers
- **Dynamic Data Generation**: On-demand mock data creation
- **Development Utilities**: Easy data setup for development environments
- **Testing Support**: Consistent test data across different test scenarios
- **Data Privacy**: Safe, anonymized data for development and testing

### **Mock Data Service Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                Mock Data Service System                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            User Identity Management                │    │
│  │  ├─ Healthcare User Profiles ─┬─ LAN_ID, PER_ID     │    │
│  │  ├─ Provider Information ─────┼─ NPI, Specialty      │    │
│  │  ├─ Patient Demographics ─────┼─ PHI-safe Data       │    │
│  │  └─ Authentication Tokens ────┴─ Mock Tokens         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Dynamic Data Generation                 │    │
│  │  ├─ Clinical Data Mocking ───┬─ Lab Results         │    │
│  │  ├─ Appointment Scheduling ──┼─ Calendar Events     │    │
│  │  ├─ Medical Records ─────────┼─ Patient History     │    │
│  │  └─ Widget Data ─────────────┴─ Dashboard Content   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Testing & Development Support           │    │
│  │  ├─ Test Data Setup ──────┬─ Consistent Scenarios  │    │
│  │  ├─ Environment Switching─┼─ Dev/Stage/Prod        │    │
│  │  ├─ Data Seeding ─────────┼─ Database Population   │    │
│  │  └─ Mock API Responses ───┴─ External Service Sim  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Complete Implementation**

### **1. Mock Data Service**

```typescript
// File: libs/common/src/mock-data/mock-data.service.ts

import { Injectable } from '@nestjs/common';
import { mockuserData } from './data/users';

@Injectable()
export class MockDataService {
  /**
   * Retrieve a mock user
   *
   * @param lanId User LAN_ID
   */
  getUser(identifier: string, type: 'LAN_ID' | 'PER_ID') {
    if (!identifier) return null;

    const normalizedId = identifier.toLowerCase();

    if (type === 'LAN_ID') {
      return (
        mockuserData[normalizedId] || {
          fullName: 'Steve G. Peters',
          identifiers: {
            LAN_ID: {
              value: 'mipambmd',
            },
            PER_ID: {
              value: '10013296',
            },
            EPIC_ID: {
              value: '8c90593f-e843-4ffd-b2f0-c37d5cca3fe2',
            },
            NPI_ID: {
              value: '1234567890',
            },
          },
          demographics: {
            gender: 'Male',
            dateOfBirth: '1975-05-15',
            age: 48,
          },
          specialty: 'Internal Medicine',
          role: 'Physician',
          department: 'Internal Medicine',
          contact: {
            email: 'steve.peters@mayo.edu',
            phone: '+1-507-284-1234',
          },
          privileges: {
            canAccessPHI: true,
            canPrescribe: true,
            canOrderLabs: true,
            canViewRecords: true,
          },
          status: 'Active',
        }
      );
    }

    // Search by PER_ID
    for (const [lanId, userData] of Object.entries(mockuserData)) {
      if (userData.identifiers.PER_ID?.value === identifier) {
        return userData;
      }
    }

    return null;
  }

  /**
   * Get all mock users
   */
  getAllUsers(): any[] {
    return Object.values(mockuserData);
  }

  /**
   * Generate mock clinical data
   */
  generateMockClinicalData(patientId: string, dataType: string): any {
    switch (dataType) {
      case 'vitals':
        return this.generateMockVitals(patientId);
      case 'labResults':
        return this.generateMockLabResults(patientId);
      case 'medications':
        return this.generateMockMedications(patientId);
      case 'allergies':
        return this.generateMockAllergies(patientId);
      case 'appointments':
        return this.generateMockAppointments(patientId);
      default:
        return this.generateMockDefaultData(patientId, dataType);
    }
  }

  /**
   * Generate mock patient demographics
   */
  generateMockPatientDemographics(patientId: string): any {
    const firstNames = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Lisa', 'Robert', 'Emily'];
    const lastNames = ['Smith', 'Johnson', 'Brown', 'Williams', 'Jones', 'Garcia', 'Miller', 'Davis'];

    const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
    const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];

    return {
      id: patientId,
      name: {
        first: firstName,
        last: lastName,
        full: `${firstName} ${lastName}`,
      },
      demographics: {
        gender: Math.random() > 0.5 ? 'Male' : 'Female',
        dateOfBirth: this.generateRandomDateOfBirth(),
        age: this.calculateAge(this.generateRandomDateOfBirth()),
        maritalStatus: this.getRandomMaritalStatus(),
        language: 'English',
        race: this.getRandomRace(),
        ethnicity: this.getRandomEthnicity(),
      },
      contact: {
        address: this.generateMockAddress(),
        phone: this.generateMockPhone(),
        email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}@example.com`,
      },
      identifiers: {
        MRN: this.generateMockMRN(),
        SSN: this.generateMockSSN(),
      },
      insurance: this.generateMockInsurance(),
    };
  }

  /**
   * Generate mock appointments
   */
  generateMockAppointments(providerId: string): any[] {
    const appointments = [];
    const numberOfAppointments = Math.floor(Math.random() * 10) + 1;

    for (let i = 0; i < numberOfAppointments; i++) {
      const appointmentDate = new Date();
      appointmentDate.setDate(appointmentDate.getDate() + Math.floor(Math.random() * 30));

      appointments.push({
        id: `appt_${i + 1}`,
        providerId,
        patientId: `patient_${Math.floor(Math.random() * 1000)}`,
        dateTime: appointmentDate.toISOString(),
        duration: Math.floor(Math.random() * 60) + 15, // 15-75 minutes
        type: this.getRandomAppointmentType(),
        status: this.getRandomAppointmentStatus(),
        location: this.getRandomLocation(),
        notes: `Mock appointment ${i + 1} notes`,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    return appointments;
  }

  /**
   * Generate mock lab results
   */
  generateMockLabResults(patientId: string): any[] {
    const labTests = [
      { name: 'CBC', unit: '10^9/L', normalRange: '4.0-11.0' },
      { name: 'Hemoglobin', unit: 'g/dL', normalRange: '12.0-16.0' },
      { name: 'Hematocrit', unit: '%', normalRange: '36-46' },
      { name: 'Platelets', unit: '10^9/L', normalRange: '150-450' },
      { name: 'Glucose', unit: 'mg/dL', normalRange: '70-100' },
      { name: 'Cholesterol', unit: 'mg/dL', normalRange: '<200' },
    ];

    return labTests.map((test, index) => ({
      id: `lab_${index + 1}`,
      patientId,
      testName: test.name,
      value: this.generateRandomLabValue(test),
      unit: test.unit,
      normalRange: test.normalRange,
      status: this.getRandomLabStatus(),
      collectedDate: this.generateRecentDate(),
      resultDate: new Date().toISOString(),
      performingLab: 'Mayo Clinic Laboratories',
      orderingProvider: 'Dr. Test Provider',
    }));
  }

  /**
   * Generate mock vitals
   */
  generateMockVitals(patientId: string): any[] {
    const vitals = [];
    const numberOfReadings = Math.floor(Math.random() * 10) + 5;

    for (let i = 0; i < numberOfReadings; i++) {
      const readingDate = new Date();
      readingDate.setHours(readingDate.getHours() - i * 24); // One reading per day

      vitals.push({
        id: `vital_${i + 1}`,
        patientId,
        dateTime: readingDate.toISOString(),
        bloodPressure: {
          systolic: Math.floor(Math.random() * 40) + 110, // 110-150
          diastolic: Math.floor(Math.random() * 30) + 70,  // 70-100
        },
        heartRate: Math.floor(Math.random() * 40) + 60, // 60-100 BPM
        temperature: Math.round((Math.random() * 3 + 97) * 10) / 10, // 97.0-100.0 °F
        respiratoryRate: Math.floor(Math.random() * 10) + 12, // 12-22 breaths/min
        oxygenSaturation: Math.floor(Math.random() * 5) + 95, // 95-100%
        weight: Math.round((Math.random() * 50 + 150) * 10) / 10, // 150-200 lbs
        height: 70, // 70 inches (fixed for simplicity)
        bmi: Math.round((Math.random() * 10 + 20) * 10) / 10, // 20-30 BMI
      });
    }

    return vitals;
  }

  /**
   * Generate mock medications
   */
  generateMockMedications(patientId: string): any[] {
    const medications = [
      { name: 'Lisinopril', strength: '10mg', form: 'Tablet', frequency: 'Once daily' },
      { name: 'Metformin', strength: '500mg', form: 'Tablet', frequency: 'Twice daily' },
      { name: 'Atorvastatin', strength: '20mg', form: 'Tablet', frequency: 'Once daily' },
      { name: 'Omeprazole', strength: '20mg', form: 'Capsule', frequency: 'Once daily' },
      { name: 'Aspirin', strength: '81mg', form: 'Tablet', frequency: 'Once daily' },
    ];

    return medications.map((med, index) => ({
      id: `med_${index + 1}`,
      patientId,
      name: med.name,
      strength: med.strength,
      form: med.form,
      frequency: med.frequency,
      startDate: this.generateRecentDate(),
      endDate: null, // Currently active
      prescribingProvider: 'Dr. Test Provider',
      indication: 'Mock indication',
      status: 'Active',
      instructions: `Take ${med.frequency}`,
    }));
  }

  /**
   * Generate mock allergies
   */
  generateMockAllergies(patientId: string): any[] {
    const allergies = [
      { allergen: 'Penicillin', severity: 'Severe', reaction: 'Rash, swelling' },
      { allergen: 'Shellfish', severity: 'Moderate', reaction: 'Nausea, vomiting' },
      { allergen: 'Latex', severity: 'Mild', reaction: 'Contact dermatitis' },
    ];

    return allergies.map((allergy, index) => ({
      id: `allergy_${index + 1}`,
      patientId,
      allergen: allergy.allergen,
      severity: allergy.severity,
      reaction: allergy.reaction,
      onset: this.generateRecentDate(),
      status: 'Active',
      documentedBy: 'Dr. Test Provider',
      notes: `Patient allergic to ${allergy.allergen}`,
    }));
  }

  // Helper methods for data generation
  private generateRandomDateOfBirth(): string {
    const today = new Date();
    const birthYear = today.getFullYear() - Math.floor(Math.random() * 80) - 18; // 18-98 years old
    const birthMonth = Math.floor(Math.random() * 12);
    const birthDay = Math.floor(Math.random() * 28) + 1;

    return `${birthYear}-${String(birthMonth + 1).padStart(2, '0')}-${String(birthDay).padStart(2, '0')}`;
  }

  private calculateAge(dateOfBirth: string): number {
    const birth = new Date(dateOfBirth);
    const today = new Date();
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();

    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age--;
    }

    return age;
  }

  private getRandomMaritalStatus(): string {
    const statuses = ['Single', 'Married', 'Divorced', 'Widowed'];
    return statuses[Math.floor(Math.random() * statuses.length)];
  }

  private getRandomRace(): string {
    const races = ['White', 'Black or African American', 'Asian', 'Hispanic or Latino', 'Other'];
    return races[Math.floor(Math.random() * races.length)];
  }

  private getRandomEthnicity(): string {
    const ethnicities = ['Not Hispanic or Latino', 'Hispanic or Latino'];
    return ethnicities[Math.floor(Math.random() * ethnicities.length)];
  }

  private generateMockAddress(): any {
    const streets = ['Main St', 'Oak Ave', 'Elm St', 'Maple Dr', 'Pine Rd'];
    const cities = ['Rochester', 'Minneapolis', 'St. Paul', 'Bloomington', 'Eagan'];

    return {
      street: `${Math.floor(Math.random() * 999) + 1} ${streets[Math.floor(Math.random() * streets.length)]}`,
      city: cities[Math.floor(Math.random() * cities.length)],
      state: 'MN',
      zipCode: String(Math.floor(Math.random() * 90000) + 55901), // MN zip codes
    };
  }

  private generateMockPhone(): string {
    const areaCodes = ['507', '612', '651', '952'];
    const areaCode = areaCodes[Math.floor(Math.random() * areaCodes.length)];
    const exchange = String(Math.floor(Math.random() * 900) + 100);
    const number = String(Math.floor(Math.random() * 9000) + 1000);

    return `${areaCode}-${exchange}-${number}`;
  }

  private generateMockMRN(): string {
    return String(Math.floor(Math.random() * 90000000) + 10000000); // 8-digit MRN
  }

  private generateMockSSN(): string {
    const part1 = String(Math.floor(Math.random() * 900) + 100);
    const part2 = String(Math.floor(Math.random() * 90) + 10);
    const part3 = String(Math.floor(Math.random() * 9000) + 1000);

    return `${part1}-${part2}-${part3}`;
  }

  private generateMockInsurance(): any {
    const insurers = ['Blue Cross Blue Shield', 'UnitedHealthcare', 'Aetna', 'Cigna', 'Humana'];

    return {
      primaryInsurance: insurers[Math.floor(Math.random() * insurers.length)],
      policyNumber: String(Math.floor(Math.random() * 900000000) + 100000000),
      groupNumber: String(Math.floor(Math.random() * 900000) + 100000),
      effectiveDate: this.generateRecentDate(),
    };
  }

  private getRandomAppointmentType(): string {
    const types = ['Office Visit', 'Consultation', 'Follow-up', 'Procedure', 'Telemedicine'];
    return types[Math.floor(Math.random() * types.length)];
  }

  private getRandomAppointmentStatus(): string {
    const statuses = ['Scheduled', 'Confirmed', 'Completed', 'Cancelled', 'No-show'];
    return statuses[Math.floor(Math.random() * statuses.length)];
  }

  private getRandomLocation(): string {
    const locations = ['Clinic A', 'Clinic B', 'Hospital', 'Telemedicine', 'Urgent Care'];
    return locations[Math.floor(Math.random() * locations.length)];
  }

  private generateRandomLabValue(test: any): number {
    const [min, max] = test.normalRange.split('-').map((v: string) => parseFloat(v));
    const range = max - min;
    const value = min + Math.random() * range * 1.5; // Allow some out-of-range values

    return Math.round(value * 100) / 100;
  }

  private getRandomLabStatus(): string {
    const statuses = ['Normal', 'High', 'Low', 'Critical', 'Pending'];
    const weights = [0.7, 0.1, 0.1, 0.05, 0.05]; // Weighted probabilities

    const random = Math.random();
    let cumulativeWeight = 0;

    for (let i = 0; i < statuses.length; i++) {
      cumulativeWeight += weights[i];
      if (random <= cumulativeWeight) {
        return statuses[i];
      }
    }

    return 'Normal';
  }

  private generateRecentDate(): string {
    const date = new Date();
    date.setDate(date.getDate() - Math.floor(Math.random() * 365)); // Within last year
    return date.toISOString();
  }

  private generateMockDefaultData(patientId: string, dataType: string): any {
    return {
      id: `mock_${Date.now()}`,
      patientId,
      dataType,
      content: `Mock ${dataType} data for patient ${patientId}`,
      generatedAt: new Date().toISOString(),
      source: 'MockDataService',
    };
  }
}
```

### **2. Mock User Data**

```typescript
// File: libs/common/src/mock-data/data/users.ts

export const mockuserData = {
  'testuser1': {
    fullName: 'John A. Doe',
    identifiers: {
      LAN_ID: {
        value: 'testuser1',
      },
      PER_ID: {
        value: '10000001',
      },
      EPIC_ID: {
        value: '550e8400-e29b-41d4-a716-446655440000',
      },
      NPI_ID: {
        value: '1234567891',
      },
    },
    demographics: {
      gender: 'Male',
      dateOfBirth: '1980-03-15',
      age: 43,
    },
    specialty: 'Cardiology',
    role: 'Physician',
    department: 'Cardiovascular Medicine',
    contact: {
      email: 'john.doe@mayo.edu',
      phone: '+1-507-284-1111',
    },
    privileges: {
      canAccessPHI: true,
      canPrescribe: true,
      canOrderLabs: true,
      canViewRecords: true,
    },
    status: 'Active',
  },

  'testuser2': {
    fullName: 'Jane B. Smith',
    identifiers: {
      LAN_ID: {
        value: 'testuser2',
      },
      PER_ID: {
        value: '10000002',
      },
      EPIC_ID: {
        value: '550e8400-e29b-41d4-a716-446655440001',
      },
      NPI_ID: {
        value: '1234567892',
      },
    },
    demographics: {
      gender: 'Female',
      dateOfBirth: '1975-08-22',
      age: 48,
    },
    specialty: 'Internal Medicine',
    role: 'Physician',
    department: 'General Internal Medicine',
    contact: {
      email: 'jane.smith@mayo.edu',
      phone: '+1-507-284-2222',
    },
    privileges: {
      canAccessPHI: true,
      canPrescribe: true,
      canOrderLabs: true,
      canViewRecords: true,
    },
    status: 'Active',
  },

  'mipambmd': {
    fullName: 'Steve G. Peters',
    identifiers: {
      LAN_ID: {
        value: 'mipambmd',
      },
      PER_ID: {
        value: '10013296',
      },
      EPIC_ID: {
        value: '8c90593f-e843-4ffd-b2f0-c37d5cca3fe2',
      },
      NPI_ID: {
        value: '1234567890',
      },
    },
    demographics: {
      gender: 'Male',
      dateOfBirth: '1975-05-15',
      age: 48,
    },
    specialty: 'Internal Medicine',
    role: 'Physician',
    department: 'Internal Medicine',
    contact: {
      email: 'steve.peters@mayo.edu',
      phone: '+1-507-284-1234',
    },
    privileges: {
      canAccessPHI: true,
      canPrescribe: true,
      canOrderLabs: true,
      canViewRecords: true,
    },
    status: 'Active',
  },

  // Add more mock users as needed...
};
```

### **3. Mock Data Module**

```typescript
// File: libs/common/src/mock-data/mock-data.module.ts

import { Module } from '@nestjs/common';
import { MockDataService } from './mock-data.service';

@Module({
  providers: [MockDataService],
  exports: [MockDataService],
})
export class MockDataModule {}
```

### **4. Logger Mock**

```typescript
// File: libs/common/src/mock-data/logger.mock.ts

import { LoggerService } from '@nestjs/common';

export class LoggerMock implements LoggerService {
  private logs: string[] = [];

  log(message: any, context?: string): any {
    const logEntry = `[LOG] ${context || 'Application'}: ${message}`;
    this.logs.push(logEntry);
    console.log(logEntry);
  }

  error(message: any, trace?: string, context?: string): any {
    const logEntry = `[ERROR] ${context || 'Application'}: ${message}${trace ? ` - ${trace}` : ''}`;
    this.logs.push(logEntry);
    console.error(logEntry);
  }

  warn(message: any, context?: string): any {
    const logEntry = `[WARN] ${context || 'Application'}: ${message}`;
    this.logs.push(logEntry);
    console.warn(logEntry);
  }

  debug(message: any, context?: string): any {
    const logEntry = `[DEBUG] ${context || 'Application'}: ${message}`;
    this.logs.push(logEntry);
    console.debug(logEntry);
  }

  verbose(message: any, context?: string): any {
    const logEntry = `[VERBOSE] ${context || 'Application'}: ${message}`;
    this.logs.push(logEntry);
    console.log(logEntry);
  }

  getLogs(): string[] {
    return [...this.logs];
  }

  clearLogs(): void {
    this.logs = [];
  }
}
```

---

## 🎯 **Usage Examples**

### **1. Basic Mock User Retrieval**

```typescript
// In any service or controller
@Injectable()
export class AuthService {
  constructor(private readonly mockDataService: MockDataService) {}

  async getMockUserForTesting(identifier: string): Promise<any> {
    // Get user by LAN_ID
    const user = this.mockDataService.getUser(identifier, 'LAN_ID');

    if (user) {
      return {
        ...user,
        // Add mock authentication token
        token: this.generateMockToken(user),
        expiresAt: new Date(Date.now() + 3600000), // 1 hour
      };
    }

    throw new Error(`Mock user not found: ${identifier}`);
  }

  private generateMockToken(user: any): string {
    // Generate a simple mock JWT-like token
    const payload = {
      sub: user.identifiers.LAN_ID.value,
      name: user.fullName,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    // Base64 encode (not secure, just for mocking)
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }
}
```

### **2. Mock Clinical Data Generation**

```typescript
@Injectable()
export class ClinicalDataService {
  constructor(private readonly mockDataService: MockDataService) {}

  async getPatientVitals(patientId: string): Promise<any[]> {
    // Check if we should use mock data (based on environment or feature flag)
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockVitals(patientId);
    }

    // Real implementation would call actual EHR system
    return this.callRealEHRSystem(patientId, 'vitals');
  }

  async getPatientLabResults(patientId: string): Promise<any[]> {
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockLabResults(patientId);
    }

    return this.callRealEHRSystem(patientId, 'labResults');
  }

  async getPatientMedications(patientId: string): Promise<any[]> {
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockMedications(patientId);
    }

    return this.callRealEHRSystem(patientId, 'medications');
  }

  async getPatientAllergies(patientId: string): Promise<any[]> {
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockAllergies(patientId);
    }

    return this.callRealEHRSystem(patientId, 'allergies');
  }

  private shouldUseMockData(): boolean {
    // Use mock data in development or when explicitly requested
    return process.env.NODE_ENV === 'development' ||
           process.env.USE_MOCK_DATA === 'true';
  }

  private async callRealEHRSystem(patientId: string, dataType: string): Promise<any[]> {
    // Real implementation would integrate with Epic, Cerner, etc.
    // This is just a placeholder
    return [];
  }
}
```

### **3. Mock Appointments for Testing**

```typescript
@Injectable()
export class AppointmentService {
  constructor(private readonly mockDataService: MockDataService) {}

  async getProviderAppointments(providerId: string): Promise<any[]> {
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockAppointments(providerId);
    }

    // Real implementation
    return this.callAppointmentAPI(providerId);
  }

  async createMockAppointmentForTesting(appointmentData: any): Promise<any> {
    // Always use mock data for testing scenarios
    const mockAppointment = {
      id: `mock_${Date.now()}`,
      ...appointmentData,
      status: 'Mock Created',
      createdAt: new Date().toISOString(),
    };

    // In a real scenario, you might store this in a test database
    this.storeMockAppointment(mockAppointment);

    return mockAppointment;
  }

  private shouldUseMockData(): boolean {
    return process.env.NODE_ENV === 'test' ||
           process.env.USE_MOCK_APPOINTMENTS === 'true';
  }

  private async callAppointmentAPI(providerId: string): Promise<any[]> {
    // Real API call implementation
    return [];
  }

  private storeMockAppointment(appointment: any): void {
    // Store in memory or test database for testing purposes
    if (!global.mockAppointments) {
      global.mockAppointments = [];
    }
    global.mockAppointments.push(appointment);
  }
}
```

### **4. Mock Patient Demographics**

```typescript
@Injectable()
export class PatientService {
  constructor(private readonly mockDataService: MockDataService) {}

  async getPatientDemographics(patientId: string): Promise<any> {
    if (this.shouldUseMockData()) {
      return this.mockDataService.generateMockPatientDemographics(patientId);
    }

    // Real implementation would call patient demographics API
    return this.callPatientDemographicsAPI(patientId);
  }

  async searchPatients(query: string): Promise<any[]> {
    if (this.shouldUseMockData()) {
      // Generate multiple mock patients for search results
      const mockPatients = [];
      for (let i = 0; i < 5; i++) {
        const patientId = `mock_patient_${i + 1}`;
        mockPatients.push(
          this.mockDataService.generateMockPatientDemographics(patientId)
        );
      }

      // Filter based on query (simple implementation)
      return mockPatients.filter(patient =>
        patient.name.full.toLowerCase().includes(query.toLowerCase())
      );
    }

    return this.callPatientSearchAPI(query);
  }

  private shouldUseMockData(): boolean {
    return process.env.NODE_ENV === 'development' ||
           process.env.USE_MOCK_PATIENTS === 'true';
  }

  private async callPatientDemographicsAPI(patientId: string): Promise<any> {
    // Real API implementation
    return {};
  }

  private async callPatientSearchAPI(query: string): Promise<any[]> {
    // Real search implementation
    return [];
  }
}
```

---

## 🎯 **Integration with Testing Frameworks**

### **1. Jest Test Setup with Mock Data**

```typescript
// File: test/setup/mock-data.setup.ts

import { MockDataService } from '@app/common/mock-data';
import { Test, TestingModule } from '@nestjs/testing';

export class MockDataTestHelper {
  private mockDataService: MockDataService;

  async setupMockDataModule(): Promise<TestingModule> {
    const moduleRef = await Test.createTestingModule({
      imports: [MockDataModule],
      providers: [MockDataService],
    }).compile();

    this.mockDataService = moduleRef.get<MockDataService>(MockDataService);

    return moduleRef;
  }

  getMockUser(identifier: string, type: 'LAN_ID' | 'PER_ID' = 'LAN_ID') {
    return this.mockDataService.getUser(identifier, type);
  }

  generateMockPatientData(patientId: string) {
    return {
      demographics: this.mockDataService.generateMockPatientDemographics(patientId),
      vitals: this.mockDataService.generateMockVitals(patientId),
      labResults: this.mockDataService.generateMockLabResults(patientId),
      medications: this.mockDataService.generateMockMedications(patientId),
      allergies: this.mockDataService.generateMockAllergies(patientId),
    };
  }

  generateMockAppointmentData(providerId: string) {
    return this.mockDataService.generateMockAppointments(providerId);
  }

  createMockClinicalScenario(scenario: string): any {
    // Create specific mock scenarios for testing
    switch (scenario) {
      case 'diabetes-management':
        return this.createDiabetesMockScenario();
      case 'cardiac-care':
        return this.createCardiacMockScenario();
      case 'emergency-admission':
        return this.createEmergencyMockScenario();
      default:
        return this.generateMockPatientData('default_patient');
    }
  }

  private createDiabetesMockScenario(): any {
    const patientId = 'diabetes_patient_001';

    return {
      patient: this.mockDataService.generateMockPatientDemographics(patientId),
      vitals: [
        // High glucose readings
        {
          id: 'vital_1',
          patientId,
          dateTime: new Date().toISOString(),
          bloodPressure: { systolic: 140, diastolic: 90 },
          heartRate: 75,
          temperature: 98.6,
          glucose: 180, // High glucose
          weight: 180,
        },
      ],
      medications: [
        {
          id: 'med_1',
          patientId,
          name: 'Metformin',
          strength: '500mg',
          frequency: 'Twice daily',
          status: 'Active',
        },
        {
          id: 'med_2',
          patientId,
          name: 'Insulin Glargine',
          strength: '20 units',
          frequency: 'Once daily',
          status: 'Active',
        },
      ],
      labResults: [
        {
          id: 'lab_1',
          patientId,
          testName: 'Hemoglobin A1c',
          value: 8.5, // High A1c
          unit: '%',
          normalRange: '<7.0',
          status: 'High',
        },
      ],
    };
  }

  private createCardiacMockScenario(): any {
    const patientId = 'cardiac_patient_001';

    return {
      patient: this.mockDataService.generateMockPatientDemographics(patientId),
      vitals: [
        {
          id: 'vital_1',
          patientId,
          dateTime: new Date().toISOString(),
          bloodPressure: { systolic: 160, diastolic: 95 }, // High BP
          heartRate: 85,
          temperature: 98.2,
          weight: 200,
        },
      ],
      medications: [
        {
          id: 'med_1',
          patientId,
          name: 'Lisinopril',
          strength: '10mg',
          frequency: 'Once daily',
          status: 'Active',
        },
        {
          id: 'med_2',
          patientId,
          name: 'Atorvastatin',
          strength: '40mg',
          frequency: 'Once daily',
          status: 'Active',
        },
      ],
      appointments: this.mockDataService.generateMockAppointments('cardiac_provider'),
    };
  }

  private createEmergencyMockScenario(): any {
    const patientId = 'emergency_patient_001';

    return {
      patient: this.mockDataService.generateMockPatientDemographics(patientId),
      vitals: [
        {
          id: 'vital_1',
          patientId,
          dateTime: new Date().toISOString(),
          bloodPressure: { systolic: 180, diastolic: 110 }, // Critical BP
          heartRate: 110, // Tachycardia
          temperature: 101.5, // Fever
          respiratoryRate: 28, // Tachypnea
          oxygenSaturation: 92, // Low O2 sat
        },
      ],
      allergies: [
        {
          id: 'allergy_1',
          patientId,
          allergen: 'Penicillin',
          severity: 'Severe',
          reaction: 'Anaphylaxis',
          status: 'Active',
        },
      ],
      emergency: {
        triageLevel: 'Level 1 - Resuscitation',
        chiefComplaint: 'Chest pain and shortness of breath',
        arrivalTime: new Date().toISOString(),
        status: 'Active',
      },
    };
  }
}

// Export helper for use in tests
export const mockDataHelper = new MockDataTestHelper();
```

### **2. Test Example Using Mock Data**

```typescript
// File: test/services/clinical-data.service.spec.ts

import { Test, TestingModule } from '@nestjs/testing';
import { ClinicalDataService } from '@app/clinical-data/clinical-data.service';
import { MockDataService } from '@app/common/mock-data';
import { mockDataHelper } from '../setup/mock-data.setup';

describe('ClinicalDataService', () => {
  let service: ClinicalDataService;
  let mockDataService: MockDataService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ClinicalDataService,
        {
          provide: MockDataService,
          useValue: mockDataService,
        },
      ],
    }).compile();

    service = module.get<ClinicalDataService>(ClinicalDataService);
    mockDataService = module.get<MockDataService>(MockDataService);
  });

  describe('getPatientVitals', () => {
    it('should return mock vitals data in development', async () => {
      // Arrange
      process.env.NODE_ENV = 'development';
      const patientId = 'test_patient_001';
      const mockVitals = mockDataHelper.generateMockPatientData(patientId).vitals;

      jest.spyOn(mockDataService, 'generateMockVitals').mockReturnValue(mockVitals);

      // Act
      const result = await service.getPatientVitals(patientId);

      // Assert
      expect(result).toEqual(mockVitals);
      expect(mockDataService.generateMockVitals).toHaveBeenCalledWith(patientId);
    });

    it('should handle diabetes management scenario', async () => {
      // Arrange
      const diabetesScenario = mockDataHelper.createMockClinicalScenario('diabetes-management');

      jest.spyOn(mockDataService, 'generateMockVitals').mockReturnValue(diabetesScenario.vitals);
      jest.spyOn(mockDataService, 'generateMockMedications').mockReturnValue(diabetesScenario.medications);
      jest.spyOn(mockDataService, 'generateMockLabResults').mockReturnValue(diabetesScenario.labResults);

      // Act
      const vitals = await service.getPatientVitals(diabetesScenario.patient.id);
      const medications = await service.getPatientMedications(diabetesScenario.patient.id);
      const labs = await service.getPatientLabResults(diabetesScenario.patient.id);

      // Assert
      expect(vitals[0].glucose).toBeGreaterThan(140); // High glucose for diabetes
      expect(medications).toContainEqual(
        expect.objectContaining({ name: 'Metformin' })
      );
      expect(labs[0].value).toBeGreaterThan(7.0); // High A1c
    });
  });
});
```

---

## ⚙️ **Configuration & Best Practices**

### **1. Mock Data Configuration**

```typescript
// File: src/config/mock-data.config.ts

export const mockDataConfig = {
  // Global mock data settings
  global: {
    enabled: process.env.MOCK_DATA_ENABLED === 'true',
    environment: process.env.NODE_ENV,
    seed: parseInt(process.env.MOCK_DATA_SEED || '12345'), // For reproducible random data
  },

  // User data settings
  users: {
    defaultUserCount: parseInt(process.env.MOCK_USER_COUNT || '10'),
    includeRealUsers: process.env.MOCK_INCLUDE_REAL_USERS === 'true',
    maskSensitiveData: true,
  },

  // Clinical data settings
  clinical: {
    generateRealisticValues: process.env.MOCK_REALISTIC_VALUES === 'true',
    includeOutOfRangeValues: process.env.MOCK_OUT_OF_RANGE === 'true',
    maxRecordsPerPatient: parseInt(process.env.MOCK_MAX_RECORDS || '50'),
  },

  // Appointment settings
  appointments: {
    defaultCount: parseInt(process.env.MOCK_APPOINTMENT_COUNT || '5'),
    includePastAppointments: process.env.MOCK_PAST_APPOINTMENTS === 'true',
    includeFutureAppointments: process.env.MOCK_FUTURE_APPOINTMENTS === 'true',
  },

  // Test scenarios
  scenarios: {
    enabled: process.env.MOCK_SCENARIOS_ENABLED === 'true',
    predefinedScenarios: [
      'diabetes-management',
      'cardiac-care',
      'emergency-admission',
      'pediatric-care',
      'maternity-care',
      'oncology-treatment',
    ],
  },
};
```

### **2. Mock Data Best Practices**

```typescript
@Injectable()
export class MockDataBestPractices {
  constructor(private readonly mockDataService: MockDataService) {}

  /**
   * Use consistent mock data across tests
   */
  async getConsistentMockData(identifier: string): Promise<any> {
    // Use a seed for reproducible results
    Math.seedrandom(identifier);

    const user = this.mockDataService.getUser(identifier, 'LAN_ID');

    if (!user) {
      throw new Error(`Mock user not found: ${identifier}`);
    }

    return user;
  }

  /**
   * Generate mock data with proper relationships
   */
  async generateRelatedMockData(baseEntity: any): Promise<any> {
    const relatedData = {
      patient: baseEntity,
      vitals: this.mockDataService.generateMockVitals(baseEntity.id),
      medications: this.mockDataService.generateMockMedications(baseEntity.id),
      appointments: this.mockDataService.generateMockAppointments(baseEntity.providerId),
    };

    // Ensure relationships are consistent
    this.validateRelationships(relatedData);

    return relatedData;
  }

  /**
   * Validate mock data relationships
   */
  private validateRelationships(data: any): void {
    const { patient, vitals, medications, appointments } = data;

    // All vitals should belong to the patient
    vitals.forEach((vital: any) => {
      if (vital.patientId !== patient.id) {
        throw new Error(`Vital ${vital.id} does not belong to patient ${patient.id}`);
      }
    });

    // All medications should belong to the patient
    medications.forEach((medication: any) => {
      if (medication.patientId !== patient.id) {
        throw new Error(`Medication ${medication.id} does not belong to patient ${patient.id}`);
      }
    });

    // All appointments should belong to the patient's provider
    appointments.forEach((appointment: any) => {
      if (appointment.providerId !== patient.providerId) {
        throw new Error(`Appointment ${appointment.id} does not belong to provider ${patient.providerId}`);
      }
    });
  }

  /**
   * Clean up mock data after tests
   */
  async cleanupMockData(): Promise<void> {
    // Reset any global mock data
    if (global.mockAppointments) {
      global.mockAppointments = [];
    }

    if (global.mockPatients) {
      global.mockPatients = [];
    }

    // Reset random seed
    Math.seedrandom();
  }

  /**
   * Generate mock data for performance testing
   */
  async generatePerformanceTestData(recordCount: number): Promise<any[]> {
    const testData = [];

    for (let i = 0; i < recordCount; i++) {
      const patientId = `perf_test_patient_${i}`;
      testData.push({
        id: patientId,
        patient: this.mockDataService.generateMockPatientDemographics(patientId),
        vitals: this.mockDataService.generateMockVitals(patientId),
        timestamp: new Date().toISOString(),
      });
    }

    return testData;
  }

  /**
   * Export mock data for external testing
   */
  async exportMockData(format: 'json' | 'csv' = 'json'): Promise<string> {
    const allUsers = this.mockDataService.getAllUsers();
    const sampleClinicalData = allUsers.map(user => ({
      user: user.identifiers.LAN_ID.value,
      patientData: this.mockDataService.generateMockPatientDemographics(
        `export_${user.identifiers.LAN_ID.value}`
      ),
      vitals: this.mockDataService.generateMockVitals(
        `export_${user.identifiers.LAN_ID.value}`
      ),
    }));

    if (format === 'json') {
      return JSON.stringify(sampleClinicalData, null, 2);
    }

    // CSV format (simplified)
    const csvHeaders = ['UserID', 'PatientName', 'Age', 'Gender', 'VitalCount'];
    const csvRows = sampleClinicalData.map(data =>
      [
        data.user,
        data.patientData.name.full,
        data.patientData.demographics.age,
        data.patientData.demographics.gender,
        data.vitals.length,
      ].join(',')
    );

    return [csvHeaders.join(','), ...csvRows].join('\n');
  }
}
```

---

## 🎯 **Next Steps**

This comprehensive mock data service provides:
- ✅ **Realistic healthcare data generation** for development and testing
- ✅ **User identity management** with proper healthcare identifiers
- ✅ **Clinical data mocking** including vitals, labs, medications, allergies
- ✅ **Dynamic data generation** with configurable parameters
- ✅ **Test scenario support** for specific clinical use cases
- ✅ **Data privacy protection** with PHI-safe mock data
- ✅ **Integration with testing frameworks** for comprehensive test coverage

**The mock data service is now fully documented and ready for development and testing scenarios! 🎭🩺**

**Key components now documented:**
- Mock data service with comprehensive healthcare data generation
- User identity management with LAN_ID, PER_ID, EPIC_ID, NPI_ID
- Clinical data generation for vitals, lab results, medications, allergies
- Mock appointment scheduling and patient demographics
- Integration with Jest testing framework
- Best practices for mock data management and testing
- Performance testing data generation capabilities
