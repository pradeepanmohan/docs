# 🚀 **Development Environment Setup & Deployment Guide**

## 🎯 **Overview**

This comprehensive guide covers the complete development environment setup, build processes, testing frameworks, deployment strategies, and operational procedures for the Navigator API. This documentation ensures consistent development practices across all team members and provides clear instructions for local development, testing, and production deployment.

---

## 📍 **Prerequisites & System Requirements**

### **System Requirements**
```bash
# Hardware Requirements
- RAM: 8GB minimum, 16GB recommended
- CPU: 4 cores minimum, 8 cores recommended
- Storage: 20GB free space
- Network: Stable internet connection

# Software Requirements
- Node.js: 18.0.0+ (LTS recommended)
- npm: 8.0.0+ or yarn: 1.22.0+
- PostgreSQL: 13.0+ (or Docker)
- Redis: 6.0+ (or Docker)
- Docker: 20.10+ (optional but recommended)
- Docker Compose: 2.0+ (optional but recommended)
```

### **Supported Operating Systems**
- ✅ **macOS**: 12.0+ (Monterey or later)
- ✅ **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+
- ✅ **Windows**: 10/11 with WSL2
- ❌ **Windows** (native): Not supported due to Node.js compatibility issues

---

## 🔧 **Package.json Scripts & Build System**

### **Complete Script Reference**

```json
{
  "scripts": {
    "build": "nest build",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\" \"libs/**/*.ts\"",
    "format:check": "prettier --check \"src/**/*.ts\" \"test/**/*.ts\" \"libs/**/*.ts\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "lint:ci": "eslint \"{src,apps,libs,test}/**/*.ts\"",
    "test:ci": "jest --config=jest.config.ci.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "report": "allure generate ./test/allure-results -o ./allure-report --clean && allure open ./allure-report",
    "test:e2e": "npm run test:e2e --workspace=test --silent",
    "test:e2e:dev": "npm run test:e2e:dev --workspace=test --silent",
    "test:e2e:ci": "npm run test:e2e:ci --workspace=test --silent",
    "test:e2e:dev:ci": "npm run test:e2e:dev:ci --workspace=test --silent",
    "test:e2e:continue": "npm run test:e2e --workspace=test --silent || true",
    "test:e2e:dev:continue": "npm run test:e2e:dev --silent || true",
    "test:pipeline": "cross-env CI=true npm run test:e2e:ci",
    "test:pipeline:profile": "cross-env SNAPSHOT_PROFILE=${SNAPSHOT_PROFILE:-strict} npm run test:pipeline",
    "test:spec": "jest --testPathPattern",
    "typeorm": "ts-node -r tsconfig-paths/register ./node_modules/typeorm/cli -d ./src/typeorm.config.ts",
    "typeorm-seeder": "ts-node -r tsconfig-paths/register ./node_modules/typeorm/cli -d ./src/typeorm-seeder.config.ts",
    "migration:run": "npm run typeorm migration:run",
    "migration:seed": "npm run typeorm-seeder migration:run",
    "migration:show": "npm run typeorm migration:show",
    "migration:generate": "npm run typeorm migration:generate ./src/migrations/gen",
    "migration:create": "ts-node ./node_modules/typeorm/cli migration:create",
    "migration:revert": "npm run typeorm migration:revert",
    "migration:revert-seed": "npm run typeorm-seeder migration:revert",
    "docker:start": "docker build --tag mctn-local-docker . && (docker rm -f mctn-local-docker-instance || true) && docker run -p 3000:3000 --name mctn-local-docker-instance --add-host host.docker.internal:host-gateway --env-file ./.env -e DATABASE_HOST=host.docker.internal mctn-local-docker",
    "docker:shell": "docker exec -it mctn-local-docker-instance sh",
    "db:up": "docker compose up -d mctn-backend-db",
    "db:down": "docker compose down",
    "db:clean": "npm run db:down && rm -rf ~/docker/pg_data/mctn_backend_db"
  }
}
```

### **Development Workflow Scripts**

#### **1. Code Quality & Formatting**
```bash
# Format all TypeScript files
npm run format

# Check formatting without fixing
npm run format:check

# Lint and auto-fix code issues
npm run lint

# Lint without auto-fix (CI mode)
npm run lint:ci
```

#### **2. Build & Development**
```bash
# Build production bundle
npm run build

# Start development server with hot reload
npm run start:dev

# Start development server with debugger
npm run start:debug

# Start production server
npm run start:prod
```

#### **3. Database Management**
```bash
# Run all pending migrations
npm run migration:run

# Run seed data migrations
npm run migration:seed

# Show migration status
npm run migration:show

# Generate migration from entity changes
npm run migration:generate

# Create new migration file
npm run migration:create -- --name=add-new-feature

# Revert last migration
npm run migration:revert

# Revert seed data
npm run migration:revert-seed
```

#### **4. Testing Scripts**
```bash
# Run all unit tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:cov

# Run tests in debug mode
npm run test:debug

# Generate test report
npm run report

# Run end-to-end tests
npm run test:e2e

# Run E2E tests in development mode
npm run test:e2e:dev

# Run specific test file
npm run test:spec -- path/to/test.spec.ts
```

---

## 🐳 **Docker & Containerization**

### **Dockerfile Analysis**

```dockerfile
# Multi-stage Docker build for optimized production images
FROM node:20-alpine

# Install PostgreSQL client for health checks and database operations
RUN apk add --no-cache postgresql-client

# Set working directory
WORKDIR /app

# Copy package files for dependency installation
COPY package.json package-lock.json* .npmrc ./

# Secure dependency installation using build secrets
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --audit=false --fund=false

# Remove problematic cross-spawn package (security fix)
RUN rm -r /usr/local/lib/node_modules/npm/node_modules/cross-spawn/

# Copy application source code
COPY . .

# Expose application port
EXPOSE 3000

# Build the application
RUN npm run build

# Production startup command with database migrations
CMD npm run migration:run && npm run migration:seed && npm run start:prod
```

**Dockerfile Features:**
- ✅ **Multi-stage build**: Optimized for production
- ✅ **Security hardening**: Removes vulnerable packages
- ✅ **Health check tools**: PostgreSQL client included
- ✅ **Secret management**: Secure npm registry access
- ✅ **Migration automation**: Database setup on container start

### **Docker Compose Configuration**

```yaml
version: '3.8'
services:
  mctn-backend-db:
    platform: linux/x86_64
    container_name: mctn-backend-db
    image: postgres:16.2
    restart: always
    environment:
      POSTGRES_USER: $DATABASE_USER
      POSTGRES_PASSWORD: $DATABASE_PASSWORD
      POSTGRES_DB: $DATABASE_NAME
    ports:
      - $DATABASE_PORT:5432
    volumes:
      - ~/docker/pg_data/mctn_backend_db:/var/lib/postgresql/data
```

**Docker Compose Features:**
- ✅ **Environment variable integration**: Secure credential management
- ✅ **Persistent data storage**: Named volume for data persistence
- ✅ **Platform specification**: Ensures x86_64 compatibility
- ✅ **Port mapping**: Configurable database port exposure
- ✅ **Auto-restart**: Database service reliability

### **Docker Development Workflow**

```bash
# Start database container
npm run db:up

# Stop database container
npm run db:down

# Clean database data (destructive)
npm run db:clean

# Build and run application in Docker
npm run docker:start

# Access running container shell
npm run docker:shell
```

---

## 🔧 **Testing Framework & Quality Assurance**

### **Jest Configuration Analysis**

```json
{
  "jest": {
    "moduleFileExtensions": ["js", "json", "ts"],
    "rootDir": ".",
    "testRegex": ".*\\.spec\\.ts$",
    "transform": {
      "^.+\\.(t|j)s$": [
        "ts-jest",
        {
          "tsconfig": "tsconfig.json",
          "useESM": true
        }
      ]
    },
    "collectCoverageFrom": ["**/*.(t|j)s"],
    "coverageDirectory": "../coverage",
    "testEnvironment": "node",
    "roots": ["<rootDir>/src/", "<rootDir>/libs/", "<rootDir>/test/"],
    "reporters": [
      "default",
      [
        "jest-html-reporter",
        {
          "pageTitle": "Navigator API Test Report",
          "outputPath": "./test-report.html",
          "includeFailureMsg": true,
          "includeConsoleLog": true
        }
      ]
    ],
    "moduleNameMapper": {
      "^@app/common(|/.*)$": "<rootDir>/libs/common/src/$1",
      "^src/(.*)": "<rootDir>/src/$1",
      "^@app/curator-engine(|/.*)$": "<rootDir>/libs/curator-engine/src/$1",
      "^(\\.{1,2}/.*)\\.js$": "$1"
    },
    "transformIgnorePatterns": ["node_modules/(?!(env-var)/)"],
    "preset": "ts-jest/presets/default-esm"
  }
}
```

**Jest Features:**
- ✅ **TypeScript support**: Full TS/JS test execution
- ✅ **ESM modules**: Modern JavaScript module support
- ✅ **Comprehensive coverage**: Multi-directory test discovery
- ✅ **HTML reporting**: Visual test result reports
- ✅ **Path mapping**: Module resolution for imports
- ✅ **Custom reporters**: Specialized test output formats

### **Vitest Configuration for E2E Tests**

```typescript
import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  plugins: sharedPlugins,
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 60000, // Extended timeout for E2E tests
    hookTimeout: 15000,
    env: sharedTestEnv,

    // Concurrency control for stability
    maxConcurrency: process.env.UPDATE_SNAPSHOTS === 'true' ? 1 : 1,
    pool: 'forks', // Process isolation

    // Global setup and test discovery
    globalSetup: [
      path.resolve(__dirname, './support/api-tools/test-results/setup.ts'),
    ],
    setupFiles: [
      ...sharedSetupFiles,
      path.resolve(__dirname, './support/setup/contract-error-handler.ts'),
    ],

    // Test file patterns
    include: [
      path.resolve(__dirname, './e2e/**/*.spec.ts'),
      path.resolve(__dirname, './e2e/**/*.test.ts'),
      path.resolve(__dirname, './contract/**/*.spec.ts'),
      path.resolve(__dirname, './contract/**/*.test.ts'),
    ],

    // Advanced reporting
    reporters: [
      'verbose',
      [
        'allure-vitest/reporter',
        {
          ...sharedAllureConfig,
          environmentInfo: {
            framework: 'vitest',
            language: 'typescript',
            os: process.platform,
            node: process.version,
            testType: 'e2e-contract',
          },
        },
      ],
      new FailedTestReporter(),
    ],

    coverage: sharedCoverageConfig,
  },

  resolve: {
    alias: sharedResolveAliases,
  },
});
```

**Vitest Features:**
- ✅ **E2E testing**: End-to-end test execution
- ✅ **Contract testing**: API contract validation
- ✅ **Snapshot testing**: UI and API response validation
- ✅ **Performance testing**: Load and stress testing
- ✅ **Allure reporting**: Advanced test reporting
- ✅ **Parallel execution**: Optimized test concurrency

### **Testing Workflow**

#### **1. Unit Testing**
```bash
# Run all unit tests
npm run test

# Run with coverage
npm run test:cov

# Run specific test file
npm run test -- --testPathPattern=auth.service.spec.ts

# Debug specific test
npm run test:debug -- --testNamePattern="should validate token"
```

#### **2. End-to-End Testing**
```bash
# Run E2E tests
npm run test:e2e

# Run E2E tests in development mode
npm run test:e2e:dev

# Run E2E tests in CI mode
npm run test:e2e:ci

# Continue on test failures (for CI)
npm run test:e2e:continue
```

#### **3. Contract Testing**
```bash
# Run contract tests
npm run test:pipeline

# Run with snapshot profile
SNAPSHOT_PROFILE=strict npm run test:pipeline:profile
```

#### **4. Performance Testing**
```bash
# Run performance tests
npm run test:performance

# Run load tests
npm run test:load

# Generate performance report
npm run test:performance:report
```

---

## 🔄 **CI/CD Pipeline & Deployment**

### **Azure DevOps Pipeline Architecture**

```yaml
# Main CI/CD pipeline configuration
resources:
  repositories:
    - repository: modn
      type: git
      name: Mayo Open Developer Network/modn-deployment-templates

trigger:
  branches:
    include:
      - main
      - navigator
  paths:
    exclude:
      - config/*
      - test/*
      - pipeline/*
      - azure-pipelines.yml
      - azure-pipelines-for-app-config.yml
      - azure-pipelines-tests.yml
      - cloudbuild.yaml
      - README.md

variables:
  - name: NON_PRODUCTION_IMAGE_URL
    value: $(ARTIFACT_REGISTRY)/$(NON_PRODUCTION_ARTIFACT_REGISTRY_PROJECT_ID)/$(REGISTRY_REPOSITORY)/$(IMAGE_NAME):$(IMAGE_TAG)
  - name: PRODUCTION_IMAGE_URL
    value: $(ARTIFACT_REGISTRY)/$(PRODUCTION_ARTIFACT_REGISTRY_PROJECT_ID)/$(REGISTRY_REPOSITORY)/$(IMAGE_NAME):$(IMAGE_TAG)
  - name: ARTIFACT_REGISTRY
    value: 'us-central1-docker.pkg.dev'
  - name: NON_PRODUCTION_ARTIFACT_REGISTRY_PROJECT_ID
    value: 'careguidance-default-non-prod'
  - name: PRODUCTION_ARTIFACT_REGISTRY_PROJECT_ID
    value: 'careguidance-default-prod'
  - name: REGISTRY_REPOSITORY
    value: 'bucket'
  - name: IMAGE_NAME
    value: 'navigator-api'
  - name: IMAGE_TAG
    value: '$(Build.BuildId)'

stages:
  - stage: Build
    displayName: Build
    jobs:
      - job: Build
        displayName: Build
        pool:
          vmImage: ubuntu-latest
        steps:
          - checkout: self
```

**Pipeline Features:**
- ✅ **Multi-environment deployment**: Separate staging and production
- ✅ **Artifact registry integration**: Google Cloud Artifact Registry
- ✅ **Security scanning**: Automated vulnerability assessment
- ✅ **Parallel execution**: Optimized build and test stages
- ✅ **Rollback capability**: Safe deployment rollback procedures
- ✅ **Monitoring integration**: Deployment metrics and alerting

### **Google Cloud Build Configuration**

```yaml
# Cloud Build configuration for Google Cloud Platform
steps:
  # Build Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - 'gcr.io/$PROJECT_ID/navigator-api:$COMMIT_SHA'
      - '.'

  # Run tests in Docker container
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'run'
      - '--rm'
      - 'gcr.io/$PROJECT_ID/navigator-api:$COMMIT_SHA'
      - 'npm'
      - 'run'
      - 'test:ci'

  # Security scanning
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
      - 'builds'
      - 'submit'
      - '--config=cloudbuild-security.yaml'
      - '.'

  # Deploy to Cloud Run
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
      - 'run'
      - 'deploy'
      - 'navigator-api'
      - '--image'
      - 'gcr.io/$PROJECT_ID/navigator-api:$COMMIT_SHA'
      - '--region'
      - 'us-central1'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'
      - '--set-env-vars'
      - 'NODE_ENV=production'

# Build timeout
timeout: '1800s'

# Build artifacts
artifacts:
  objects:
    location: 'gs://navigator-api-artifacts/'
    paths:
      - 'test-results/**/*'
      - 'coverage/**/*'
```

**Cloud Build Features:**
- ✅ **Container-first deployment**: Docker-based build and deploy
- ✅ **Multi-stage pipeline**: Build, test, security, deploy
- ✅ **Google Cloud integration**: Native GCP service integration
- ✅ **Artifact management**: Build artifact storage and versioning
- ✅ **Security integration**: Automated security scanning
- ✅ **Environment management**: Configurable deployment environments

---

## 📊 **Performance Testing & Monitoring**

### **Performance Testing Framework**

```typescript
// Performance testing configuration
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './performance',
  timeout: 300000, // 5 minutes for performance tests
  expect: {
    timeout: 10000,
  },

  // Performance test configuration
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:3000',
    extraHTTPHeaders: {
      'Authorization': `Bearer ${process.env.PERF_TEST_TOKEN}`,
    },
  },

  // Load testing scenarios
  projects: [
    {
      name: 'load-test',
      testMatch: '**/*.perf.spec.ts',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
      },
    },
    {
      name: 'stress-test',
      testMatch: '**/*.stress.spec.ts',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
      },
    },
    {
      name: 'spike-test',
      testMatch: '**/*.spike.spec.ts',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
      },
    },
  ],

  // Performance reporting
  reporter: [
    ['html', { outputFolder: 'performance-reports' }],
    ['json', { outputFile: 'performance-results.json' }],
    ['junit', { outputFile: 'performance-junit.xml' }],
  ],
});
```

**Performance Testing Features:**
- ✅ **Load testing**: Sustained load simulation
- ✅ **Stress testing**: System limits identification
- ✅ **Spike testing**: Sudden traffic surge handling
- ✅ **API performance**: Response time and throughput measurement
- ✅ **Resource monitoring**: CPU, memory, and database performance
- ✅ **Automated reporting**: Performance metrics and visualizations

### **Application Monitoring**

```typescript
// Application performance monitoring
@Injectable()
export class ApplicationMonitor {
  constructor(
    private readonly metrics: MetricsService,
    private readonly health: HealthCheckService,
  ) {}

  // Application startup metrics
  async trackApplicationStartup(): Promise<void> {
    const startupTime = Date.now() - global.startTime;

    this.metrics.histogram('app_startup_duration', startupTime);
    this.metrics.gauge('app_startup_timestamp', Date.now());

    this.logger.info('Application startup completed', {
      startupTime: `${startupTime}ms`,
      nodeVersion: process.version,
      platform: process.platform,
      memoryUsage: process.memoryUsage(),
    });
  }

  // Runtime performance metrics
  async collectRuntimeMetrics(): Promise<void> {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    // Memory metrics
    this.metrics.gauge('process_memory_heap_used', memUsage.heapUsed);
    this.metrics.gauge('process_memory_heap_total', memUsage.heapTotal);
    this.metrics.gauge('process_memory_external', memUsage.external);
    this.metrics.gauge('process_memory_rss', memUsage.rss);

    // CPU metrics
    this.metrics.gauge('process_cpu_user', cpuUsage.user);
    this.metrics.gauge('process_cpu_system', cpuUsage.system);

    // Event loop metrics
    const eventLoopDelay = this.measureEventLoopDelay();
    this.metrics.histogram('event_loop_delay', eventLoopDelay);
  }

  // Database performance monitoring
  async monitorDatabasePerformance(): Promise<void> {
    const connectionPoolStats = await this.getConnectionPoolStats();

    this.metrics.gauge('db_connections_active', connectionPoolStats.active);
    this.metrics.gauge('db_connections_idle', connectionPoolStats.idle);
    this.metrics.gauge('db_connections_total', connectionPoolStats.total);
    this.metrics.gauge('db_connections_waiting', connectionPoolStats.waiting);

    // Query performance
    const slowQueries = await this.getSlowQueries();
    slowQueries.forEach(query => {
      this.metrics.histogram('db_query_duration', query.duration, {
        query: query.sql.substring(0, 100),
        table: query.table,
      });
    });
  }

  // External service monitoring
  async monitorExternalServices(): Promise<void> {
    const services = [
      { name: 'Epic API', url: process.env.EPIC_BASE_URL },
      { name: 'Curator Engine', url: process.env.CURATOR_ENGINE_BASE_URL },
      { name: 'Redis Cache', url: process.env.REDIS_HOST },
    ];

    for (const service of services) {
      const responseTime = await this.measureServiceResponseTime(service.url);

      this.metrics.histogram('external_service_response_time', responseTime, {
        service: service.name,
      });

      this.metrics.gauge('external_service_health', responseTime < 5000 ? 1 : 0, {
        service: service.name,
      });
    }
  }

  // Business metrics tracking
  async trackBusinessMetrics(): Promise<void> {
    // API usage metrics
    const apiUsage = await this.getApiUsageStats();
    this.metrics.gauge('api_requests_total', apiUsage.totalRequests);
    this.metrics.gauge('api_requests_per_minute', apiUsage.requestsPerMinute);

    // Feature usage
    const featureUsage = await this.getFeatureUsageStats();
    Object.entries(featureUsage).forEach(([feature, usage]) => {
      this.metrics.gauge('feature_usage', usage.count, {
        feature,
        version: usage.version,
      });
    });

    // Error rates
    const errorStats = await this.getErrorStats();
    this.metrics.gauge('application_error_rate', errorStats.rate);
    this.metrics.gauge('application_errors_total', errorStats.total);
  }
}
```

---

## 🔒 **Security & Compliance**

### **Security Scanning Integration**

```yaml
# Security scanning pipeline step
- task: securedevelopmentassessment@1
  displayName: 'Run Security Assessment'
  inputs:
    credScanPath: '$(System.DefaultWorkingDirectory)'
    toolVersion: 'Latest'
    suppressionsFile: '.sdl/suppressions.json'

# Container vulnerability scanning
- task: Docker@2
  displayName: 'Scan Docker Image'
  inputs:
    command: 'build'
    Dockerfile: '**/Dockerfile'
    arguments: '--scan'

# Dependency vulnerability check
- task: npm-audit@1
  displayName: 'NPM Audit'
  inputs:
    path: '$(System.DefaultWorkingDirectory)'
    severity: 'moderate'
```

### **Environment Security**

```bash
# Secure environment variable handling
#!/bin/bash

# Load encrypted secrets
if [ "$ENVIRONMENT" = "production" ]; then
    # Decrypt production secrets
    gpg --decrypt secrets/prod-secrets.gpg > .env.prod

    # Set secure file permissions
    chmod 600 .env.prod
fi

# Validate required security variables
required_vars=("JWT_SECRET" "DB_PASSWORD" "API_KEYS")

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required security variable $var is not set"
        exit 1
    fi
done
```

**Security Features:**
- ✅ **Automated scanning**: Continuous security vulnerability assessment
- ✅ **Secret management**: Encrypted credential storage and access
- ✅ **Access control**: Environment-based security configurations
- ✅ **Audit logging**: Comprehensive security event tracking
- ✅ **Compliance monitoring**: HIPAA and security standard adherence

---

## 🚀 **Production Deployment Guide**

### **Pre-deployment Checklist**

```bash
# Environment validation
./scripts/validate-environment.sh

# Database migration dry-run
npm run migration:show

# Security scan
npm run security:scan

# Performance baseline
npm run performance:baseline

# Backup verification
./scripts/verify-backups.sh
```

### **Deployment Process**

```bash
# 1. Build production image
docker build -t navigator-api:latest .

# 2. Run database migrations
docker run --rm --env-file .env.prod navigator-api:latest npm run migration:run

# 3. Deploy with zero-downtime
kubectl set image deployment/navigator-api app=navigator-api:latest

# 4. Verify deployment
curl -f https://api.mayo.edu/health

# 5. Monitor post-deployment
npm run monitor:deployment
```

### **Rollback Procedure**

```bash
# 1. Identify deployment issue
kubectl get pods -l app=navigator-api

# 2. Rollback to previous version
kubectl rollout undo deployment/navigator-api

# 3. Verify rollback success
kubectl rollout status deployment/navigator-api

# 4. Monitor application health
npm run health:check
```

---

## 📊 **Monitoring & Alerting**

### **Application Dashboards**

```typescript
// Real-time monitoring dashboard configuration
@Injectable()
export class MonitoringDashboard {
  constructor(private readonly monitoring: MonitoringService) {}

  // Setup comprehensive monitoring
  async setupMonitoring(): Promise<void> {
    // Application metrics
    await this.setupApplicationMetrics();

    // Infrastructure metrics
    await this.setupInfrastructureMetrics();

    // Business metrics
    await this.setupBusinessMetrics();

    // Alert configurations
    await this.setupAlerts();
  }

  // Application performance metrics
  private async setupApplicationMetrics(): Promise<void> {
    const metrics = [
      {
        name: 'http_request_duration_seconds',
        help: 'Duration of HTTP requests in seconds',
        type: 'histogram',
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      },
      {
        name: 'http_requests_total',
        help: 'Total number of HTTP requests',
        type: 'counter',
        labels: ['method', 'endpoint', 'status'],
      },
      {
        name: 'active_connections',
        help: 'Number of active connections',
        type: 'gauge',
      },
    ];

    for (const metric of metrics) {
      await this.monitoring.registerMetric(metric);
    }
  }

  // Infrastructure monitoring
  private async setupInfrastructureMetrics(): Promise<void> {
    // CPU usage
    this.monitoring.gauge('cpu_usage_percent', async () => {
      return this.getCpuUsage();
    });

    // Memory usage
    this.monitoring.gauge('memory_usage_bytes', async () => {
      return process.memoryUsage().heapUsed;
    });

    // Disk usage
    this.monitoring.gauge('disk_usage_percent', async () => {
      return this.getDiskUsage();
    });

    // Network I/O
    this.monitoring.gauge('network_bytes_total', async () => {
      return this.getNetworkStats();
    });
  }

  // Business KPI monitoring
  private async setupBusinessMetrics(): Promise<void> {
    // User engagement
    this.monitoring.gauge('active_users', async () => {
      return this.getActiveUserCount();
    });

    // API usage
    this.monitoring.counter('api_calls_total', async () => {
      return this.getTotalApiCalls();
    });

    // Error rates
    this.monitoring.gauge('error_rate_percent', async () => {
      return this.getErrorRate();
    });

    // Response times
    this.monitoring.histogram('response_time_seconds', async () => {
      return this.getResponseTimes();
    });
  }

  // Alert configuration
  private async setupAlerts(): Promise<void> {
    const alerts = [
      {
        name: 'HighErrorRate',
        condition: 'error_rate_percent > 5',
        duration: '5m',
        severity: 'critical',
        description: 'Error rate is above 5%',
      },
      {
        name: 'HighResponseTime',
        condition: 'response_time_seconds{quantile="0.95"} > 2',
        duration: '5m',
        severity: 'warning',
        description: '95th percentile response time is above 2 seconds',
      },
      {
        name: 'HighMemoryUsage',
        condition: 'memory_usage_bytes / memory_total_bytes > 0.9',
        duration: '5m',
        severity: 'warning',
        description: 'Memory usage is above 90%',
      },
      {
        name: 'LowDiskSpace',
        condition: 'disk_free_bytes < 1073741824', // 1GB
        duration: '5m',
        severity: 'critical',
        description: 'Available disk space is below 1GB',
      },
    ];

    for (const alert of alerts) {
      await this.monitoring.createAlert(alert);
    }
  }
}
```

---

## 🎯 **Best Practices & Guidelines**

### **1. Development Best Practices**

```typescript
// Code quality standards
@Injectable()
export class DevelopmentStandards {
  // Pre-commit hooks
  async setupPreCommitHooks(): Promise<void> {
    // Lint staged files
    // Run unit tests
    // Check code formatting
    // Validate TypeScript types
  }

  // Code review checklist
  validateCodeReview(pr: PullRequest): ValidationResult {
    const issues: string[] = [];

    // Security checks
    if (!this.hasSecurityReview(pr)) {
      issues.push('Security review required for authentication changes');
    }

    // Test coverage
    if (pr.coverage < 80) {
      issues.push('Test coverage must be at least 80%');
    }

    // Documentation
    if (!this.hasUpdatedDocumentation(pr)) {
      issues.push('Documentation must be updated for API changes');
    }

    // Migration safety
    if (this.hasDatabaseChanges(pr) && !this.hasMigration(pr)) {
      issues.push('Database changes require migration file');
    }

    return {
      isValid: issues.length === 0,
      issues,
      recommendations: this.generateRecommendations(issues),
    };
  }

  // Performance standards
  validatePerformanceStandards(code: string): PerformanceValidation {
    // Bundle size limits
    // Memory leak detection
    // Database query optimization
    // API response time limits
  }

  // Security standards
  validateSecurityStandards(code: string): SecurityValidation {
    // Input validation
    // SQL injection prevention
    // XSS protection
    // Authentication checks
    // Authorization enforcement
  }
}
```

### **2. Deployment Best Practices**

```typescript
// Deployment automation
@Injectable()
export class DeploymentAutomation {
  // Blue-green deployment
  async performBlueGreenDeployment(newVersion: string): Promise<void> {
    // Create new environment
    await this.createGreenEnvironment(newVersion);

    // Run health checks
    await this.performHealthChecks('green');

    // Switch traffic to green
    await this.switchTrafficToGreen();

    // Monitor green environment
    await this.monitorGreenEnvironment();

    // Clean up blue environment
    await this.cleanupBlueEnvironment();
  }

  // Canaray deployment
  async performCanaryDeployment(newVersion: string): Promise<void> {
    // Deploy to canary group
    await this.deployToCanary(newVersion);

    // Route percentage of traffic
    await this.routeTrafficToCanary(10); // 10%

    // Monitor canary metrics
    await this.monitorCanaryMetrics();

    // Gradually increase traffic
    await this.graduallyIncreaseTraffic();

    // Full deployment or rollback
    await this.decideFullDeployment();
  }

  // Automated rollback
  async performAutomatedRollback(reason: string): Promise<void> {
    // Log rollback reason
    await this.logRollbackReason(reason);

    // Identify healthy version
    const healthyVersion = await this.findHealthyVersion();

    // Switch to healthy version
    await this.switchToHealthyVersion(healthyVersion);

    // Notify stakeholders
    await this.notifyStakeholders(reason);

    // Analyze rollback cause
    await this.analyzeRollbackCause();
  }
}
```

### **3. Monitoring Best Practices**

```typescript
// Comprehensive monitoring setup
@Injectable()
export class MonitoringBestPractices {
  // Setup observability stack
  async setupObservability(): Promise<void> {
    // Metrics collection
    await this.setupMetricsCollection();

    // Distributed tracing
    await this.setupDistributedTracing();

    // Log aggregation
    await this.setupLogAggregation();

    // Alert management
    await this.setupAlertManagement();

    // Dashboard creation
    await this.setupDashboards();
  }

  // Incident response
  async handleIncident(alert: Alert): Promise<void> {
    // Alert triage
    await this.triageAlert(alert);

    // Impact assessment
    await this.assessImpact(alert);

    // Communication
    await this.notifyOnCall(alert);

    // Investigation
    await this.investigateIncident(alert);

    // Resolution
    await this.resolveIncident(alert);

    // Post-mortem
    await this.performPostMortem(alert);
  }

  // Capacity planning
  async performCapacityPlanning(): Promise<void> {
    // Resource usage analysis
    await this.analyzeResourceUsage();

    // Performance trend analysis
    await this.analyzePerformanceTrends();

    // Scalability assessment
    await this.assessScalability();

    // Capacity recommendations
    await this.generateCapacityRecommendations();

    // Implementation planning
    await this.planCapacityImprovements();
  }
}
```

---

## 🎯 **Next Steps**

Now that you understand the Development Environment Setup & Deployment comprehensively, explore:

1. **[Environment Configuration](./../configuration/)** - Complete environment setup and configuration management
2. **[CI/CD Pipelines](./../cicd/)** - Detailed CI/CD pipeline configurations and best practices
3. **[Testing Strategies](./../testing/)** - Comprehensive testing frameworks and methodologies
4. **[Performance Optimization](./../performance/)** - Advanced performance tuning and optimization techniques

Each component integrates seamlessly to provide a robust, scalable, and maintainable deployment pipeline for the entire Mayo Care Team Navigator platform.

**🚀 Ready to explore the environment configuration that powers different deployment environments across this healthcare platform? Your development setup expertise will help you understand how configuration management works seamlessly across local, staging, and production environments!**
