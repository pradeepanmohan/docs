# 📚 **Navigator API Documentation**

Welcome to the comprehensive documentation for the **Mayo Clinic Care Team Navigator API**. This documentation is now **organized to mirror the source code structure** for optimal navigation and maintainability.

---

# 🚀 **🎯 NEW TO THE PROJECT? START HERE FIRST! 🎯**

## 📖 **[Complete Onboarding Guide for New Developers](setup/onboarding-guide.md)**

**⏱️ Time Required:** 6-10 hours over 4 weeks
**🎯 Purpose:** Structured learning path to become a productive team member
**📚 What You'll Get:** Step-by-step phases, practical examples, progress tracking

### **Quick Links for New Developers:**
- **[📋 Onboarding Guide](setup/onboarding-guide.md)** - Your complete learning roadmap
- **[🏥 Project Overview](setup/project-overview.md)** - Healthcare context and goals
- **[⚙️ Development Setup](setup/development-setup.md)** - Get your environment running
- **[🏗️ System Architecture](architecture/system-overview.md)** - Big picture understanding

---

> **💡 Pro Tip:** If you're new to the team, start with the [Onboarding Guide](setup/onboarding-guide.md) - it's designed specifically for you!

## 🗂️ **Documentation Organization**

The documentation is now structured to **perfectly mirror the `src/` folder structure**, making it intuitive to find documentation that corresponds to specific source code components.

### 📁 **Directory Structure**

```
docs/
├── 📖 README.md                          # This overview file
├── 🎯 setup/onboarding-guide.md         # ⭐ NEW DEVELOPER START HERE!
├── 🏗️ architecture/                      # System architecture
│   └── system-overview.md               # High-level system design
├── ⚙️ setup/                            # Development & deployment setup
│   ├── development-setup.md            # Environment setup
│   ├── project-overview.md             # Getting started guide
│   └── cicd-pipelines.md               # CI/CD & deployment
├── 🧪 testing/                          # Testing frameworks
│   ├── testing-framework.md            # Unit & integration testing
│   └── performance-testing.md          # Load & performance testing
├── 🎯 controllers/                      # API endpoint documentation
│   ├── access-blacklist.md             # Access blacklist endpoints
│   ├── ame.md                         # Ask Mayo Expert AI
│   ├── appointments.md                # Clinical appointments
│   ├── askctn.md                      # Ask Clinical Trials Network
│   ├── auth.md                        # Authentication endpoints
│   ├── break-the-glass.md             # Emergency access override
│   ├── clinical-summary.md            # Patient clinical summaries
│   ├── dataconcept.md                 # Clinical data concepts
│   ├── fae.md                         # Find An Expert
│   ├── health.md                      # Health monitoring
│   ├── mobile.md                      # Mobile authentication
│   ├── preferences.md                 # User preferences
│   ├── preferred-view.md              # Preferred clinical views
│   └── securechat.md                  # Secure chat (Microsoft Teams)
├── 🔧 services/                        # Business logic services
│   ├── business-services.md           # Core healthcare services
│   ├── audit-logging.md               # Audit trail service
│   ├── curator-engine.md              # Healthcare data integration
│   └── token-provider.md              # Authentication tokens
├── 🛡️ core/                           # Core system components
│   ├── infrastructure.md              # App module & bootstrap
│   ├── entities-dtos.md               # Database entities & DTOs
│   ├── logging-system.md              # Winston logger & GCP integration
│   ├── caching-system.md              # Redis & multi-level caching
│   ├── performance-logging.md         # Execution time tracking
│   ├── health-indicators.md           # System health monitoring
│   ├── mock-data-service.md           # Test data generation
│   └── audit-interceptors.md          # Request/response auditing
├── 🔒 guards/                          # Authentication guards
│   └── guards.md                      # Universal auth & access control
├── 🔗 interceptors/                    # Request processing
│   └── interceptors.md                # Context & audit interceptors
├── 🌐 middleware/                      # HTTP middleware
│   └── middleware.md                  # Request ID & response logging
├── 🏷️ decorators/                      # Custom decorators
│   └── decorators.md                  # User injection & utilities
├── ❌ errors/                          # Error handling
│   └── additional-components.md       # Exception classes & utilities
├── 🗄️ types/                           # Type definitions
│   └── types-and-migrations.md        # TypeScript types & migrations
├── 📊 migrations/                     # Database migrations
│   └── (migration documentation in types-and-migrations.md)
└── 📋 complete-documentation-index.md  # Complete reference guide
```

## 🎯 **Finding Documentation**

### **For Source Code Components:**
1. **Find the component in `src/`** (e.g., `src/controllers/auth/`)
2. **Look in the corresponding docs folder** (e.g., `docs/controllers/auth.md`)
3. **Same structure, same naming - instant navigation!**

### **Quick Reference Map:**

| **Source Location** | **Documentation Location** | **Purpose** |
|-------------------|---------------------------|-------------|
| `src/controllers/` | `docs/controllers/` | API endpoints & business logic |
| `src/services/` | `docs/services/` | Business services & integrations |
| `src/guards/` | `docs/guards/` | Authentication & authorization |
| `src/interceptors/` | `docs/interceptors/` | Request processing & auditing |
| `src/middleware/` | `docs/middleware/` | HTTP request/response handling |
| `src/decorators/` | `docs/decorators/` | Custom decorators & utilities |
| `src/errors/` | `docs/errors/` | Error classes & exception handling |
| `src/types/` | `docs/types/` | TypeScript definitions |
| `src/migrations/` | `docs/types/` | Database schema & migrations |

## 🚀 **Quick Start Guide**

### **🎯 NEW DEVELOPER? START HERE:**
**📖 Complete Onboarding Guide:** [`docs/setup/onboarding-guide.md`](setup/onboarding-guide.md)
- **⏱️ Time:** 6-10 hours over 4 weeks
- **🎯 Purpose:** Structured learning path for new team members
- **📚 Includes:** Step-by-step phases, timelines, and checkpoints

### **1. Quick Setup (For Experienced Developers)**
```bash
# 1. Setup environment
📖 Read: docs/setup/development-setup.md
📖 Read: docs/setup/project-overview.md

# 2. Understand architecture
📖 Read: docs/architecture/system-overview.md

# 3. Explore API endpoints
📖 Browse: docs/controllers/
```

### **2. Understanding a Specific Component**
```typescript
// If you're looking at: src/controllers/auth/auth.service.ts
// Read documentation at: docs/controllers/auth.md

// If you're working on: src/services/provider-specialty.service.ts
// Read documentation at: docs/services/business-services.md
```

### **3. Development Workflow**
```bash
# 1. Setup & testing
📖 docs/setup/development-setup.md
📖 docs/testing/testing-framework.md

# 2. Security implementation
📖 docs/guards/guards.md
📖 docs/interceptors/interceptors.md

# 3. Deployment
📖 docs/setup/cicd-pipelines.md
```

## 📚 **Documentation Categories**

### **🏗️ Architecture & Design**
- **[System Overview](./architecture/system-overview.md)** - High-level system design
- **[Complete Documentation Index](./complete-documentation-index.md)** - Full reference

### **⚙️ Development & Operations**
- **[Development Setup](./setup/development-setup.md)** - Environment configuration
- **[CI/CD Pipelines](./setup/cicd-pipelines.md)** - Deployment automation
- **[Infrastructure](./core/infrastructure.md)** - Core system components

### **🧪 Quality Assurance**
- **[Testing Framework](./testing/testing-framework.md)** - Unit & integration testing
- **[Performance Testing](./testing/performance-testing.md)** - Load testing & SLOs

### **🎯 API & Business Logic**
- **[Controllers](./controllers/)** - All 13 API endpoint documentations
- **[Services](./services/)** - Business services & integrations
- **[Core Components](./core/)** - Entities, DTOs, infrastructure

### **🔒 Security & Middleware**
- **[Guards](./guards/)** - Authentication & access control
- **[Interceptors](./interceptors/)** - Request processing
- **[Middleware](./middleware/)** - HTTP request handling
- **[Decorators](./decorators/)** - Custom utilities

### **❌ Error Handling & Types**
- **[Error Classes](./errors/)** - Exception handling & utilities
- **[Types & Migrations](./types/)** - TypeScript definitions & database schema

## 🎯 **Key Features**

### **🏥 Healthcare Innovation**
- ✅ **AI-Powered Medical Intelligence** (AME, ASKCTN, Curator Engine)
- ✅ **HIPAA-Compliant Architecture** with comprehensive audit trails
- ✅ **Multi-Provider Authentication** (Epic MyChart + Microsoft Entra ID)
- ✅ **Real-time Clinical Workflows** with advanced data integration

### **⚡ Technical Excellence**
- ✅ **100% API Documentation** with detailed request/response schemas
- ✅ **Enterprise Testing Framework** with performance and contract testing
- ✅ **Production-Ready CI/CD** with automated deployment pipelines
- ✅ **Advanced Security** with role-based access and data protection

### **📊 Quality Metrics**
- ✅ **36+ Comprehensive Documentation Files**
- ✅ **100% Coverage** of all API endpoints and system components
- ✅ **Source-Mirrored Organization** for intuitive navigation
- ✅ **Enterprise-Grade Security** documentation
- ✅ **Performance Optimization** guides and best practices
- ✅ **Complete Infrastructure** documentation (logging, caching, health checks)
- ✅ **Comprehensive Testing** frameworks and mock data services

## 🎯 **Target Audience**

- **🚀 Developers**: Complete API reference and implementation details
- **⚙️ DevOps Engineers**: CI/CD pipelines and deployment procedures
- **🧪 QA Engineers**: Testing frameworks and quality assurance
- **🔒 Security Teams**: Security implementation and compliance
- **🏥 Healthcare Administrators**: System capabilities and workflows

## 📞 **Support & Navigation**

### **Finding What You Need:**
1. **Know the source file?** → Check the corresponding docs folder
2. **Need API reference?** → Browse `docs/controllers/`
3. **Working on authentication?** → Read `docs/guards/guards.md`
4. **Database changes?** → Check `docs/types/types-and-migrations.md`

### **Support Channels:**
- **📧 General Support**: navigator-support@mayo.edu
- **🐛 Technical Issues**: Create GitHub issue
- **🔐 Security Concerns**: security@mayo.edu

---

## 🎯 **📚 Complete Documentation Suite Summary:**

### **🎯 For New Developers:**
- **[⭐ Onboarding Guide](setup/onboarding-guide.md)** - Your complete learning roadmap
- **[🏥 Project Overview](setup/project-overview.md)** - Healthcare context and goals
- **[⚙️ Development Setup](setup/development-setup.md)** - Get your environment running
- **[🏗️ System Architecture](architecture/system-overview.md)** - Big picture understanding

### **🔧 For Existing Developers:**
- **[📋 Complete Index](complete-documentation-index.md)** - All documentation organized
- **[🎯 Controllers](controllers/)** - API endpoint documentation
- **[🔧 Services](services/)** - Business logic and integrations
- **[🧪 Testing](testing/)** - Testing frameworks and patterns

### **📊 Documentation Statistics:**
- **📁 41 Documentation Files** - Complete coverage
- **🏗️ Source-Mirrored Structure** - Easy navigation
- **🎯 Role-Specific Guidance** - Tailored learning paths
- **⏱️ Structured Onboarding** - 6-10 hours over 4 weeks
- **🛡️ Infrastructure Coverage** - Logging, caching, health monitoring
- **🧪 Testing Excellence** - Mock data, performance testing, frameworks
- **🔐 Security Complete** - Audit trails, compliance, threat detection
- **🚀 Enterprise Features** - Advanced performance monitoring, health checks

---

**🌟 This documentation is now perfectly organized to mirror your source code structure, making it effortless to find the documentation you need for any component you're working on!**

**🎯 New developers: Start with the [Onboarding Guide](setup/onboarding-guide.md) - it's designed specifically for you! 🚀**
