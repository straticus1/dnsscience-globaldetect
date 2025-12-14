# GlobalDetect Inventory Compliance Guide

This document describes how GlobalDetect's Network Inventory system supports compliance with major regulatory frameworks and security standards.

## Table of Contents

1. [Overview](#overview)
2. [Shared Responsibility Model](#shared-responsibility-model)
3. [Supported Frameworks](#supported-frameworks)
4. [Technical Controls](#technical-controls)
5. [Configuration Guide](#configuration-guide)
6. [Audit and Evidence Collection](#audit-and-evidence-collection)

---

## Overview

GlobalDetect's Network Inventory system is designed with compliance in mind, providing technical controls that support organizations subject to various regulatory requirements. The system implements defense-in-depth security principles including:

- **Encryption at Rest** - AES-256/Fernet encryption for sensitive fields
- **Immutable Audit Logging** - Cryptographically chained audit trails
- **Data Retention Management** - Configurable retention with compliant purging
- **Access Control** - API key authentication with role-based access
- **Data Integrity** - Cryptographic checksums for tamper detection

### Compliance Frameworks Supported

| Framework | Full Name | Primary Focus |
|-----------|-----------|---------------|
| SOX | Sarbanes-Oxley Act | Financial reporting integrity |
| GLBA | Gramm-Leach-Bliley Act | Financial institution data protection |
| GDPR | General Data Protection Regulation | EU personal data protection |
| PCI-DSS | Payment Card Industry Data Security Standard | Cardholder data protection |
| CMMC | Cybersecurity Maturity Model Certification | Defense contractor security |
| NIST 800-53 | Security and Privacy Controls | Federal information systems |
| NIST 800-171 | Protecting CUI | Controlled unclassified information |
| FedRAMP | Federal Risk and Authorization Management | Cloud services for federal agencies |
| FISMA | Federal Information Security Management Act | Federal agency security |

---

## Shared Responsibility Model

GlobalDetect provides **technical controls** and **capabilities** that support compliance. However, achieving compliance requires a partnership between the software and the operating organization.

### GlobalDetect Provides

| Capability | Description |
|------------|-------------|
| Encryption Engine | FIPS-validated encryption algorithms (AES-256-GCM, PBKDF2) |
| Audit Logging | Immutable, cryptographically-chained audit events |
| Data Retention | Configurable retention periods with secure purging |
| Access Logging | Complete authentication and authorization logging |
| Integrity Verification | Tamper detection through cryptographic checksums |
| Sensitive Field Protection | Automatic encryption of PII, credentials, financial data |

### Customer Responsibilities

| Responsibility | Description |
|----------------|-------------|
| Key Management | Secure storage and rotation of encryption keys |
| Access Control | Implementing organizational access policies |
| Network Security | Firewall rules, VPN, network segmentation |
| Physical Security | Data center physical access controls |
| Backup & Recovery | Encrypted backups, disaster recovery procedures |
| Security Training | Employee security awareness training |
| Policy Documentation | Written security policies and procedures |
| Vulnerability Management | Patching and security updates |
| Incident Response | Documented incident response procedures |

---

## Supported Frameworks

### SOX (Sarbanes-Oxley Act)

**Applies to:** Publicly traded companies

**Relevant Sections:**
- Section 302: Corporate responsibility for financial reports
- Section 404: Internal controls assessment

**GlobalDetect Controls:**

| SOX Requirement | GlobalDetect Feature |
|-----------------|---------------------|
| Audit trail for financial data | Immutable audit logging with 7-year retention |
| Change management | All modifications logged with before/after states |
| Access controls | API key authentication, access logging |
| Data integrity | Cryptographic checksums, tamper detection |
| Segregation of duties | Role-based access control support |

**Configuration:**
```python
from globaldetect.inventory.audit import AuditConfig, ComplianceFramework

config = AuditConfig(
    enabled=True,
    compliance_frameworks=[ComplianceFramework.SOX],
    retention_days=2555,  # 7 years
    log_reads=True,
    log_writes=True,
)
```

---

### GLBA (Gramm-Leach-Bliley Act)

**Applies to:** Financial institutions

**Relevant Rules:**
- Safeguards Rule: Protect customer information
- Privacy Rule: Privacy notices and opt-out rights

**GlobalDetect Controls:**

| GLBA Requirement | GlobalDetect Feature |
|------------------|---------------------|
| Encryption of customer data | Field-level encryption for PII |
| Access monitoring | Comprehensive audit logging |
| Risk assessment support | Audit reports for security reviews |
| Data protection | Encryption at rest, secure transmission |

**Protected Fields (automatically encrypted):**
- `contact_email`
- `contact_phone`
- `contact_pagerduty`
- `contact_slack`
- `cost_center`
- `purchase_order`

---

### GDPR (General Data Protection Regulation)

**Applies to:** Organizations processing EU personal data

**Relevant Articles:**
- Article 5: Principles of data processing
- Article 17: Right to erasure
- Article 25: Data protection by design
- Article 30: Records of processing activities
- Article 32: Security of processing
- Article 33: Breach notification

**GlobalDetect Controls:**

| GDPR Article | GlobalDetect Feature |
|--------------|---------------------|
| Art. 5 - Data minimization | Configurable field collection |
| Art. 17 - Right to erasure | Data purging with audit trail |
| Art. 25 - Privacy by design | Encryption enabled by default for PII |
| Art. 30 - Processing records | Audit logs document all processing |
| Art. 32 - Security | Encryption, access controls, integrity checks |
| Art. 33 - Breach detection | Tamper detection, integrity verification |

**Data Subject Rights Support:**
```python
from globaldetect.inventory.audit import AuditLogger

# Generate data access report for GDPR Subject Access Request
logger = AuditLogger(config)
report = logger.generate_compliance_report(
    framework=ComplianceFramework.GDPR,
    start_date=datetime(2024, 1, 1),
    end_date=datetime.now(),
)
```

---

### PCI-DSS (Payment Card Industry Data Security Standard)

**Applies to:** Organizations handling payment card data

**Relevant Requirements:**
- Req 3: Protect stored cardholder data
- Req 7: Restrict access to cardholder data
- Req 8: Identify and authenticate access
- Req 10: Track and monitor all access
- Req 12: Maintain security policies

**GlobalDetect Controls:**

| PCI-DSS Requirement | GlobalDetect Feature |
|--------------------|---------------------|
| 3.4 - Render PAN unreadable | Field-level encryption |
| 3.5 - Key management | PBKDF2 key derivation, rotation support |
| 7.1 - Access restriction | API key authentication |
| 8.1 - User identification | User ID in all audit events |
| 10.1 - Audit trails | Immutable logging with timestamps |
| 10.2 - Automated audit trails | All access automatically logged |
| 10.3 - Audit trail entries | User, timestamp, action, success/failure |
| 10.5 - Secure audit trails | Cryptographic chaining, tamper detection |
| 10.7 - Audit history | Minimum 1-year retention (configurable) |

**Encryption Configuration:**
```python
from globaldetect.inventory.encryption import EncryptionConfig

config = EncryptionConfig(
    algorithm=EncryptionAlgorithm.AES_256_GCM,  # FIPS 140-2 approved
    kdf=KeyDerivationFunction.PBKDF2_SHA256,
    iterations=480000,  # OWASP 2023 recommendation
)
```

---

### CMMC (Cybersecurity Maturity Model Certification)

**Applies to:** Defense Industrial Base (DIB) contractors

**Levels Supported:**
- Level 1: Foundational
- Level 2: Advanced (supports NIST 800-171)
- Level 3: Expert (additional controls)

**GlobalDetect Controls:**

| CMMC Practice | GlobalDetect Feature |
|---------------|---------------------|
| AC.L1-3.1.1 - Limit access | API key authentication |
| AC.L2-3.1.7 - Privileged access | Role-based access control |
| AU.L2-3.3.1 - Audit events | Comprehensive audit logging |
| AU.L2-3.3.2 - Unique user IDs | User tracking in audit events |
| IA.L1-3.5.1 - Identification | API key and user identification |
| SC.L2-3.13.11 - CUI encryption | Encryption at rest for sensitive data |
| SC.L2-3.13.16 - Data at rest | Field-level encryption |

---

### NIST 800-53 (Security and Privacy Controls)

**Applies to:** Federal information systems

**Control Families Addressed:**

| Family | Controls | GlobalDetect Features |
|--------|----------|----------------------|
| AC (Access Control) | AC-2, AC-3, AC-6 | API authentication, access logging |
| AU (Audit) | AU-2, AU-3, AU-6, AU-9, AU-11 | Immutable logging, retention, review |
| IA (Identification) | IA-2, IA-4, IA-5 | User/system identification |
| SC (System/Comm) | SC-8, SC-12, SC-13, SC-28 | Encryption, key management |
| SI (System Integrity) | SI-7, SI-12 | Integrity verification, retention |

**Detailed Control Mapping:**

| Control | Description | Implementation |
|---------|-------------|----------------|
| AU-2 | Audit events | Login, CRUD operations, admin actions logged |
| AU-3 | Content of audit records | User, timestamp, action, target, before/after |
| AU-9 | Protection of audit information | Cryptographic chaining, append-only storage |
| AU-11 | Audit retention | Configurable retention (default 7 years) |
| SC-12 | Key management | PBKDF2 derivation, rotation support |
| SC-13 | Cryptographic protection | FIPS 140-2 validated algorithms |
| SC-28 | Protection at rest | AES-256 encryption for sensitive fields |

---

### NIST 800-171 (Protecting CUI)

**Applies to:** Non-federal systems with Controlled Unclassified Information

**Security Requirements Addressed:**

| Requirement | Description | GlobalDetect Feature |
|-------------|-------------|---------------------|
| 3.1.1 | Limit access | API key authentication |
| 3.1.2 | Limit transactions | Access control enforcement |
| 3.3.1 | Create audit records | Comprehensive audit logging |
| 3.3.2 | Unique user attribution | User ID in all events |
| 3.5.1 | Identify users | Authentication logging |
| 3.13.11 | Encrypt CUI at rest | Field-level encryption |
| 3.13.16 | Protect CUI confidentiality | Encryption for sensitive data |

---

### FedRAMP (Federal Risk and Authorization Management)

**Applies to:** Cloud services for federal agencies

**Impact Levels Supported:**
- Low
- Moderate
- High (with additional configuration)

**Control Implementation:**

| FedRAMP Control | GlobalDetect Feature |
|-----------------|---------------------|
| AU-2 | Audit event logging |
| AU-3 | Audit record content |
| AU-9 | Audit log protection |
| SC-13 | FIPS 140-2 validated cryptography |
| SC-28 | Encryption at rest |

**FIPS 140-2 Compliance:**
```python
from globaldetect.inventory.encryption import EncryptionAlgorithm

# Use FIPS 140-2 validated algorithm
config = EncryptionConfig(
    algorithm=EncryptionAlgorithm.AES_256_GCM,  # FIPS approved
)
```

---

### FISMA (Federal Information Security Management Act)

**Applies to:** Federal agencies and contractors

**Requirements Addressed:**

| FISMA Requirement | GlobalDetect Feature |
|-------------------|---------------------|
| Risk assessment | Audit logs for security analysis |
| Security controls | NIST 800-53 control implementation |
| Continuous monitoring | Real-time audit logging |
| Incident response | Audit trail for investigations |
| Documentation | Compliance reports |

---

## Technical Controls

### Encryption at Rest

GlobalDetect implements field-level encryption for sensitive data using industry-standard algorithms.

**Algorithms:**
- **AES-256-GCM** - FIPS 140-2 approved, authenticated encryption
- **Fernet** - AES-128-CBC with HMAC-SHA256

**Key Derivation:**
- PBKDF2-SHA256 with 480,000 iterations (OWASP 2023 recommendation)
- 256-bit key length
- Cryptographically random salt generation

**Encrypted Fields (Default):**
```
api_key, password, secret, token, private_key,
contact_email, contact_phone, contact_pagerduty, contact_slack,
cost_center, purchase_order, custom_fields
```

**Key Management:**
```bash
# Generate encryption key
globaldetect encryption generate-key > ~/.config/globaldetect/encryption.key
chmod 600 ~/.config/globaldetect/encryption.key

# Or use environment variable
export GLOBALDETECT_ENCRYPTION_KEY="base64-encoded-key"

# Or use AWS KMS (enterprise)
export GLOBALDETECT_KMS_KEY_ID="alias/globaldetect-encryption"
```

### Audit Logging

GlobalDetect implements cryptographically-chained audit logging that provides:

**Event Types:**
- Authentication events (login success/failure)
- Data access (reads)
- Data modification (create, update, delete)
- Administrative actions
- Data exports
- Retention/purge operations

**Audit Record Fields:**
```json
{
  "event_id": "uuid",
  "timestamp": "ISO-8601",
  "action": "create|read|update|delete|...",
  "resource_type": "system|switch|location|...",
  "resource_id": "identifier",
  "user_id": "authenticated-user",
  "ip_address": "client-ip",
  "user_agent": "client-info",
  "details": {"before": {...}, "after": {...}},
  "success": true,
  "checksum": "sha256-hash",
  "previous_checksum": "chain-link"
}
```

**Integrity Verification:**
```python
from globaldetect.inventory.audit import AuditLogger

logger = AuditLogger(config)
is_valid, errors = logger.verify_chain_integrity()
if not is_valid:
    print("Tamper detected:", errors)
```

### Data Retention

GlobalDetect supports configurable data retention with secure purging:

| Framework | Minimum Retention |
|-----------|-------------------|
| SOX | 7 years |
| GLBA | 6 years |
| GDPR | As needed (minimize) |
| PCI-DSS | 1 year |
| HIPAA | 6 years |
| FedRAMP | 3 years |

**Retention Configuration:**
```python
from globaldetect.inventory.audit import RetentionPolicy

policy = RetentionPolicy(
    default_days=2555,  # 7 years
    framework_overrides={
        ComplianceFramework.PCI_DSS: 365,
        ComplianceFramework.GDPR: 1095,  # 3 years
    }
)
```

---

## Configuration Guide

### Minimum Compliance Configuration

```python
from globaldetect.inventory.audit import AuditConfig, ComplianceFramework
from globaldetect.inventory.encryption import EncryptionConfig

# Audit configuration
audit_config = AuditConfig(
    enabled=True,
    log_file="/var/log/globaldetect/audit.jsonl",
    retention_days=2555,  # 7 years for SOX
    log_reads=True,
    log_writes=True,
    log_authentication=True,
    compliance_frameworks=[
        ComplianceFramework.SOX,
        ComplianceFramework.PCI_DSS,
        ComplianceFramework.NIST_800_53,
    ],
    immutable_storage=True,
    chain_verification=True,
)

# Encryption configuration
encryption_config = EncryptionConfig(
    algorithm=EncryptionAlgorithm.AES_256_GCM,
    kdf=KeyDerivationFunction.PBKDF2_SHA256,
    iterations=480000,
    key_env_var="GLOBALDETECT_ENCRYPTION_KEY",
)
```

### PostgreSQL Enterprise Configuration

```bash
# Database with encryption
export GLOBALDETECT_DB="postgresql://user:pass@host/inventory?sslmode=require"

# Encryption key (use secrets manager in production)
export GLOBALDETECT_ENCRYPTION_KEY="$(aws secretsmanager get-secret-value ...)"

# Initialize with encryption
globaldetect db init --encrypt-sensitive-fields
```

### AWS Deployment

```bash
# RDS PostgreSQL with encryption
export GLOBALDETECT_DB="postgresql://user:pass@mydb.xxx.rds.amazonaws.com/inventory"

# KMS for key management
export GLOBALDETECT_USE_KMS=true
export GLOBALDETECT_KMS_KEY_ID="alias/globaldetect-key"

# S3 for audit log archival
export GLOBALDETECT_AUDIT_ARCHIVE_BUCKET="my-audit-logs"
```

---

## Audit and Evidence Collection

### Generating Compliance Reports

```python
from globaldetect.inventory.audit import AuditLogger, ComplianceFramework
from datetime import datetime, timedelta

logger = AuditLogger(config)

# SOX annual audit report
sox_report = logger.generate_compliance_report(
    framework=ComplianceFramework.SOX,
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 12, 31),
)

# PCI-DSS quarterly review
pci_report = logger.generate_compliance_report(
    framework=ComplianceFramework.PCI_DSS,
    start_date=datetime.now() - timedelta(days=90),
    end_date=datetime.now(),
)
```

### Evidence for Auditors

| Evidence Type | Location | Description |
|---------------|----------|-------------|
| Audit Logs | `/var/log/globaldetect/audit.jsonl` | All system activity |
| Integrity Proof | `verify_chain_integrity()` | Cryptographic verification |
| Compliance Report | `generate_compliance_report()` | Framework-specific summary |
| Encryption Keys | Secrets Manager / HSM | Key inventory and rotation history |
| Access Logs | Application logs | Authentication records |

### Integrity Verification for Auditors

```bash
# Verify audit log chain hasn't been tampered with
globaldetect audit verify --start-date 2024-01-01 --end-date 2024-12-31

# Export audit logs for external review
globaldetect audit export --format json --output audit-2024.json

# Generate SOX compliance evidence package
globaldetect audit report --framework sox --year 2024 --output sox-evidence/
```

---

## Security Recommendations

### Production Deployment Checklist

- [ ] Enable encryption at rest for all sensitive fields
- [ ] Store encryption keys in HSM or secrets manager (not filesystem)
- [ ] Configure audit log shipping to immutable storage (S3 Glacier, etc.)
- [ ] Enable TLS 1.3 for all network communications
- [ ] Implement network segmentation for inventory database
- [ ] Configure backup encryption
- [ ] Enable database audit logging (PostgreSQL pg_audit)
- [ ] Implement key rotation schedule
- [ ] Document incident response procedures
- [ ] Conduct regular integrity verification
- [ ] Perform annual security assessments

### Key Rotation

```python
from globaldetect.inventory.encryption import EncryptionManager

manager = EncryptionManager(config)

# Generate new key
new_key = EncryptionManager.generate_key()

# Rotate all encrypted data
manager.rotate_key(new_key, all_records)

# Update key in secrets manager
# Archive old key per retention requirements
```

---

## Limitations and Disclaimers

1. **Not a Complete Solution**: GlobalDetect provides technical controls that *support* compliance but does not guarantee compliance. Organizations must implement additional administrative, physical, and procedural controls.

2. **Customer Configuration Required**: Many compliance features require proper configuration. Default settings may not meet all requirements.

3. **Shared Responsibility**: Compliance is a shared responsibility between the software, cloud provider, and operating organization.

4. **Legal Advice**: This document is not legal advice. Consult with compliance professionals and legal counsel for your specific requirements.

5. **Certification**: GlobalDetect has not been independently certified for any compliance framework. Organizations should conduct their own assessments.

6. **Updates**: Compliance requirements change. Organizations should monitor regulatory updates and adjust configurations accordingly.

---

## Contact and Support

For compliance-related questions:
- Documentation: https://dnsscience.io/docs/globaldetect/compliance
- GitHub Issues: https://github.com/dnsscience/globaldetect/issues
- Security Issues: security@dnsscience.io

---

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
