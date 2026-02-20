
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# DAVE API Fields Reference

**Device Assessment and Vulnerability Exposure (DAVE)**  
**API Fields Reference Documentation**

---

This document provides a comprehensive list of all available fields for GET and PUT requests for each API endpoint in the Device Assessment and Vulnerability Exposure (DAVE).

## Table of Contents

### GET Requests
- [Authentication](#authentication)
- [Assets](#assets)
- [Vulnerabilities](#vulnerabilities)
- [Software Components](#software-components)
- [Recalls](#recalls)
- [Patches](#patches)
- [Locations](#locations)
- [Device Mapping](#device-mapping)
- [Risk Priorities](#risk-priorities)
- [Software Packages](#software-packages)
- [Remediation Actions](#remediation-actions)
- [Threats](#threats)
- [Analytics](#analytics)
- [Reports](#reports)
- [EPSS Analytics](#epss-analytics)

### POST Requests
- [POST Vulnerabilities Evaluate](#post-vulnerabilities-evaluate)
- [POST Components](#post-components)
- [POST Reports Export](#post-reports-export)
- [POST Reports Schedule](#post-reports-schedule)
- [POST Location Assignment](#post-location-assignment)

### PUT Requests
- [PUT Assets](#put-assets)
- [PUT Vulnerabilities](#put-vulnerabilities)
- [PUT Components](#put-components)
- [PUT Recalls](#put-recalls)
- [PUT Patches](#put-patches)
- [PUT Locations](#put-locations)
- [PUT Risk Priorities](#put-risk-priorities)
- [PUT Remediation Actions](#put-remediation-actions)

---

## Authentication

### GET /api/v1/auth/me

**Description:** Get current user information

**Response Fields:**
```json
{
  "success": boolean,
  "user": {
    "user_id": "string (UUID)",
    "username": "string",
    "email": "string",
    "role": "string (Admin|User)",
    "is_active": boolean,
    "last_login": "string (ISO 8601 datetime)",
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)",
    "mfa_enabled": boolean,
    "failed_login_attempts": integer,
    "account_locked_until": "string (ISO 8601 datetime) | null"
  }
}
```

---

## Assets

### GET /api/v1/assets

**Description:** List all assets with pagination and filtering

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "asset_id": "string (UUID)",
      "hostname": "string",
      "ip_address": "string",
      "asset_type": "string (Server|Workstation|Network Device|Medical Device|Other)",
      "criticality": "string (Clinical-High|Clinical-Medium|Clinical-Low|Non-Clinical-High|Non-Clinical-Medium|Non-Clinical-Low)",
      "department": "string",
      "status": "string (Active|Inactive|Maintenance|Retired)",
      "location_id": "string (UUID)",
      "asset_tag": "string",
      "serial_number": "string",
      "manufacturer": "string",
      "model": "string",
      "os_version": "string",
      "os_type": "string (Windows|Linux|macOS|Other)",
      "last_scan_date": "string (ISO 8601 datetime)",
      "vulnerability_count": integer,
      "critical_vulnerability_count": integer,
      "high_vulnerability_count": integer,
      "medium_vulnerability_count": integer,
      "low_vulnerability_count": integer,
      "kev_vulnerability_count": integer,
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)",
      "created_by": "string (UUID)",
      "updated_by": "string (UUID)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/assets/{asset_id}

**Description:** Get specific asset details with complete information including medical device mapping

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "asset_id": "string (UUID)",
    "hostname": "string",
    "ip_address": "string",
    "mac_address": "string",
    "asset_type": "string (Server|Workstation|Network Device|Medical Device|Other)",
    "asset_subtype": "string",
    "manufacturer": "string",
    "model": "string",
    "serial_number": "string",
    "location": "string",
    "firmware_version": "string",
    "cpu": "string",
    "memory_ram": "string",
    "storage": "string",
    "power_requirements": "string",
    "primary_communication_protocol": "string",
    "assigned_admin_user": "string",
    "business_unit": "string",
    "department": "string",
    "cost_center": "string",
    "warranty_expiration_date": "string (ISO 8601 date)",
    "scheduled_replacement_date": "string (ISO 8601 date)",
    "disposal_date": "string (ISO 8601 date)",
    "disposal_method": "string",
    "criticality": "string (Clinical-High|Clinical-Medium|Clinical-Low|Non-Clinical-High|Non-Clinical-Medium|Non-Clinical-Low)",
    "regulatory_classification": "string",
    "phi_status": "string",
    "data_encryption_transit": "string",
    "data_encryption_rest": "string",
    "authentication_method": "string",
    "patch_level_last_update": "string",
    "last_audit_date": "string (ISO 8601 date)",
    "source": "string",
    "status": "string (Active|Inactive|Maintenance|Retired)",
    "first_seen": "string (ISO 8601 datetime)",
    "last_seen": "string (ISO 8601 datetime)",
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)",
    "mapping_status": "string (Mapped|Unmapped)",
    "device_id": "string (UUID) | null",
    "device_identifier": "string | null",
    "brand_name": "string | null",
    "model_number": "string | null",
    "manufacturer_name": "string | null",
    "device_description": "string | null",
    "gmdn_term": "string | null",
    "is_implantable": "boolean | null",
    "fda_class": "string | null",
    "udi": "string | null",
    "mapping_confidence": "string | null",
    "mapping_method": "string | null",
    "mapped_at": "string (ISO 8601 datetime) | null"
  }
}
```

---

## Vulnerabilities

### GET /api/v1/vulnerabilities

**Description:** List vulnerabilities with filtering options

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Results per page (default: 25, max: 100)
- `search` (optional): Search in CVE ID or description
- `severity` (optional): Filter by severity (Critical, High, Medium, Low)
- `status` (optional): Filter by remediation status
- `asset_id` (optional): Filter by specific asset
- `epss-gt` (optional): Filter by EPSS score greater than value (0.0-1.0)
- `epss-percentile-gt` (optional): Filter by EPSS percentile greater than value (0.0-1.0)
- `sort` (optional): Sort field (severity, cvss_score, published_date, epss, epss_percentile, affected_assets)
- `sort_dir` (optional): Sort direction (asc, desc, default: desc)

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "cve_id": "string",
      "description": "string",
      "severity": "string (Critical|High|Medium|Low)",
      "cvss_v4_score": number,
      "cvss_v3_score": number,
      "cvss_v2_score": number,
      "cvss_v4_vector": "string",
      "cvss_v3_vector": "string",
      "cvss_v2_vector": "string",
      "is_kev": boolean,
      "kev_due_date": "string (ISO 8601 datetime) | null",
      "published_date": "string (ISO 8601 datetime)",
      "last_modified_date": "string (ISO 8601 datetime)",
      "epss_score": "decimal (0.0000-1.0000) | null",
      "epss_percentile": "decimal (0.0000-1.0000) | null",
      "epss_date": "string (ISO 8601 date) | null",
      "epss_last_updated": "string (ISO 8601 datetime) | null",
      "affected_assets_count": integer,
      "affected_assets": [
        {
          "asset_id": "string (UUID)",
          "hostname": "string",
          "ip_address": "string",
          "criticality": "string"
        }
      ],
      "references": [
        {
          "url": "string",
          "source": "string"
        }
      ],
      "cwe_ids": ["string"],
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/vulnerabilities/{cve_id}

**Description:** Get specific vulnerability details

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "cve_id": "string",
    "description": "string",
    "severity": "string",
    "cvss_v4_score": number,
    "cvss_v3_score": number,
    "cvss_v2_score": number,
    "cvss_v4_vector": "string",
    "cvss_v3_vector": "string",
    "cvss_v2_vector": "string",
    "is_kev": boolean,
    "kev_due_date": "string (ISO 8601 datetime) | null",
    "published_date": "string (ISO 8601 datetime)",
    "last_modified_date": "string (ISO 8601 datetime)",
    "epss_score": "decimal (0.0000-1.0000) | null",
    "epss_percentile": "decimal (0.0000-1.0000) | null",
    "epss_date": "string (ISO 8601 date) | null",
    "epss_last_updated": "string (ISO 8601 datetime) | null",
    "affected_assets_count": integer,
    "affected_assets": [
      {
        "asset_id": "string (UUID)",
        "hostname": "string",
        "ip_address": "string",
        "criticality": "string",
        "location_name": "string",
        "department": "string"
      }
    ],
    "references": [
      {
        "url": "string",
        "source": "string",
        "tags": ["string"]
      }
    ],
    "cwe_ids": ["string"],
    "software_packages": [
      {
        "package_id": "string (UUID)",
        "package_name": "string",
        "version": "string",
        "vendor": "string"
      }
    ],
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

## Software Components

### GET /api/v1/components

**Description:** List all software components with optional filtering and pagination

**Authentication:** Required (API Key or Session)

**Permissions:** `components:read` scope required

**Query Parameters:**
- `limit` (integer, optional): Maximum number of results (default: 100, max: 1000)
- `offset` (integer, optional): Number of results to skip for pagination (default: 0)
- `search` (string, optional): Search by component name, vendor, or version
- `independent_only` (boolean, optional): If `true`, returns only components created independently (not from SBOM)

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "component_id": "string (UUID)",
      "sbom_id": "string (UUID) | null - null for independent components",
      "name": "string - Component name",
      "version": "string | null - Component version",
      "vendor": "string | null - Vendor or publisher name",
      "license": "string | null - License identifier",
      "purl": "string | null - Package URL (PURL)",
      "cpe": "string | null - Common Platform Enumeration (CPE)",
      "created_at": "string (ISO 8601 datetime)",
      "package_id": "string (UUID) | null - Link to software_packages table",
      "version_id": "string (UUID) | null - Link to software_package_versions table"
    }
  ],
  "pagination": {
    "total": integer,
    "limit": integer,
    "offset": integer,
    "has_more": boolean
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/components/{component_id}

**Description:** Get a specific software component by ID

**Authentication:** Required (API Key or Session)

**Permissions:** `components:read` scope required

**Path Parameters:**
- `component_id` (UUID, required): Software component UUID

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "component_id": "string (UUID)",
    "sbom_id": "string (UUID) | null",
    "name": "string",
    "version": "string | null",
    "vendor": "string | null",
    "license": "string | null",
    "purl": "string | null",
    "cpe": "string | null",
    "created_at": "string (ISO 8601 datetime)",
    "package_id": "string (UUID) | null",
    "version_id": "string (UUID) | null"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Error Responses:**

**404 Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_NOT_FOUND",
    "message": "Software component not found"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

---

## Recalls

### GET /api/v1/recalls

**Description:** List medical device recalls

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "recall_id": "string (UUID)",
      "recall_number": "string",
      "product_name": "string",
      "manufacturer": "string",
      "model_number": "string",
      "serial_numbers": ["string"],
      "recall_date": "string (ISO 8601 date)",
      "recall_status": "string (Active|Resolved|Cancelled)",
      "reason": "string",
      "risk_level": "string (Class I|Class II|Class III)",
      "affected_devices_count": integer,
      "affected_devices": [
        {
          "device_id": "string (UUID)",
          "device_name": "string",
          "location_name": "string",
          "department": "string"
        }
      ],
      "fda_url": "string",
      "contact_information": {
        "phone": "string",
        "email": "string",
        "website": "string"
      },
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/recalls/{recall_id}

**Description:** Get specific recall details

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "recall_id": "string (UUID)",
    "recall_number": "string",
    "product_name": "string",
    "manufacturer": "string",
    "model_number": "string",
    "serial_numbers": ["string"],
    "recall_date": "string (ISO 8601 date)",
    "recall_status": "string",
    "reason": "string",
    "risk_level": "string",
    "description": "string",
    "affected_devices_count": integer,
    "affected_devices": [
      {
        "device_id": "string (UUID)",
        "device_name": "string",
        "asset_id": "string (UUID)",
        "hostname": "string",
        "ip_address": "string",
        "location_name": "string",
        "department": "string",
        "criticality": "string"
      }
    ],
    "fda_url": "string",
    "contact_information": {
      "phone": "string",
      "email": "string",
      "website": "string"
    },
    "related_vulnerabilities": [
      {
        "cve_id": "string",
        "severity": "string",
        "description": "string"
      }
    ],
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

## Patches

### GET /api/v1/patches

**Description:** List available patches

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "patch_id": "string (UUID)",
      "patch_name": "string",
      "patch_type": "string (Security|Feature|Bug Fix|Critical)",
      "target_package_id": "string (UUID)",
      "target_package_name": "string",
      "target_version": "string",
      "patch_version": "string",
      "cve_count": integer,
      "cvss_score": number,
      "release_date": "string (ISO 8601 datetime)",
      "is_active": boolean,
      "affected_assets_count": integer,
      "applied_assets_count": integer,
      "cve_list": [
        {
          "cve_id": "string",
          "severity": "string",
          "cvss_score": number
        }
      ],
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/patches/{patch_id}

**Description:** Get specific patch details

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "patch_id": "string (UUID)",
    "patch_name": "string",
    "patch_type": "string",
    "target_package_id": "string (UUID)",
    "target_package_name": "string",
    "target_version": "string",
    "patch_version": "string",
    "cve_count": integer,
    "cvss_score": number,
    "release_date": "string (ISO 8601 datetime)",
    "is_active": boolean,
    "description": "string",
    "installation_instructions": "string",
    "rollback_instructions": "string",
    "affected_assets_count": integer,
    "applied_assets_count": integer,
    "affected_assets": [
      {
        "asset_id": "string (UUID)",
        "hostname": "string",
        "ip_address": "string",
        "current_version": "string",
        "patch_status": "string (Pending|Applied|Failed|Rolled Back)"
      }
    ],
    "cve_list": [
      {
        "cve_id": "string",
        "severity": "string",
        "cvss_score": number,
        "description": "string"
      }
    ],
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

## Locations

### GET /api/v1/locations

**Description:** List all locations

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "location_id": "string (UUID)",
      "location_name": "string",
      "location_type": "string (Clinical|Non-Clinical|Administrative|Support)",
      "criticality": integer (1-10),
      "floor": integer,
      "room_number": "string",
      "building": "string",
      "department": "string",
      "asset_count": integer,
      "vulnerability_count": integer,
      "critical_vulnerability_count": integer,
      "ip_range_start": "string",
      "ip_range_end": "string",
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/locations/{location_id}

**Description:** Get specific location details

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "location_id": "string (UUID)",
    "location_name": "string",
    "location_type": "string",
    "criticality": integer,
    "floor": integer,
    "room_number": "string",
    "building": "string",
    "department": "string",
    "asset_count": integer,
    "vulnerability_count": integer,
    "critical_vulnerability_count": integer,
    "ip_range_start": "string",
    "ip_range_end": "string",
    "assets": [
      {
        "asset_id": "string (UUID)",
        "hostname": "string",
        "ip_address": "string",
        "asset_type": "string",
        "criticality": "string",
        "status": "string"
      }
    ],
    "created_at": "string (ISO 8601 datetime)",
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

### GET /api/v1/locations/simple

**Description:** Get simplified location list for dropdowns

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "location_id": "string (UUID)",
      "location_name": "string",
      "location_type": "string",
      "criticality": integer,
      "asset_count": integer
    }
  ]
}
```

---

## Device Mapping

### GET /api/v1/devices/map

**Description:** List device-to-asset mappings

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "mapping_id": "string (UUID)",
      "device_id": "string (UUID)",
      "device_name": "string",
      "device_type": "string",
      "manufacturer": "string",
      "model": "string",
      "serial_number": "string",
      "asset_id": "string (UUID)",
      "asset_hostname": "string",
      "asset_ip_address": "string",
      "location_name": "string",
      "department": "string",
      "mapped_at": "string (ISO 8601 datetime)",
      "mapped_by": "string (UUID)",
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

---

## Risk Priorities

### GET /api/v1/risk-priorities

**Description:** List prioritized vulnerabilities

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "link_id": "string (UUID)",
      "cve_id": "string",
      "hostname": "string",
      "ip_address": "string",
      "device_name": "string",
      "severity": "string (Critical|High|Medium|Low)",
      "asset_criticality": "string",
      "location_criticality": integer,
      "is_kev": boolean,
      "cvss_v3_score": number,
      "cvss_v4_score": number,
      "calculated_risk_score": number,
      "priority_tier": integer (1|2|3),
      "location_name": "string",
      "department": "string",
      "asset_type": "string",
      "published_date": "string (ISO 8601 datetime)",
      "kev_due_date": "string (ISO 8601 datetime) | null",
      "days_since_published": integer,
      "days_until_kev_due": integer | null,
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/risk-priorities/stats

**Description:** Get risk priority statistics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "tier_1_count": integer,
    "tier_2_count": integer,
    "tier_3_count": integer,
    "total_count": integer,
    "kev_count": integer,
    "critical_count": integer,
    "high_count": integer,
    "medium_count": integer,
    "low_count": integer,
    "average_risk_score": number,
    "highest_risk_score": number,
    "tier_breakdown": {
      "tier_1": {
        "count": integer,
        "percentage": number,
        "average_risk_score": number
      },
      "tier_2": {
        "count": integer,
        "percentage": number,
        "average_risk_score": number
      },
      "tier_3": {
        "count": integer,
        "percentage": number,
        "average_risk_score": number
      }
    },
    "severity_breakdown": {
      "critical": {
        "count": integer,
        "percentage": number
      },
      "high": {
        "count": integer,
        "percentage": number
      },
      "medium": {
        "count": integer,
        "percentage": number
      },
      "low": {
        "count": integer,
        "percentage": number
      }
    }
  }
}
```

---

## Software Packages

### GET /api/v1/software-packages/risk-priorities.php

**Description:** List software packages with risk priorities

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "package_id": "string (UUID)",
      "package_name": "string",
      "vendor": "string",
      "version": "string",
      "total_vulnerabilities": integer,
      "kev_count": integer,
      "critical_severity_count": integer,
      "high_severity_count": integer,
      "medium_severity_count": integer,
      "low_severity_count": integer,
      "affected_assets_count": integer,
      "aggregate_risk_score": number,
      "priority_tier": integer (1|2|3),
      "latest_vulnerability_date": "string (ISO 8601 datetime)",
      "affected_assets": [
        {
          "asset_id": "string (UUID)",
          "hostname": "string",
          "ip_address": "string",
          "location_name": "string",
          "department": "string"
        }
      ],
      "vulnerabilities": [
        {
          "cve_id": "string",
          "severity": "string",
          "cvss_score": number,
          "is_kev": boolean
        }
      ],
      "created_at": "string (ISO 8601 datetime)",
      "updated_at": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/software-packages/risk-priorities.php/{package_id}/affected-assets

**Description:** Get affected assets for a specific package

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "asset_id": "string (UUID)",
      "hostname": "string",
      "ip_address": "string",
      "asset_type": "string",
      "criticality": "string",
      "status": "string",
      "location_name": "string",
      "department": "string",
      "package_version": "string",
      "vulnerability_count": integer,
      "critical_vulnerability_count": integer,
      "kev_vulnerability_count": integer,
      "last_scan_date": "string (ISO 8601 datetime)"
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

### GET /api/v1/software-packages/risk-priorities.php/{package_id}/vulnerabilities

**Description:** Get vulnerabilities for a specific package

**Response Fields:**
```json
{
  "success": boolean,
  "data": [
    {
      "cve_id": "string",
      "description": "string",
      "severity": "string",
      "cvss_v3_score": number,
      "cvss_v4_score": number,
      "is_kev": boolean,
      "published_date": "string (ISO 8601 datetime)",
      "kev_due_date": "string (ISO 8601 datetime) | null",
      "affected_assets_count": integer,
      "affected_assets": [
        {
          "asset_id": "string (UUID)",
          "hostname": "string",
          "ip_address": "string",
          "location_name": "string"
        }
      ]
    }
  ],
  "pagination": {
    "page": integer,
    "limit": integer,
    "total": integer,
    "pages": integer
  }
}
```

---

## Analytics

### GET /api/v1/analytics/dashboard

**Description:** Get dashboard analytics summary

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "summary": {
      "assets": {
        "total_assets": integer,
        "mapped_assets": integer,
        "unmapped_assets": integer,
        "critical_assets": integer,
        "active_assets": integer,
        "inactive_assets": integer,
        "assets_by_type": {
          "Server": integer,
          "Workstation": integer,
          "Network Device": integer,
          "Medical Device": integer,
          "Other": integer
        },
        "assets_by_criticality": {
          "Clinical-High": integer,
          "Clinical-Medium": integer,
          "Clinical-Low": integer,
          "Non-Clinical-High": integer,
          "Non-Clinical-Medium": integer,
          "Non-Clinical-Low": integer
        }
      },
      "vulnerabilities": {
        "total_vulnerabilities": integer,
        "critical_vulns": integer,
        "high_vulns": integer,
        "medium_vulns": integer,
        "low_vulns": integer,
        "kev_vulns": integer,
        "open_vulns": integer,
        "resolved_vulns": integer,
        "vulns_by_severity": {
          "Critical": integer,
          "High": integer,
          "Medium": integer,
          "Low": integer
        }
      },
      "recalls": {
        "total_recalls": integer,
        "active_recalls": integer,
        "resolved_recalls": integer,
        "affected_devices": integer,
        "recalls_by_risk": {
          "Class I": integer,
          "Class II": integer,
          "Class III": integer
        }
      },
      "compliance": {
        "kev_compliance_percentage": number,
        "patch_compliance_percentage": number,
        "scan_compliance_percentage": number,
        "overall_compliance_score": number
      }
    },
    "trends": {
      "assets_added": [
        {
          "date": "string (YYYY-MM-DD)",
          "assets_added": integer
        }
      ],
      "vulnerabilities_discovered": [
        {
          "date": "string (YYYY-MM-DD)",
          "vulnerabilities_discovered": integer
        }
      ],
      "vulnerabilities_resolved": [
        {
          "date": "string (YYYY-MM-DD)",
          "vulnerabilities_resolved": integer
        }
      ]
    },
    "top_vulnerabilities": [
      {
        "cve_id": "string",
        "severity": "string",
        "affected_assets_count": integer,
        "cvss_score": number
      }
    ],
    "top_affected_assets": [
      {
        "asset_id": "string (UUID)",
        "hostname": "string",
        "vulnerability_count": integer,
        "critical_vulnerability_count": integer
      }
    ]
  }
}
```

### GET /api/v1/analytics/dashboard?path=assets

**Description:** Get detailed asset analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "asset_distribution": {
      "by_type": {
        "Server": integer,
        "Workstation": integer,
        "Network Device": integer,
        "Medical Device": integer,
        "Other": integer
      },
      "by_criticality": {
        "Clinical-High": integer,
        "Clinical-Medium": integer,
        "Clinical-Low": integer,
        "Non-Clinical-High": integer,
        "Non-Clinical-Medium": integer,
        "Non-Clinical-Low": integer
      },
      "by_department": {
        "ICU": integer,
        "Emergency": integer,
        "Surgery": integer,
        "IT": integer,
        "Administration": integer
      },
      "by_status": {
        "Active": integer,
        "Inactive": integer,
        "Maintenance": integer,
        "Retired": integer
      }
    },
    "vulnerability_coverage": {
      "scanned_assets": integer,
      "unscanned_assets": integer,
      "scan_percentage": number,
      "last_scan_dates": {
        "within_24h": integer,
        "within_7d": integer,
        "within_30d": integer,
        "over_30d": integer
      }
    },
    "risk_distribution": {
      "high_risk_assets": integer,
      "medium_risk_assets": integer,
      "low_risk_assets": integer,
      "average_risk_score": number
    }
  }
}
```

### GET /api/v1/analytics/dashboard?path=vulnerabilities

**Description:** Get detailed vulnerability analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "vulnerability_distribution": {
      "by_severity": {
        "Critical": integer,
        "High": integer,
        "Medium": integer,
        "Low": integer
      },
      "by_status": {
        "Open": integer,
        "In Progress": integer,
        "Resolved": integer,
        "False Positive": integer
      },
      "kev_vs_non_kev": {
        "kev": integer,
        "non_kev": integer
      }
    },
    "cvss_distribution": {
      "cvss_v3": {
        "0.0-3.9": integer,
        "4.0-6.9": integer,
        "7.0-8.9": integer,
        "9.0-10.0": integer
      },
      "cvss_v4": {
        "0.0-3.9": integer,
        "4.0-6.9": integer,
        "7.0-8.9": integer,
        "9.0-10.0": integer
      }
    },
    "age_distribution": {
      "published_this_week": integer,
      "published_this_month": integer,
      "published_this_quarter": integer,
      "published_this_year": integer,
      "published_over_year_ago": integer
    },
    "top_cwe_categories": [
      {
        "cwe_id": "string",
        "name": "string",
        "count": integer,
        "percentage": number
      }
    ]
  }
}
```

### GET /api/v1/analytics/dashboard?path=recalls

**Description:** Get detailed recall analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "recall_distribution": {
      "by_status": {
        "Active": integer,
        "Resolved": integer,
        "Cancelled": integer
      },
      "by_risk_level": {
        "Class I": integer,
        "Class II": integer,
        "Class III": integer
      },
      "by_manufacturer": {
        "Manufacturer A": integer,
        "Manufacturer B": integer,
        "Manufacturer C": integer
      }
    },
    "affected_devices": {
      "total_affected": integer,
      "devices_by_location": {
        "ICU": integer,
        "Emergency": integer,
        "Surgery": integer
      },
      "devices_by_type": {
        "Medical Device": integer,
        "Server": integer,
        "Workstation": integer
      }
    },
    "timeline": {
      "recalls_this_month": integer,
      "recalls_this_quarter": integer,
      "recalls_this_year": integer,
      "average_resolution_time_days": number
    }
  }
}
```

### GET /api/v1/analytics/dashboard?path=compliance

**Description:** Get compliance analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "overall_compliance": {
      "score": number,
      "grade": "string (A|B|C|D|F)",
      "last_updated": "string (ISO 8601 datetime)"
    },
    "kev_compliance": {
      "percentage": number,
      "total_kev_vulns": integer,
      "resolved_kev_vulns": integer,
      "overdue_kev_vulns": integer,
      "days_until_due": [
        {
          "cve_id": "string",
          "days_until_due": integer,
          "severity": "string"
        }
      ]
    },
    "patch_compliance": {
      "percentage": number,
      "total_patches": integer,
      "applied_patches": integer,
      "pending_patches": integer,
      "failed_patches": integer
    },
    "scan_compliance": {
      "percentage": number,
      "total_assets": integer,
      "scanned_assets": integer,
      "unscanned_assets": integer,
      "last_scan_ages": {
        "within_24h": integer,
        "within_7d": integer,
        "within_30d": integer,
        "over_30d": integer
      }
    },
    "compliance_trends": [
      {
        "date": "string (YYYY-MM-DD)",
        "overall_score": number,
        "kev_score": number,
        "patch_score": number,
        "scan_score": number
      }
    ]
  }
}
```

---

## Analytics

### GET /api/v1/analytics/dashboard

**Description:** Get dashboard analytics and metrics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "summary": {
      "assets": {
        "total_assets": integer,
        "mapped_assets": integer,
        "critical_assets": integer,
        "active_assets": integer
      },
      "vulnerabilities": {
        "total_vulnerabilities": integer,
        "critical_vulns": integer,
        "high_vulns": integer,
        "open_vulns": integer
      },
      "recalls": {
        "total_recalls": integer,
        "active_recalls": integer,
        "affected_devices": integer
      }
    },
    "trends": {
      "assets_added": [
        {
          "date": "string (ISO 8601 date)",
          "assets_added": integer
        }
      ]
    },
    "date_range": {
      "from": "string (ISO 8601 date)",
      "to": "string (ISO 8601 date)"
    },
    "department": "string"
  }
}
```

### GET /api/v1/analytics/dashboard/assets

**Description:** Get asset analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "type_distribution": [
      {
        "asset_type": "string",
        "count": integer,
        "mapped_count": integer
      }
    ],
    "department_distribution": [
      {
        "department": "string",
        "count": integer
      }
    ],
    "criticality_distribution": [
      {
        "criticality": "string",
        "count": integer
      }
    ]
  }
}
```

### GET /api/v1/analytics/dashboard/vulnerabilities

**Description:** Get vulnerability analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "severity_distribution": [
      {
        "severity": "string",
        "count": integer,
        "affected_assets": integer
      }
    ],
    "status_distribution": [
      {
        "remediation_status": "string",
        "count": integer
      }
    ],
    "top_affected_assets": [
      {
        "asset_id": "string (UUID)",
        "hostname": "string",
        "asset_type": "string",
        "department": "string",
        "vulnerability_count": integer,
        "critical_count": integer
      }
    ]
  }
}
```

### GET /api/v1/analytics/dashboard/recalls

**Description:** Get recall analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "status_distribution": [
      {
        "recall_status": "string",
        "count": integer
      }
    ],
    "manufacturer_distribution": [
      {
        "manufacturer": "string",
        "count": integer
      }
    ],
    "recent_recalls": [
      {
        "recall_id": "string (UUID)",
        "recall_number": "string",
        "product_name": "string",
        "manufacturer": "string",
        "recall_date": "string (ISO 8601 date)",
        "recall_status": "string",
        "affected_devices": integer
      }
    ]
  }
}
```

### GET /api/v1/analytics/dashboard/compliance

**Description:** Get compliance analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "compliance_metrics": {
      "total_assets": integer,
      "mapped_assets": integer,
      "assets_with_vulnerabilities": integer,
      "assets_with_recalls": integer,
      "mapping_compliance": number,
      "vulnerability_coverage": number,
      "recall_coverage": number
    }
  }
}
```

---

## Reports

### GET /api/v1/reports/export/formats

**Description:** Get supported export formats

**Response Fields:**
```json
{
  "success": boolean,
  "formats": {
    "pdf": {
      "name": "string",
      "description": "string",
      "mime_type": "string",
      "extension": "string"
    },
    "excel": {
      "name": "string",
      "description": "string",
      "mime_type": "string",
      "extension": "string"
    },
    "csv": {
      "name": "string",
      "description": "string",
      "mime_type": "string",
      "extension": "string"
    },
    "json": {
      "name": "string",
      "description": "string",
      "mime_type": "string",
      "extension": "string"
    }
  }
}
```

### GET /api/v1/reports/export/templates

**Description:** Get report templates

**Response Fields:**
```json
{
  "success": boolean,
  "templates": {
    "asset_summary": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    },
    "vulnerability_report": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    },
    "recall_report": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    },
    "compliance_report": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    },
    "device_mapping": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    },
    "security_dashboard": {
      "name": "string",
      "description": "string",
      "category": "string",
      "icon": "string"
    }
  }
}
```

### POST /api/v1/reports/export/export

**Description:** Export report

**Request Body Fields:**
```json
{
  "report_type": "string (required) - asset_summary|vulnerability_report|recall_report|compliance_report|device_mapping|security_dashboard",
  "format": "string (optional) - pdf|excel|csv|json - default: pdf",
  "date_from": "string (optional) - ISO 8601 date",
  "date_to": "string (optional) - ISO 8601 date",
  "filters": {
    "department": "string (optional)",
    "status": "string (optional)",
    "severity": "string (optional)",
    "classification": "string (optional)"
  }
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "export_id": "string",
  "download_url": "string",
  "expires_at": "string (ISO 8601 datetime)"
}
```

### POST /api/v1/reports/export/schedule

**Description:** Schedule recurring report

**Request Body Fields:**
```json
{
  "report_type": "string (required)",
  "format": "string (optional) - default: pdf",
  "schedule": "string (required) - cron format",
  "email": "string (optional)",
  "filters": "object (optional)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "schedule_id": "string",
  "next_run": "string (ISO 8601 datetime)"
}
```

---

## POST Requests

### POST Vulnerabilities Evaluate

#### POST /api/v1/vulnerabilities/evaluate

**Description:** Evaluate SBOM against NVD for vulnerabilities

**Request Body Fields:**
```json
{
  "asset_id": "string (UUID) - required",
  "evaluation_type": "string (optional) - default: sbom"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "evaluation_id": "string (UUID)",
    "asset_id": "string (UUID)",
    "evaluation_type": "string",
    "status": "string (Pending|Running|Completed|Failed)",
    "message": "string",
    "vulnerabilities_found": integer
  }
}
```

### POST Reports Export

#### POST /api/v1/reports/export/export

**Description:** Export report

**Request Body Fields:**
```json
{
  "report_type": "string (required) - asset_summary|vulnerability_report|recall_report|compliance_report|device_mapping|security_dashboard",
  "format": "string (optional) - pdf|excel|csv|json - default: pdf",
  "date_from": "string (optional) - ISO 8601 date",
  "date_to": "string (optional) - ISO 8601 date",
  "filters": {
    "department": "string (optional)",
    "status": "string (optional)",
    "severity": "string (optional)",
    "classification": "string (optional)"
  }
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "export_id": "string",
  "download_url": "string",
  "expires_at": "string (ISO 8601 datetime)"
}
```

### POST Reports Schedule

#### POST /api/v1/reports/export/schedule

**Description:** Schedule recurring report

**Request Body Fields:**
```json
{
  "report_type": "string (required)",
  "format": "string (optional) - default: pdf",
  "schedule": "string (required) - cron format",
  "email": "string (optional)",
  "filters": "object (optional)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "schedule_id": "string",
  "next_run": "string (ISO 8601 datetime)"
}
```


#### GET /api/v1/locations/assign-assets/check-ip/{ip_address}

**Description:** Check which location an IP address belongs to

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "ip_address": "string",
    "location_id": "string (UUID) | null",
    "location_name": "string | null",
    "found": boolean
  }
}
```

---

## EPSS Analytics

### GET /api/v1/epss/

**Description:** Get EPSS statistics and analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "overall": {
      "total_vulnerabilities": integer,
      "vulnerabilities_with_epss": integer,
      "high_epss_count": integer,
      "medium_epss_count": integer,
      "low_epss_count": integer,
      "avg_epss_score": "decimal (0.0000-1.0000)",
      "avg_epss_percentile": "decimal (0.0000-1.0000)",
      "last_epss_update": "string (ISO 8601 datetime)"
    },
    "by_severity": [
      {
        "severity": "string - Critical|High|Medium|Low",
        "count": integer,
        "avg_epss_score": "decimal (0.0000-1.0000)",
        "avg_epss_percentile": "decimal (0.0000-1.0000)",
        "high_epss_count": integer
      }
    ],
    "recent_trends": [
      {
        "recorded_date": "string (ISO 8601 date)",
        "vulnerabilities_count": integer,
        "avg_epss_score": "decimal (0.0000-1.0000)",
        "high_epss_count": integer
      }
    ]
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/trends/{cve_id}

**Description:** Get EPSS trend data for a specific CVE

**Query Parameters:**
- `days` (optional): Number of days to fetch (default: 30, max: 365)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "cve_id": "string (CVE-YYYY-NNNN)",
    "current": {
      "epss_score": "decimal (0.0000-1.0000)",
      "epss_percentile": "decimal (0.0000-1.0000)",
      "epss_date": "string (ISO 8601 date)",
      "epss_last_updated": "string (ISO 8601 datetime)"
    },
    "trend": [
      {
        "recorded_date": "string (ISO 8601 date)",
        "epss_score": "decimal (0.0000-1.0000)",
        "epss_percentile": "decimal (0.0000-1.0000)"
      }
    ],
    "days_requested": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/sync-status

**Description:** Get EPSS sync status and history

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "last_sync": {
      "sync_started_at": "string (ISO 8601 datetime)",
      "sync_completed_at": "string (ISO 8601 datetime)",
      "sync_status": "string - Success|Failed|Partial|Running",
      "total_cves_processed": integer,
      "cves_updated": integer,
      "cves_new": integer,
      "api_date": "string (ISO 8601 date)",
      "api_total_cves": integer,
      "api_version": "string",
      "error_message": "string (optional)"
    },
    "sync_history": [
      {
        "sync_started_at": "string (ISO 8601 datetime)",
        "sync_completed_at": "string (ISO 8601 datetime)",
        "sync_status": "string",
        "total_cves_processed": integer,
        "cves_updated": integer,
        "cves_new": integer,
        "error_message": "string (optional)"
      }
    ],
    "coverage": {
      "total_vulnerabilities": integer,
      "vulnerabilities_with_epss": integer,
      "updated_today": integer,
      "last_epss_update": "string (ISO 8601 datetime)"
    }
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/high-risk

**Description:** Get high EPSS risk vulnerabilities

**Query Parameters:**
- `threshold` (optional): EPSS score threshold (default: 0.7)
- `limit` (optional): Maximum results (default: 20, max: 100)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "vulnerabilities": [
      {
        "cve_id": "string (CVE-YYYY-NNNN)",
        "description": "string",
        "severity": "string - Critical|High|Medium|Low",
        "epss_score": "decimal (0.0000-1.0000)",
        "epss_percentile": "decimal (0.0000-1.0000)",
        "epss_date": "string (ISO 8601 date)",
        "is_kev": boolean,
        "affected_assets": integer,
        "open_count": integer
      }
    ],
    "threshold": "decimal (0.0000-1.0000)",
    "count": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/trending

**Description:** Get trending vulnerabilities with largest EPSS increases

**Query Parameters:**
- `days` (optional): Days to analyze (default: 7)
- `limit` (optional): Maximum results (default: 10, max: 50)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "vulnerabilities": [
      {
        "cve_id": "string (CVE-YYYY-NNNN)",
        "description": "string",
        "severity": "string - Critical|High|Medium|Low",
        "current_score": "decimal (0.0000-1.0000)",
        "previous_score": "decimal (0.0000-1.0000)",
        "score_change": "decimal (0.0000-1.0000)",
        "is_kev": boolean,
        "affected_assets": integer
      }
    ],
    "days_analyzed": integer,
    "count": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/trends/{cve_id}

**Description:** Get EPSS trend data for a specific CVE

**Query Parameters:**
- `days` (optional): Number of days to fetch (default: 30, max: 365)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "cve_id": "string (CVE-YYYY-NNNN)",
    "current": {
      "epss_score": "decimal (0.0000-1.0000)",
      "epss_percentile": "decimal (0.0000-1.0000)",
      "epss_date": "string (ISO 8601 date)",
      "epss_last_updated": "string (ISO 8601 datetime)"
    },
    "trend": [
      {
        "recorded_date": "string (ISO 8601 date)",
        "epss_score": "decimal (0.0000-1.0000)",
        "epss_percentile": "decimal (0.0000-1.0000)"
      }
    ],
    "days_requested": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/sync-status

**Description:** Get EPSS sync status and history

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "last_sync": {
      "sync_started_at": "string (ISO 8601 datetime)",
      "sync_completed_at": "string (ISO 8601 datetime)",
      "sync_status": "string - Success|Failed|Partial|Running",
      "total_cves_processed": integer,
      "cves_updated": integer,
      "cves_new": integer,
      "api_date": "string (ISO 8601 date)",
      "api_total_cves": integer,
      "api_version": "string",
      "error_message": "string (optional)"
    },
    "sync_history": [
      {
        "sync_started_at": "string (ISO 8601 datetime)",
        "sync_completed_at": "string (ISO 8601 datetime)",
        "sync_status": "string",
        "total_cves_processed": integer,
        "cves_updated": integer,
        "cves_new": integer,
        "error_message": "string (optional)"
      }
    ],
    "coverage": {
      "total_vulnerabilities": integer,
      "vulnerabilities_with_epss": integer,
      "updated_today": integer,
      "last_epss_update": "string (ISO 8601 datetime)"
    }
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/high-risk

**Description:** Get high EPSS risk vulnerabilities

**Query Parameters:**
- `threshold` (optional): EPSS score threshold (default: 0.7)
- `limit` (optional): Maximum results (default: 20, max: 100)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "vulnerabilities": [
      {
        "cve_id": "string (CVE-YYYY-NNNN)",
        "description": "string",
        "severity": "string - Critical|High|Medium|Low",
        "epss_score": "decimal (0.0000-1.0000)",
        "epss_percentile": "decimal (0.0000-1.0000)",
        "epss_date": "string (ISO 8601 date)",
        "is_kev": boolean,
        "affected_assets": integer,
        "open_count": integer
      }
    ],
    "threshold": "decimal (0.0000-1.0000)",
    "count": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/epss/trending

**Description:** Get trending vulnerabilities with largest EPSS increases

**Query Parameters:**
- `days` (optional): Days to analyze (default: 7)
- `limit` (optional): Maximum results (default: 10, max: 50)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "vulnerabilities": [
      {
        "cve_id": "string (CVE-YYYY-NNNN)",
        "description": "string",
        "severity": "string - Critical|High|Medium|Low",
        "current_score": "decimal (0.0000-1.0000)",
        "previous_score": "decimal (0.0000-1.0000)",
        "score_change": "decimal (0.0000-1.0000)",
        "is_kev": boolean,
        "affected_assets": integer
      }
    ],
    "days_analyzed": integer,
    "count": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

---

## Risk Priorities

### GET /api/v1/risk-priorities/

**Description:** Get risk priority calculations and analytics

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "overall": {
      "total_assets": integer,
      "total_vulnerabilities": integer,
      "high_priority_count": integer,
      "medium_priority_count": integer,
      "low_priority_count": integer,
      "avg_risk_score": "decimal (0.00-10.00)",
      "last_calculation": "string (ISO 8601 datetime)"
    },
    "by_priority": [
      {
        "priority": "string - High|Medium|Low",
        "count": integer,
        "avg_risk_score": "decimal (0.00-10.00)",
        "avg_epss_score": "decimal (0.0000-1.0000)",
        "kev_count": integer
      }
    ],
    "recent_trends": [
      {
        "recorded_date": "string (ISO 8601 date)",
        "high_priority_count": integer,
        "avg_risk_score": "decimal (0.00-10.00)"
      }
    ]
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/risk-priorities/asset/{asset_id}

**Description:** Get risk priority details for a specific asset

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "asset": {
      "id": integer,
      "name": "string",
      "ip_address": "string",
      "device_type": "string",
      "location": "string",
      "status": "string - Active|Inactive|Maintenance|Retired"
    },
    "risk_priority": {
      "priority": "string - High|Medium|Low",
      "risk_score": "decimal (0.00-10.00)",
      "epss_score": "decimal (0.0000-1.0000)",
      "is_kev": boolean,
      "last_calculated": "string (ISO 8601 datetime)"
    },
    "vulnerabilities": [
      {
        "cve_id": "string (CVE-YYYY-NNNN)",
        "description": "string",
        "severity": "string - Critical|High|Medium|Low",
        "epss_score": "decimal (0.0000-1.0000)",
        "is_kev": boolean,
        "open_count": integer
      }
    ],
    "calculation_factors": {
      "epss_weight": "decimal (0.00-1.00)",
      "kev_weight": "decimal (0.00-1.00)",
      "severity_weight": "decimal (0.00-1.00)",
      "asset_criticality": "decimal (0.00-1.00)"
    }
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/risk-priorities/high-priority

**Description:** Get high priority assets and vulnerabilities

**Query Parameters:**
- `limit` (optional): Maximum results (default: 20, max: 100)
- `threshold` (optional): Risk score threshold (default: 7.0)

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "assets": [
      {
        "asset_id": integer,
        "asset_name": "string",
        "ip_address": "string",
        "device_type": "string",
        "risk_score": "decimal (0.00-10.00)",
        "priority": "string - High|Medium|Low",
        "vulnerability_count": integer,
        "kev_count": integer,
        "last_updated": "string (ISO 8601 datetime)"
      }
    ],
    "threshold": "decimal (0.00-10.00)",
    "count": integer
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### GET /api/v1/risk-priorities/calculation-status

**Description:** Get risk priority calculation status and history

**Response Fields:**
```json
{
  "success": boolean,
  "data": {
    "last_calculation": {
      "calculation_started_at": "string (ISO 8601 datetime)",
      "calculation_completed_at": "string (ISO 8601 datetime)",
      "calculation_status": "string - Success|Failed|Partial|Running",
      "total_assets_processed": integer,
      "assets_updated": integer,
      "assets_new": integer,
      "error_message": "string (optional)"
    },
    "calculation_history": [
      {
        "calculation_started_at": "string (ISO 8601 datetime)",
        "calculation_completed_at": "string (ISO 8601 datetime)",
        "calculation_status": "string",
        "total_assets_processed": integer,
        "assets_updated": integer,
        "assets_new": integer,
        "error_message": "string (optional)"
      }
    ],
    "coverage": {
      "total_assets": integer,
      "assets_with_risk_scores": integer,
      "updated_today": integer,
      "last_risk_calculation": "string (ISO 8601 datetime)"
    }
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

---

## PUT Requests

### PUT Remediation Actions

#### PATCH /api/v1/remediation-actions/{action_id}/devices/{device_id}

**Description:** Update device patch status for a remediation action

**Request Body Fields:**
```json
{
  "patch_status": "string (required) - Pending|In Progress|Completed|Failed"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string"
}
```

---

### POST Vulnerabilities

#### POST /api/v1/vulnerabilities

**Description:** Create a new vulnerability with comprehensive field support

**Important:** Vulnerabilities must be linked to a device/asset and component when created via API. This ensures every vulnerability has at least one affected asset and prevents orphaned vulnerabilities with zero affected assets.

**Authentication:** Required (API Key or Session)

**Permissions:** Admin only

**Content-Type:** `application/json`

**Request Body Fields:**
```json
{
  "cve_id": "string (required) - CVE identifier in format CVE-YYYY-NNNN",
  "device_id": "string (required*) - Medical device UUID to link vulnerability to",
  "asset_id": "string (required*) - Asset UUID (alternative to device_id, will be resolved to device_id)",
  "component_id": "string (required) - Software component UUID that has this vulnerability",
  "description": "string (optional) - Vulnerability description",
  "severity": "string (optional) - Critical|High|Medium|Low|Info|Unknown",
  "priority": "string (optional) - Critical-KEV|High|Medium|Low|Normal",
  "cvss_v2_score": "number (optional) - CVSS v2.0 score (0.0-10.0)",
  "cvss_v2_vector": "string (optional) - CVSS v2.0 vector string",
  "cvss_v3_score": "number (optional) - CVSS v3.x score (0.0-10.0)",
  "cvss_v3_vector": "string (optional) - CVSS v3.x vector string",
  "cvss_v4_score": "number (optional) - CVSS v4.0 score (0.0-10.0)",
  "cvss_v4_vector": "string (optional) - CVSS v4.0 vector string",
  "published_date": "string (optional) - Date published (YYYY-MM-DD)",
  "last_modified_date": "string (optional) - Date last modified (YYYY-MM-DD)",
  "is_kev": "boolean (optional) - Whether in CISA KEV catalog",
  "kev_id": "string (optional) - KEV catalog ID (UUID)",
  "kev_date_added": "string (optional) - Date added to KEV (YYYY-MM-DD)",
  "kev_due_date": "string (optional) - KEV remediation due date (YYYY-MM-DD)",
  "kev_required_action": "string (optional) - Required action for KEV",
  "epss_score": "number (optional) - EPSS probability score (0.0000-1.0000)",
  "epss_percentile": "number (optional) - EPSS percentile ranking (0.0000-1.0000)",
  "epss_date": "string (optional) - Date of EPSS score (YYYY-MM-DD)",
  "epss_last_updated": "string (optional) - Last EPSS update (YYYY-MM-DD HH:MM:SS)",
  "nvd_data": "object (optional) - Additional NVD data as JSON"
}
```

**Required Fields:**
- `cve_id` - CVE identifier (required)
- `device_id` OR `asset_id` - One must be provided (required*)
- `component_id` - Software component UUID (required)

**Field Requirements:**
- **device_id**: Must be a valid UUID of an existing medical device
- **asset_id**: Must be a valid UUID of an asset that is mapped to a medical device (will be automatically resolved to device_id)
- **component_id**: Must be a valid UUID of an existing software component

**Behavior:**
- When a vulnerability is created via API, a `device_vulnerabilities_link` entry is automatically created linking the vulnerability to the specified device and component
- If the vulnerability already exists but the device/component link doesn't, the link will be created (allows adding vulnerability to additional devices)
- If both the vulnerability and the device/component link already exist, the request will return a 409 Conflict error
- This ensures vulnerabilities created via API always have at least one affected asset, preventing orphaned vulnerabilities

**Note:** Vulnerabilities discovered through SBOM evaluation automatically create device links. This requirement only applies to vulnerabilities created directly via the API.

**Example Request (using device_id):**
```json
{
  "cve_id": "CVE-2024-1234",
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "component_id": "660e8400-e29b-41d4-a716-446655440001",
  "description": "Remote code execution vulnerability in example software",
  "severity": "Critical",
  "priority": "High",
  "cvss_v3_score": 9.8,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_v4_score": 9.9,
  "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "published_date": "2024-01-15",
  "last_modified_date": "2024-01-20",
  "is_kev": true,
  "kev_date_added": "2024-01-16",
  "kev_due_date": "2024-02-15",
  "kev_required_action": "Apply security updates immediately",
  "epss_score": 0.1234,
  "epss_percentile": 0.8567,
  "epss_date": "2024-01-15",
  "epss_last_updated": "2024-01-15 14:30:00",
  "nvd_data": {
    "references": [
      {
        "url": "https://example.com/advisory",
        "source": "Vendor"
      }
    ],
    "cwe_ids": ["CWE-787", "CWE-416"]
  }
}
```

**Example Request (using asset_id instead of device_id):**
```json
{
  "cve_id": "CVE-2024-1234",
  "asset_id": "770e8400-e29b-41d4-a716-446655440002",
  "component_id": "660e8400-e29b-41d4-a716-446655440001",
  "description": "Remote code execution vulnerability in example software",
  "severity": "Critical",
  "cvss_v3_score": 9.8
}
```

**Success Response (201 Created):**
```json
{
  "success": true,
  "message": "Vulnerability created successfully and linked to device",
  "data": {
    "cve_id": "CVE-2024-1234",
    "device_id": "550e8400-e29b-41d4-a716-446655440000",
    "component_id": "660e8400-e29b-41d4-a716-446655440001",
    "link_created": true,
    "created_at": "2024-01-27T10:30:00+00:00",
    "created_by": "admin"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**Error Responses:**

**400 Bad Request - Missing Required Fields:**
```json
{
  "success": false,
  "error": {
    "code": "MISSING_REQUIRED_FIELDS",
    "message": "Missing required fields: cve_id, device_id or asset_id, component_id. Vulnerabilities must be linked to a device/asset and component."
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Device Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "DEVICE_NOT_FOUND",
    "message": "Device with ID 550e8400-e29b-41d4-a716-446655440000 does not exist"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Asset Not Mapped:**
```json
{
  "success": false,
  "error": {
    "code": "ASSET_NOT_MAPPED",
    "message": "Asset with ID 770e8400-e29b-41d4-a716-446655440002 is not mapped to a medical device"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Component Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_NOT_FOUND",
    "message": "Software component with ID 660e8400-e29b-41d4-a716-446655440001 does not exist"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**409 Conflict - Device Vulnerability Link Exists:**
```json
{
  "success": false,
  "error": {
    "code": "DEVICE_VULNERABILITY_LINK_EXISTS",
    "message": "This vulnerability is already linked to the specified device and component"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**Note on 409 Conflict:** If a vulnerability already exists and you're trying to add it to a new device/component combination, the link will be created. This error only occurs when both the vulnerability AND the specific device/component link already exist.

**400 Bad Request - Invalid CVE ID Format:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CVE_ID",
    "message": "CVE ID must be in format CVE-YYYY-NNNN"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Invalid Severity:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_SEVERITY",
    "message": "Severity must be one of: Critical, High, Medium, Low, Info, Unknown"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Invalid CVSS Score:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CVSS_SCORE",
    "message": "cvss_v3_score must be between 0.0 and 10.0"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Invalid Date Format:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_DATE_FORMAT",
    "message": "published_date must be in YYYY-MM-DD format"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - Invalid KEV ID:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_KEV_ID",
    "message": "KEV ID does not exist in the CISA KEV catalog"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "Only administrators can create vulnerabilities"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```


**Usage Examples:**

**cURL (using device_id):**
```bash
curl -X POST https://your-server.com/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "cve_id": "CVE-2024-1234",
    "device_id": "550e8400-e29b-41d4-a716-446655440000",
    "component_id": "660e8400-e29b-41d4-a716-446655440001",
    "description": "Remote code execution vulnerability",
    "severity": "Critical",
    "cvss_v3_score": 9.8,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "published_date": "2024-01-15"
  }'
```

**cURL (using asset_id):**
```bash
curl -X POST https://your-server.com/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "cve_id": "CVE-2024-1234",
    "asset_id": "770e8400-e29b-41d4-a716-446655440002",
    "component_id": "660e8400-e29b-41d4-a716-446655440001",
    "description": "Remote code execution vulnerability",
    "severity": "Critical",
    "cvss_v3_score": 9.8
  }'
```

**JavaScript:**
```javascript
const response = await fetch('/api/v1/vulnerabilities', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-api-key'
  },
  body: JSON.stringify({
    cve_id: 'CVE-2024-1234',
    device_id: '550e8400-e29b-41d4-a716-446655440000', // Required: device_id OR asset_id
    component_id: '660e8400-e29b-41d4-a716-446655440001', // Required
    description: 'Remote code execution vulnerability',
    severity: 'Critical',
    cvss_v3_score: 9.8,
    cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    published_date: '2024-01-15'
  })
});

const result = await response.json();
console.log(result);
```

**Python:**
```python
import requests
import json

url = 'https://your-server.com/api/v1/vulnerabilities'
headers = {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-api-key'
}
data = {
    'cve_id': 'CVE-2024-1234',
    'device_id': '550e8400-e29b-41d4-a716-446655440000',  # Required: device_id OR asset_id
    'component_id': '660e8400-e29b-41d4-a716-446655440001',  # Required
    'description': 'Remote code execution vulnerability',
    'severity': 'Critical',
    'cvss_v3_score': 9.8,
    'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'published_date': '2024-01-15'
}

response = requests.post(url, headers=headers, json=data)
result = response.json()
print(result)
```

**Field Validation Rules:**
- **CVE ID Format**: Must match pattern `CVE-\d{4}-\d{4,}`
- **Severity Values**: Critical, High, Medium, Low, Info, Unknown
- **Priority Values**: Critical-KEV, High, Medium, Low, Normal
- **device_id**: Must be a valid UUID and exist in `medical_devices` table
- **asset_id**: Must be a valid UUID and be mapped to a medical device in `medical_devices` table (alternative to device_id)
- **component_id**: Must be a valid UUID and exist in `software_components` table

**Important Notes:**
- **Asset Resolution**: If `asset_id` is provided, it will be automatically resolved to the corresponding `device_id` from the `medical_devices` table. If the asset is not mapped to a device, the request will fail with `ASSET_NOT_MAPPED` error.
- **Automatic Link Creation**: When a vulnerability is created via API, a `device_vulnerabilities_link` entry is automatically created, ensuring the vulnerability always has at least one affected asset.
- **Adding to Multiple Devices**: If a vulnerability already exists, you can add it to additional devices by providing a different `device_id` or `component_id`. The link will be created even if the vulnerability record already exists.
- **Conflict Handling**: A 409 Conflict error only occurs when attempting to create a link that already exists (same `cve_id`, `device_id`, and `component_id` combination).
- **CVSS Score Ranges**: 0.0 - 10.0 for all CVSS versions
- **EPSS Score Ranges**: 0.0000 - 1.0000 for both score and percentile
- **Date Formats**: YYYY-MM-DD for dates, YYYY-MM-DD HH:MM:SS for timestamps
- **Boolean Values**: true, false, "true", "false", 1, 0, "1", "0"

---

### POST Components

#### POST /api/v1/components

**Description:** Create a new software component independently of SBOM imports

**Important:** Components created via this API are independent of SBOM imports and will have `sbom_id = NULL`. This allows you to add software components discovered through other means (manual inventory, network scanning, etc.).

**Authentication:** Required (API Key or Session)

**Permissions:** `components:write` scope required

**Content-Type:** `application/json`

**Request Body Fields:**
```json
{
  "name": "string (required) - Component name (e.g., 'OpenSSL', 'Apache HTTP Server')",
  "version": "string (optional) - Component version (e.g., '3.0.0', '2.4.41')",
  "vendor": "string (optional) - Vendor or publisher name (e.g., 'OpenSSL', 'Apache Software Foundation')",
  "license": "string (optional) - License identifier (e.g., 'Apache-2.0', 'MIT', 'GPL-2.0')",
  "purl": "string (optional) - Package URL (PURL) format identifier",
  "cpe": "string (optional) - Common Platform Enumeration (CPE) identifier"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "component_id": "string (UUID)",
    "sbom_id": "null - Always null for independently created components",
    "name": "string",
    "version": "string | null",
    "vendor": "string | null",
    "license": "string | null",
    "purl": "string | null",
    "cpe": "string | null",
    "created_at": "string (ISO 8601 datetime)",
    "package_id": "string (UUID) | null",
    "version_id": "string (UUID) | null"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Example Request:**
```json
{
  "name": "OpenSSL",
  "version": "3.0.0",
  "vendor": "OpenSSL",
  "license": "Apache-2.0",
  "purl": "pkg:generic/openssl@3.0.0",
  "cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
}
```

**Success Response (201 Created):**
```json
{
  "success": true,
  "message": "Software component created successfully",
  "data": {
    "component_id": "123e4567-e89b-12d3-a456-426614174000",
    "sbom_id": null,
    "name": "OpenSSL",
    "version": "3.0.0",
    "vendor": "OpenSSL",
    "license": "Apache-2.0",
    "purl": "pkg:generic/openssl@3.0.0",
    "cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
    "created_at": "2025-01-10T10:30:00Z",
    "package_id": null,
    "version_id": null
  },
  "timestamp": "2025-01-10T10:30:00Z"
}
```

**Error Responses:**

**400 Bad Request - Missing Required Field:**
```json
{
  "success": false,
  "error": {
    "code": "MISSING_REQUIRED_FIELD",
    "message": "Field \"name\" is required"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "Permission required: components:write"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Field Validation Rules:**
- **Name**: Required field, must not be empty
- **Version**: Optional, recommended for accurate vulnerability tracking
- **Vendor**: Optional, helps identify the component publisher
- **License**: Optional, license identifier in standard format
- **PURL**: Optional, Package URL format (e.g., `pkg:generic/openssl@3.0.0`)
- **CPE**: Optional, Common Platform Enumeration format (e.g., `cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*`)
- **Independent Components**: All components created via this API have `sbom_id = NULL` to distinguish them from SBOM-imported components

**Usage Notes:**
- Components created via this API can be used when creating vulnerabilities via `POST /api/v1/vulnerabilities`
- Use the `component_id` returned from this endpoint when linking vulnerabilities to devices/assets
- Components can be updated using `PUT /api/v1/components/{component_id}` and deleted using `DELETE /api/v1/components/{component_id}`

---

### POST Asset Import

#### POST /api/v1/assets/import

**Description:** Import assets from security scan files (nmap, Nessus, CSV) to automatically create or update assets in the system.

**Authentication:** Required (API Key or Session)

**Permissions:** Assets write permission required

**Content-Type:** `multipart/form-data`

**Request Parameters:**
- `scan_file` (file, required): The uploaded scan file
- `file_type` (string, required): Type of scan file - "nmap", "nessus", or "csv"
- `import_options` (string, optional): JSON string with import configuration options

**Import Options:**
```json
{
  "default_criticality": {
    "Medical Device": "Clinical-High",
    "IoMT Sensor": "Clinical-Medium",
    "Server": "Infrastructure-High",
    "Unknown": "Low"
  },
  "update_existing": true,
  "skip_duplicates": false
}
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "file_name": "network_scan.xml",
    "file_type": "nmap",
    "total_processed": 25,
    "assets_created": 18,
    "assets_updated": 7,
    "assets_skipped": 0,
    "errors": []
  },
  "timestamp": "2024-01-20T10:30:00Z"
}
```

**Error Response (400):**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_FILE_TYPE",
    "message": "Invalid file type. Supported types: nmap, nessus, csv"
  },
  "timestamp": "2024-01-20T10:30:00Z"
}
```

**Supported File Types:**

1. **Nmap XML**: Standard nmap XML output files
   - Automatically detects open ports and determines asset type
   - Maps common medical device ports (443, 80, 8080, 8443, 22, 23, 161, 162, 502, 102, 1883, 8883)
   - Identifies IoMT sensors and servers based on port patterns

2. **Nessus XML**: Tenable Nessus scan results
   - Parses vulnerability data to determine asset criticality
   - Extracts hostnames and IP addresses
   - Analyzes vulnerability descriptions for medical device indicators

3. **CSV**: Custom CSV files with asset data
   - Flexible column mapping (supports common column names)
   - Maps: ip, ip_address, hostname, host, type, asset_type, criticality, priority, status, manufacturer, model, serial, serial_number, department, location
   - Updates existing assets or creates new ones

**Usage Examples:**

cURL (Nmap XML):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/import \
  -H "X-API-Key: your-api-key" \
  -F "scan_file=@network_scan.xml" \
  -F "file_type=nmap" \
  -F 'import_options={"default_criticality":{"Medical Device":"Clinical-High"}}'
```

cURL (Nessus XML):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/import \
  -H "X-API-Key: your-api-key" \
  -F "scan_file=@vulnerability_scan.nessus" \
  -F "file_type=nessus"
```

cURL (CSV):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/import \
  -H "X-API-Key: your-api-key" \
  -F "scan_file=@assets.csv" \
  -F "file_type=csv"
```

JavaScript:
```javascript
const formData = new FormData();
formData.append('scan_file', fileInput.files[0]);
formData.append('file_type', 'nmap');
formData.append('import_options', JSON.stringify({
  default_criticality: {
    'Medical Device': 'Clinical-High',
    'IoMT Sensor': 'Clinical-Medium'
  }
}));

const response = await fetch('/api/v1/assets/import', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your-api-key'
  },
  body: formData
});

const result = await response.json();
console.log(result);
```

Python:
```python
import requests

url = 'https://your-csms-instance.com/api/v1/assets/import'
headers = {'X-API-Key': 'your-api-key'}

files = {'scan_file': open('network_scan.xml', 'rb')}
data = {
    'file_type': 'nmap',
    'import_options': '{"default_criticality":{"Medical Device":"Clinical-High"}}'
}

response = requests.post(url, headers=headers, files=files, data=data)
result = response.json()
print(result)
```

**Asset Type Detection:**

- **Medical Device**: Detected by medical-specific ports (DICOM, HL7, FHIR) or vulnerability descriptions containing medical keywords
- **IoMT Sensor**: Identified by IoT/embedded device ports (1883, 8883, 502, 102) or sensor-related vulnerability descriptions
- **Server**: Standard server ports (80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 1433, 3306, 5432)
- **Unknown**: Default when no specific patterns are detected

**Criticality Assignment:**
- Based on asset type and vulnerability severity
- Configurable through import options
- Defaults: Medical Device (Clinical-High), IoMT Sensor (Clinical-Medium), Server (Infrastructure-High), Unknown (Low)

**File Size Limits:**
- Maximum file size: 50MB
- Supported formats: XML (nmap, Nessus), CSV
- Character encoding: UTF-8 recommended for CSV files

---

### POST Asset Upload

#### POST /api/v1/assets/upload

**Description:** Upload assets from security scan files (nmap, Nessus, CSV) with basic processing and department/location assignment.

**Authentication:** Required (Session only)

**Permissions:** User authentication required

**Content-Type:** `multipart/form-data`

**Request Parameters:**
- `file` (file, required): The uploaded scan file
- `type` (string, optional): Type of scan file - "nmap", "nessus", or "csv" (defaults to "nmap")
- `department` (string, optional): Department to assign to imported assets
- `location` (string, optional): Location to assign to imported assets

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "processed": 25,
    "errors": [],
    "file_type": "nmap",
    "filename": "network_scan.xml"
  },
  "message": "File uploaded and processed successfully",
  "timestamp": "2024-01-20T10:30:00Z"
}
```

**Error Response (400):**
```json
{
  "success": false,
  "error": {
    "code": "NO_FILE",
    "message": "No file uploaded or upload error occurred"
  }
}
```

**Supported File Types:**

1. **Nmap XML**: Standard nmap XML output files
   - Extracts hostnames, IP addresses, MAC addresses
   - Captures OS information and open ports
   - Stores raw nmap data for reference

2. **Nessus XML**: Tenable Nessus scan results
   - Extracts host information and vulnerability data
   - Stores raw Nessus data for reference

3. **CSV**: Custom CSV files with asset data
   - Supports columns: hostname, ip_address, mac_address, manufacturer, model, serial_number
   - Flexible column mapping

**Usage Examples:**

cURL (Nmap XML):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/upload \
  -H "Authorization: Bearer your-session-token" \
  -F "file=@network_scan.xml" \
  -F "type=nmap" \
  -F "department=IT" \
  -F "location=Data Center"
```

cURL (Nessus XML):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/upload \
  -H "Authorization: Bearer your-session-token" \
  -F "file=@vulnerability_scan.nessus" \
  -F "type=nessus" \
  -F "department=Security"
```

cURL (CSV):
```bash
curl -X POST https://your-csms-instance.com/api/v1/assets/upload \
  -H "Authorization: Bearer your-session-token" \
  -F "file=@assets.csv" \
  -F "type=csv" \
  -F "department=Operations" \
  -F "location=Main Office"
```

**Key Differences from /api/v1/assets/import:**

| Feature | /api/v1/assets/upload | /api/v1/assets/import |
|---------|----------------------|----------------------|
| **Authentication** | Session only | API Key + Session |
| **Permissions** | Basic user auth | Assets write permission |
| **Asset Type Detection** | Basic | Intelligent classification |
| **Criticality Assignment** | Manual (department/location) | Automatic based on type |
| **Configuration** | Simple parameters | JSON configuration options |
| **Response Detail** | Basic processing count | Detailed import statistics |
| **Error Handling** | Basic | Comprehensive |

---

### POST Device SBOM Upload

#### POST /api/v1/devices/sbom

**Description:** Upload Software Bill of Materials (SBOM) files for specific medical devices to track software components and vulnerabilities.

**Authentication:** Required (API Key or Session)

**Permissions:** Devices write permission required

**Content-Type:** `multipart/form-data`

**Request Parameters:**
- `sbom_file` (file, required): The uploaded SBOM file
- `device_id` (string, required): UUID of the medical device
- `format` (string, optional): SBOM format - "SPDX", "CycloneDX", "spdx-tag-value", "JSON", or "XML" (defaults to "SPDX")
- `description` (string, optional): Description of the SBOM

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "sbom_id": "123e4567-e89b-12d3-a456-426614174000",
    "device_id": "456e7890-e89b-12d3-a456-426614174001",
    "format": "SPDX",
    "file_name": "device-firmware-sbom.json",
    "file_size": 2048576,
    "components_count": 45,
    "parsed_successfully": true,
    "queued_for_evaluation": true,
    "queue_id": "789e0123-e89b-12d3-a456-426614174002"
  },
  "timestamp": "2024-01-20T10:30:00Z"
}
```

**Error Response (400):**
```json
{
  "success": false,
  "error": {
    "code": "MISSING_DEVICE_ID",
    "message": "Device ID is required"
  },
  "timestamp": "2024-01-20T10:30:00Z"
}
```

**Supported SBOM Formats:**

1. **SPDX**: Software Package Data Exchange format
   - Standard format for software package information
   - Supports comprehensive component metadata
   - Includes licensing and vulnerability information

2. **CycloneDX**: Lightweight SBOM format
   - Focused on security and vulnerability management
   - Supports dependency graphs
   - Includes CPE and PURL identifiers

3. **spdx-tag-value**: SPDX in tag-value format
   - Human-readable SPDX format
   - Text-based representation

4. **JSON**: Generic JSON format
   - Flexible JSON structure
   - Custom component definitions

5. **XML**: XML-based SBOM format
   - Structured XML representation
   - Extensible markup format

**Usage Examples:**

cURL (SPDX):
```bash
curl -X POST https://your-csms-instance.com/api/v1/devices/sbom \
  -H "X-API-Key: your-api-key" \
  -F "sbom_file=@device-sbom.spdx.json" \
  -F "device_id=123e4567-e89b-12d3-a456-426614174000" \
  -F "format=SPDX" \
  -F "description=Medical device firmware SBOM"
```

cURL (CycloneDX):
```bash
curl -X POST https://your-csms-instance.com/api/v1/devices/sbom \
  -H "X-API-Key: your-api-key" \
  -F "sbom_file=@device-sbom.cyclonedx.json" \
  -F "device_id=123e4567-e89b-12d3-a456-426614174000" \
  -F "format=CycloneDX"
```

JavaScript:
```javascript
const formData = new FormData();
formData.append('sbom_file', fileInput.files[0]);
formData.append('device_id', '123e4567-e89b-12d3-a456-426614174000');
formData.append('format', 'SPDX');
formData.append('description', 'Medical device firmware SBOM');

const response = await fetch('/api/v1/devices/sbom', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your-api-key'
  },
  body: formData
});

const result = await response.json();
console.log(result);
```

Python:
```python
import requests

url = 'https://your-csms-instance.com/api/v1/devices/sbom'
headers = {'X-API-Key': 'your-api-key'}

files = {'sbom_file': open('device-sbom.json', 'rb')}
data = {
    'device_id': '123e4567-e89b-12d3-a456-426614174000',
    'format': 'SPDX',
    'description': 'Medical device firmware SBOM'
}

response = requests.post(url, headers=headers, files=files, data=data)
result = response.json()
print(result)
```

**SBOM Processing Features:**

- **Component Extraction**: Automatically extracts software components from SBOM files
- **Vulnerability Evaluation**: Queues SBOM for background vulnerability analysis
- **Format Support**: Handles multiple SBOM formats (SPDX, CycloneDX, JSON, XML)
- **Metadata Storage**: Stores file information, parsing status, and evaluation results
- **Background Processing**: Automatically queues SBOMs for vulnerability evaluation
- **Component Tracking**: Links components to known vulnerabilities in the database

**File Size Limits:**
- Maximum file size: 100MB
- Supported formats: JSON, XML, SPDX, CycloneDX
- Character encoding: UTF-8 recommended

---

### PUT Vulnerabilities

#### PUT /api/v1/vulnerabilities/{cve_id}

**Description:** Update vulnerability information with comprehensive field support

**Authentication:** Required (API Key or Session)

**Permissions:** Vulnerabilities write permission required

**Content-Type:** `application/json`

**Request Body Fields:**
```json
{
  "description": "string (optional) - Vulnerability description",
  "severity": "string (optional) - Critical|High|Medium|Low|Info|Unknown",
  "priority": "string (optional) - Critical-KEV|High|Medium|Low|Normal",
  "cvss_v2_score": "number (optional) - CVSS v2.0 score (0.0-10.0)",
  "cvss_v2_vector": "string (optional) - CVSS v2.0 vector string",
  "cvss_v3_score": "number (optional) - CVSS v3.x score (0.0-10.0)",
  "cvss_v3_vector": "string (optional) - CVSS v3.x vector string",
  "cvss_v4_score": "number (optional) - CVSS v4.0 score (0.0-10.0)",
  "cvss_v4_vector": "string (optional) - CVSS v4.0 vector string",
  "published_date": "string (optional) - Date published (YYYY-MM-DD)",
  "last_modified_date": "string (optional) - Date last modified (YYYY-MM-DD)",
  "is_kev": "boolean (optional) - Whether in CISA KEV catalog",
  "kev_id": "string (optional) - KEV catalog ID (UUID)",
  "kev_date_added": "string (optional) - Date added to KEV (YYYY-MM-DD)",
  "kev_due_date": "string (optional) - KEV remediation due date (YYYY-MM-DD)",
  "kev_required_action": "string (optional) - Required action for KEV",
  "epss_score": "number (optional) - EPSS probability score (0.0000-1.0000)",
  "epss_percentile": "number (optional) - EPSS percentile ranking (0.0000-1.0000)",
  "epss_date": "string (optional) - Date of EPSS score (YYYY-MM-DD)",
  "epss_last_updated": "string (optional) - Last EPSS update (YYYY-MM-DD HH:MM:SS)",
  "nvd_data": "object (optional) - Additional NVD data as JSON"
}
```

**Example Request:**
```json
{
  "description": "Updated description for remote code execution vulnerability",
  "severity": "Critical",
  "priority": "High",
  "cvss_v3_score": 9.8,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "published_date": "2024-01-15",
  "last_modified_date": "2024-01-20"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Vulnerability updated successfully",
  "data": {
    "cve_id": "CVE-2024-1234",
    "updated_fields": ["description", "severity", "priority", "cvss_v3_score"],
    "updated_at": "2024-01-27T10:30:00+00:00"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**Error Responses:**

**400 Bad Request - Invalid Field Value:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_SEVERITY",
    "message": "Severity must be one of: Critical, High, Medium, Low, Info, Unknown"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**400 Bad Request - No Fields to Update:**
```json
{
  "success": false,
  "error": {
    "code": "NO_FIELDS_TO_UPDATE",
    "message": "No valid fields to update"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**404 Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "VULNERABILITY_NOT_FOUND",
    "message": "Vulnerability not found"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "You do not have permission to update vulnerabilities"
  },
  "timestamp": "2024-01-27T10:30:00+00:00"
}
```

**Field Validation Rules:**
- All field validations match the POST endpoint (see POST Vulnerabilities section)
- Only fields included in the request body will be updated
- `updated_at` timestamp is automatically updated on successful save

---

### PUT Components

#### PUT /api/v1/components/{component_id}

**Description:** Update an existing software component

**Authentication:** Required (API Key or Session)

**Permissions:** `components:write` scope required

**Content-Type:** `application/json`

**Path Parameters:**
- `component_id` (UUID, required): Software component UUID

**Request Body Fields:**
All fields are optional. Only include fields you want to update.
```json
{
  "name": "string (optional) - Component name",
  "version": "string (optional) - Component version",
  "vendor": "string (optional) - Vendor or publisher name",
  "license": "string (optional) - License identifier",
  "purl": "string (optional) - Package URL (PURL)",
  "cpe": "string (optional) - Common Platform Enumeration (CPE)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "component_id": "string (UUID)",
    "sbom_id": "string (UUID) | null",
    "name": "string",
    "version": "string | null",
    "vendor": "string | null",
    "license": "string | null",
    "purl": "string | null",
    "cpe": "string | null",
    "created_at": "string (ISO 8601 datetime)",
    "package_id": "string (UUID) | null",
    "version_id": "string (UUID) | null"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Example Request:**
```json
{
  "version": "3.0.1",
  "cpe": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Software component updated successfully",
  "data": {
    "component_id": "123e4567-e89b-12d3-a456-426614174000",
    "sbom_id": null,
    "name": "OpenSSL",
    "version": "3.0.1",
    "vendor": "OpenSSL",
    "license": "Apache-2.0",
    "purl": "pkg:generic/openssl@3.0.1",
    "cpe": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*",
    "created_at": "2025-01-10T10:30:00Z",
    "package_id": null,
    "version_id": null
  },
  "timestamp": "2025-01-10T10:30:00Z"
}
```

**Error Responses:**

**400 Bad Request - No Fields to Update:**
```json
{
  "success": false,
  "error": {
    "code": "NO_FIELDS_TO_UPDATE",
    "message": "No valid fields provided for update"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**404 Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_NOT_FOUND",
    "message": "Software component not found"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "Permission required: components:write"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Field Validation Rules:**
- All field validations match the POST endpoint (see POST Components section)
- Only fields included in the request body will be updated
- `sbom_id` cannot be modified via this endpoint (it's set only during SBOM import)

**Usage Notes:**
- Use this endpoint to update component information discovered after initial creation
- Common use cases: updating version numbers, adding CPE identifiers, correcting vendor names
- The `sbom_id` field will remain unchanged (null for independent components, or the original SBOM ID for imported components)

---

### DELETE /api/v1/components/{component_id}

**Description:** Delete a software component

**Authentication:** Required (API Key or Session)

**Permissions:** `components:delete` scope required

**Path Parameters:**
- `component_id` (UUID, required): Software component UUID

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Software component deleted successfully",
  "timestamp": "2025-01-10T10:30:00Z"
}
```

**Error Responses:**

**404 Not Found:**
```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_NOT_FOUND",
    "message": "Software component not found"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**409 Conflict - Component In Use:**
```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_IN_USE",
    "message": "Cannot delete component: it is linked to 5 vulnerability(ies)"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "Permission required: components:delete"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

**Usage Notes:**
- Components that are linked to vulnerabilities cannot be deleted
- You must first remove all vulnerability links (via `device_vulnerabilities_link` table) before deleting the component
- This prevents orphaned vulnerability records that reference non-existent components

---

### PUT Recalls

#### PUT /api/v1/recalls/{recall_id}

**Description:** Update recall information

**Request Body Fields:**
```json
{
  "recall_number": "string (optional)",
  "product_name": "string (optional)",
  "manufacturer": "string (optional)",
  "recall_date": "string (optional) - ISO 8601 date",
  "recall_status": "string (optional) - Active|Resolved|Cancelled",
  "reason_for_recall": "string (optional)",
  "recall_classification": "string (optional) - Class I|Class II|Class III",
  "affected_products": "array (optional) - Array of affected product objects",
  "contact_information": "object (optional) - Contact information object"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "recall_id": "string (UUID)",
    "updated_fields": ["string"],
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

### PUT Patches

#### PUT /api/v1/patches/{patch_id}

**Description:** Update patch information (Admin only)

**Request Body Fields:**
```json
{
  "patch_name": "string (optional)",
  "patch_type": "string (optional) - Security|Feature|Bug Fix|Critical",
  "target_device_type": "string (optional)",
  "target_package_id": "string (optional) - UUID",
  "target_version": "string (optional)",
  "cve_list": "array (optional) - Array of CVE objects",
  "description": "string (optional)",
  "release_date": "string (optional) - ISO 8601 datetime",
  "vendor": "string (optional)",
  "kb_article": "string (optional)",
  "download_url": "string (optional)",
  "install_instructions": "string (optional)",
  "prerequisites": "string (optional)",
  "estimated_install_time": "string (optional)",
  "requires_reboot": "boolean (optional)",
  "is_active": "boolean (optional)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "patch_id": "string (UUID)",
    "updated_fields": ["string"],
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

### PUT Users

#### PUT /api/v1/users/{user_id}

**Description:** Update user information (Admin only)

**Request Body Fields:**
```json
{
  "username": "string (optional)",
  "email": "string (optional)",
  "role": "string (optional) - Admin|Clinical Engineer|IT Security Analyst|Read-Only",
  "is_active": "boolean (optional)",
  "password": "string (optional) - New password (will be hashed)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "user_id": "string (UUID)",
    "updated_fields": ["string"],
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

### PUT Locations

#### PUT /api/v1/locations/{location_id}

**Description:** Update location information

**Request Body Fields:**
```json
{
  "parent_location_id": "string (optional) - UUID",
  "location_name": "string (optional)",
  "location_type": "string (optional) - Building|Floor|Department|Ward|Lab|Room|Other",
  "location_code": "string (optional)",
  "description": "string (optional)",
  "criticality": "integer (optional) - 1-10",
  "is_active": "boolean (optional)",
  "ip_ranges": "array (optional) - Array of IP range objects"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "location_id": "string (UUID)",
    "updated_fields": ["string"],
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

### PUT Risk Priorities

#### PUT /api/v1/risk-priorities/{link_id}

**Description:** Update risk priority information

**Request Body Fields:**
```json
{
  "remediation_status": "string (optional) - Open|In Progress|Resolved|False Positive",
  "remediation_notes": "string (optional)",
  "assigned_to": "string (optional) - User ID",
  "due_date": "string (optional) - ISO 8601 date",
  "compensating_controls": "string (optional)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "link_id": "string (UUID)",
    "updated_fields": ["string"],
    "updated_at": "string (ISO 8601 datetime)"
  }
}
```

---

### PUT Admin Risk Matrix

#### PUT /api/v1/admin/risk-matrix

**Description:** Update risk matrix configuration (Admin only)

**Request Body Fields:**
```json
{
  "config_name": "string (required)",
  "kev_weight": "number (required)",
  "clinical_high_score": "number (required)",
  "business_medium_score": "number (required)",
  "non_essential_score": "number (required)",
  "location_weight_multiplier": "number (required)",
  "critical_severity_score": "number (required)",
  "high_severity_score": "number (required)",
  "medium_severity_score": "number (required)",
  "low_severity_score": "number (required)",
  "epss_weight_enabled": "boolean (optional, default: true)",
  "epss_high_threshold": "decimal (optional, default: 0.7, range: 0.0-1.0)",
  "epss_weight_score": "number (optional, default: 20, range: 0-100)"
}
```

**Response Fields:**
```json
{
  "success": boolean,
  "message": "string",
  "data": {
    "config_id": "string (UUID)",
    "config_name": "string",
    "is_active": boolean,
    "created_at": "string (ISO 8601 datetime)",
    "created_by": "string (UUID)"
  }
}
```

---

## PUT Request Field Validation Rules

### Common Validation Rules
- **UUID Fields**: Must be valid UUID format
- **Date Fields**: Must be in ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)
- **Enum Fields**: Must match one of the specified values
- **Numeric Fields**: Must be valid numbers within specified ranges
- **String Fields**: Cannot be empty strings (use null instead)

### Field Requirements
- **Optional Fields**: All PUT request fields are optional unless marked as required
- **Partial Updates**: Only provided fields will be updated
- **Validation**: Server validates all provided fields before updating
- **Audit Trail**: All updates are logged with user ID and timestamp

### Error Responses
```json
{
  "success": false,
  "error": {
    "code": "string",
    "message": "string",
    "details": "object (optional)"
  },
  "timestamp": "string (ISO 8601 datetime)"
}
```

### Common Error Codes
- **INVALID_JSON**: Malformed JSON in request body
- **NO_FIELDS_TO_UPDATE**: No valid fields provided for update
- **VALIDATION_ERROR**: Field validation failed
- **NOT_FOUND**: Resource not found
- **INSUFFICIENT_PERMISSIONS**: User lacks required permissions
- **INTERNAL_ERROR**: Server error occurred

---

*Last Updated: November 2, 2025*
*Version: 1.1.0*
