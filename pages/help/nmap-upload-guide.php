<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Nmap Upload Guide for Device Assessment and Vulnerability Exposure ()
 * Comprehensive guide for uploading Nmap scan results via API
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Upload Guide - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/help.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Nmap Upload Guide Specific Styles */
        .guide-section {
            margin-bottom: 2rem;
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 8px;
            padding: 1.5rem;
        }

        .guide-section h3 {
            color: var(--siemens-petrol);
            border-bottom: 2px solid var(--siemens-petrol);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .code-example {
            background: var(--bg-primary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
            overflow-x: auto;
        }

        .code-example pre {
            margin: 0;
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .code-example code {
            color: var(--text-primary);
        }

        .parameter-table {
            overflow-x: auto;
            margin: 1rem 0;
        }

        .parameter-table table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
        }

        .parameter-table th,
        .parameter-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-primary);
        }

        .parameter-table th {
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-primary);
        }

        .parameter-table td {
            color: var(--text-secondary);
        }

        .parameter-table code {
            background: var(--bg-primary);
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: var(--siemens-petrol);
        }

        .response-example {
            background: var(--bg-primary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .response-example h5 {
            color: var(--text-primary);
            margin: 0 0 0.5rem 0;
            font-size: 0.9rem;
            font-weight: 600;
        }

        .response-example pre {
            margin: 0;
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            line-height: 1.4;
        }

        .step-list {
            counter-reset: step-counter;
        }

        .step-list li {
            counter-increment: step-counter;
            margin-bottom: 1rem;
            padding-left: 2rem;
            position: relative;
        }

        .step-list li::before {
            content: counter(step-counter);
            position: absolute;
            left: 0;
            top: 0;
            background: var(--siemens-petrol);
            color: white;
            width: 1.5rem;
            height: 1.5rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .warning-box {
            background: var(--bg-secondary);
            border-left: 4px solid var(--siemens-orange);
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 4px 4px 0;
        }

        .warning-box h4 {
            color: var(--siemens-orange);
            margin: 0 0 0.5rem 0;
            font-size: 1rem;
        }

        .warning-box p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .success-box {
            background: var(--bg-secondary);
            border-left: 4px solid #10b981;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 4px 4px 0;
        }

        .success-box h4 {
            color: #10b981;
            margin: 0 0 0.5rem 0;
            font-size: 1rem;
        }

        .success-box p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .api-endpoint {
            background: var(--bg-primary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .api-endpoint .method {
            display: inline-block;
            background: var(--siemens-petrol);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
            margin-right: 1rem;
        }

        .api-endpoint .url {
            font-family: 'Courier New', monospace;
            color: var(--text-primary);
            font-weight: 500;
        }

        .toc {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .toc h3 {
            color: var(--siemens-petrol);
            margin: 0 0 1rem 0;
            font-size: 1.1rem;
        }

        .toc ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .toc li {
            margin-bottom: 0.5rem;
        }

        .toc a {
            color: var(--text-secondary);
            text-decoration: none;
            transition: color 0.2s;
        }

        .toc a:hover {
            color: var(--siemens-petrol);
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="help-content-container">
            <div class="help-page-header">
                <div class="container">
                    <h1><i class="fas fa-upload"></i> Nmap Upload Guide</h1>
                    <p>Comprehensive guide for uploading Nmap scan results via API</p>
                </div>
            </div>

            <div class="help-content">

            <div class="documentation-content">
                <!-- Table of Contents -->
                <div class="toc">
                    <h3><i class="fas fa-list"></i> Table of Contents</h3>
                    <ul>
                        <li><a href="#overview">Overview</a></li>
                        <li><a href="#api-endpoint">API Endpoint</a></li>
                        <li><a href="#parameters">Required Parameters</a></li>
                        <li><a href="#examples">Usage Examples</a></li>
                        <li><a href="#response-format">Response Format</a></li>
                        <li><a href="#nmap-formats">Supported Nmap Formats</a></li>
                        <li><a href="#extracted-data">Extracted Data</a></li>
                        <li><a href="#advanced-usage">Advanced Usage</a></li>
                        <li><a href="#authentication">Authentication</a></li>
                        <li><a href="#monitoring">Monitoring Results</a></li>
                        <li><a href="#error-handling">Error Handling</a></li>
                        <li><a href="#best-practices">Best Practices</a></li>
                        <li><a href="#next-steps">Next Steps</a></li>
                    </ul>
                </div>

                <!-- Overview -->
                <div class="guide-section" id="overview">
                    <h3><i class="fas fa-info-circle"></i> Overview</h3>
                    <p>This guide shows you how to use the  API to upload Nmap scan results for automated asset discovery and management. The API supports Nmap XML output files and automatically extracts network information, open ports, and service details.</p>
                    
                    <div class="success-box">
                        <h4><i class="fas fa-check-circle"></i> Key Benefits</h4>
                        <p>• Automated asset discovery from network scans<br>
                        • Automatic extraction of host information, ports, and services<br>
                        • Integration with device mapping and vulnerability management<br>
                        • Support for multiple scan types and formats</p>
                    </div>
                </div>

                <!-- API Endpoint -->
                <div class="guide-section" id="api-endpoint">
                    <h3><i class="fas fa-code"></i> API Endpoint</h3>
                    
                    <div class="api-endpoint">
                        <span class="method">POST</span>
                        <span class="url">/api/v1/assets/upload</span>
                    </div>
                    
                    <p><strong>Content-Type:</strong> <code>multipart/form-data</code></p>
                    <p><strong>Authentication:</strong> Bearer Token Required</p>
                </div>

                <!-- Parameters -->
                <div class="guide-section" id="parameters">
                    <h3><i class="fas fa-cogs"></i> Required Parameters</h3>
                    
                    <div class="parameter-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Parameter</th>
                                    <th>Type</th>
                                    <th>Required</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><code>file</code></td>
                                    <td>file</td>
                                    <td>Yes</td>
                                    <td>Nmap XML output file</td>
                                </tr>
                                <tr>
                                    <td><code>type</code></td>
                                    <td>string</td>
                                    <td>Yes</td>
                                    <td>Upload type - must be "nmap"</td>
                                </tr>
                                <tr>
                                    <td><code>department</code></td>
                                    <td>string</td>
                                    <td>No</td>
                                    <td>Department assignment for discovered assets</td>
                                </tr>
                                <tr>
                                    <td><code>location</code></td>
                                    <td>string</td>
                                    <td>No</td>
                                    <td>Location assignment for discovered assets</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Usage Examples -->
                <div class="guide-section" id="examples">
                    <h3><i class="fas fa-terminal"></i> Usage Examples</h3>
                    
                    <h4>1. Basic Nmap Upload (cURL)</h4>
                    <div class="code-example">
                        <pre><code>curl -X POST "https://your-dave-instance.com/api/v1/assets/upload" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -F "file=@nmap_scan_results.xml" \
  -F "type=nmap"</code></pre>
                    </div>

                    <h4>2. Nmap Upload with Department and Location</h4>
                    <div class="code-example">
                        <pre><code>curl -X POST "https://your-dave-instance.com/api/v1/assets/upload" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -F "file=@nmap_scan_results.xml" \
  -F "type=nmap" \
  -F "department=Radiology" \
  -F "location=Floor 3"</code></pre>
                    </div>

                    <h4>3. Python Example</h4>
                    <div class="code-example">
                        <pre><code>import requests

# API endpoint
url = "https://your-dave-instance.com/api/v1/assets/upload"

# Headers
headers = {
    "Authorization": "Bearer YOUR_API_TOKEN"
}

# File upload
files = {
    "file": ("nmap_scan_results.xml", open("nmap_scan_results.xml", "rb"), "application/xml")
}

# Form data
data = {
    "type": "nmap",
    "department": "Radiology",
    "location": "Floor 3"
}

# Upload file
response = requests.post(url, headers=headers, files=files, data=data)

if response.status_code == 200:
    result = response.json()
    print(f"Success! Processed {result['data']['processed']} assets")
    if result['data']['errors']:
        print(f"Errors: {result['data']['errors']}")
else:
    print(f"Error: {response.json()}")</code></pre>
                    </div>

                    <h4>4. JavaScript/Node.js Example</h4>
                    <div class="code-example">
                        <pre><code>const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

async function uploadNmapScan(filePath, department = null, location = null) {
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    form.append('type', 'nmap');
    if (department) form.append('department', department);
    if (location) form.append('location', location);

    try {
        const response = await axios.post(
            'https://your-dave-instance.com/api/v1/assets/upload',
            form,
            {
                headers: {
                    ...form.getHeaders(),
                    'Authorization': 'Bearer YOUR_API_TOKEN'
                }
            }
        );

        if (response.data.data.errors.length > 0) {
        }
    } catch (error) {
        console.error('Upload failed:', error.response?.data || error.message);
    }
}

// Usage
uploadNmapScan('./nmap_scan_results.xml', 'Radiology', 'Floor 3');</code></pre>
                    </div>
                </div>

                <!-- Response Format -->
                <div class="guide-section" id="response-format">
                    <h3><i class="fas fa-reply"></i> Response Format</h3>
                    
                    <h4>Success Response (200 OK)</h4>
                    <div class="response-example">
                        <h5>JSON Response</h5>
                        <pre><code>{
    "success": true,
    "data": {
        "processed": 15,
        "errors": [],
        "file_type": "nmap",
        "filename": "nmap_scan_results.xml"
    },
    "message": "File uploaded and processed successfully",
    "timestamp": "2024-01-01T00:00:00Z"
}</code></pre>
                    </div>

                    <h4>Error Response (400 Bad Request)</h4>
                    <div class="response-example">
                        <h5>JSON Response</h5>
                        <pre><code>{
    "success": false,
    "error": {
        "code": "INVALID_TYPE",
        "message": "Invalid upload type. Must be: nmap, nessus, csv"
    }
}</code></pre>
                    </div>

                    <h4>Error Response (401 Unauthorized)</h4>
                    <div class="response-example">
                        <h5>JSON Response</h5>
                        <pre><code>{
    "success": false,
    "error": {
        "code": "UNAUTHORIZED",
        "message": "Authentication required"
    }
}</code></pre>
                    </div>
                </div>

                <!-- Supported Nmap Formats -->
                <div class="guide-section" id="nmap-formats">
                    <h3><i class="fas fa-file-code"></i> Supported Nmap Output Formats</h3>
                    
                    <h4>1. XML Output (Recommended)</h4>
                    <div class="code-example">
                        <pre><code>nmap -sS -O -sV -oX scan_results.xml 192.168.1.0/24</code></pre>
                    </div>

                    <h4>2. Comprehensive Scan</h4>
                    <div class="code-example">
                        <pre><code>nmap -sS -O -sV -sC -A -oX comprehensive_scan.xml 192.168.1.0/24</code></pre>
                    </div>

                    <h4>3. Service Detection</h4>
                    <div class="code-example">
                        <pre><code>nmap -sS -sV -p 1-65535 -oX service_scan.xml 192.168.1.0/24</code></pre>
                    </div>

                    <div class="warning-box">
                        <h4><i class="fas fa-exclamation-triangle"></i> Important</h4>
                        <p>Only XML output format is supported. Use the <code>-oX</code> flag to generate XML output from Nmap.</p>
                    </div>
                </div>

                <!-- Extracted Data -->
                <div class="guide-section" id="extracted-data">
                    <h3><i class="fas fa-database"></i> Extracted Data</h3>
                    
                    <p>The API extracts the following information from Nmap XML files:</p>
                    
                    <h4>Asset Information</h4>
                    <ul>
                        <li><strong>Hostname:</strong> Hostname if available</li>
                        <li><strong>IP Address:</strong> Primary IP address</li>
                        <li><strong>MAC Address:</strong> MAC address if available</li>
                        <li><strong>Operating System:</strong> OS detection results</li>
                        <li><strong>Open Ports:</strong> List of open ports with services</li>
                        <li><strong>Service Versions:</strong> Service and version information</li>
                    </ul>

                    <h4>Port Information</h4>
                    <ul>
                        <li><strong>Port Number:</strong> Port number</li>
                        <li><strong>Protocol:</strong> TCP/UDP protocol</li>
                        <li><strong>Service Name:</strong> Detected service name</li>
                        <li><strong>Service Version:</strong> Service version if available</li>
                        <li><strong>State:</strong> Port state (open, closed, filtered)</li>
                    </ul>
                </div>

                <!-- Advanced Usage -->
                <div class="guide-section" id="advanced-usage">
                    <h3><i class="fas fa-rocket"></i> Advanced Usage</h3>
                    
                    <h4>1. Automated Scanning with Upload</h4>
                    <div class="code-example">
                        <pre><code>#!/bin/bash
# Automated Nmap scan and upload script

# Configuration
API_URL="https://your-dave-instance.com/api/v1/assets/upload"
API_TOKEN="YOUR_API_TOKEN"
DEPARTMENT="Radiology"
LOCATION="Floor 3"
TARGET_NETWORK="192.168.1.0/24"

# Run Nmap scan
echo "Starting Nmap scan of $TARGET_NETWORK..."
nmap -sS -O -sV -oX scan_results.xml $TARGET_NETWORK

# Upload results
echo "Uploading scan results..."
curl -X POST "$API_URL" \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@scan_results.xml" \
  -F "type=nmap" \
  -F "department=$DEPARTMENT" \
  -F "location=$LOCATION"

# Clean up
rm scan_results.xml
echo "Scan complete and results uploaded!"</code></pre>
                    </div>

                    <h4>2. Scheduled Scanning</h4>
                    <div class="code-example">
                        <pre><code># Add to crontab for daily scans
# Run every day at 2 AM
0 2 * * * /path/to/automated_scan.sh</code></pre>
                    </div>

                    <h4>3. Multiple Network Scans</h4>
                    <div class="code-example">
                        <pre><code>#!/bin/bash
# Scan multiple networks and upload results

NETWORKS=("192.168.1.0/24" "192.168.2.0/24" "10.0.1.0/24")
DEPARTMENTS=("Radiology" "Cardiology" "ICU")

for i in "${!NETWORKS[@]}"; do
    NETWORK="${NETWORKS[$i]}"
    DEPT="${DEPARTMENTS[$i]}"
    
    echo "Scanning $NETWORK for $DEPT..."
    nmap -sS -O -sV -oX "scan_${i}.xml" "$NETWORK"
    
    curl -X POST "$API_URL" \
      -H "Authorization: Bearer $API_TOKEN" \
      -F "file=@scan_${i}.xml" \
      -F "type=nmap" \
      -F "department=$DEPT"
    
    rm "scan_${i}.xml"
done</code></pre>
                    </div>
                </div>

                <!-- Authentication -->
                <div class="guide-section" id="authentication">
                    <h3><i class="fas fa-lock"></i> Authentication</h3>
                    
                    <h4>1. Get API Token</h4>
                    <p>First, authenticate to get an API token:</p>
                    <div class="code-example">
                        <pre><code>curl -X POST "https://your-dave-instance.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'</code></pre>
                    </div>

                    <h4>2. Use Token in Requests</h4>
                    <p>Include the token in the Authorization header:</p>
                    <div class="code-example">
                        <pre><code>curl -X POST "https://your-dave-instance.com/api/v1/assets/upload" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@nmap_scan_results.xml" \
  -F "type=nmap"</code></pre>
                    </div>
                </div>

                <!-- Monitoring Results -->
                <div class="guide-section" id="monitoring">
                    <h3><i class="fas fa-chart-line"></i> Monitoring Upload Results</h3>
                    
                    <h4>1. Check Uploaded Assets</h4>
                    <div class="code-example">
                        <pre><code>curl -X GET "https://your-dave-instance.com/api/v1/assets" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"</code></pre>
                    </div>

                    <h4>2. Filter by Source</h4>
                    <div class="code-example">
                        <pre><code>curl -X GET "https://your-dave-instance.com/api/v1/assets?source=nmap" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"</code></pre>
                    </div>

                    <h4>3. Filter by Department</h4>
                    <div class="code-example">
                        <pre><code>curl -X GET "https://your-dave-instance.com/api/v1/assets?department=Radiology" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"</code></pre>
                    </div>
                </div>

                <!-- Error Handling -->
                <div class="guide-section" id="error-handling">
                    <h3><i class="fas fa-exclamation-triangle"></i> Error Handling</h3>
                    
                    <h4>Common Error Codes</h4>
                    <ul>
                        <li><strong><code>NO_FILE</code>:</strong> No file uploaded or upload error</li>
                        <li><strong><code>INVALID_TYPE</code>:</strong> Invalid upload type specified</li>
                        <li><strong><code>INVALID_EXTENSION</code>:</strong> Invalid file extension</li>
                        <li><strong><code>UPLOAD_FAILED</code>:</strong> Failed to save uploaded file</li>
                        <li><strong><code>PROCESSING_FAILED</code>:</strong> No assets were processed</li>
                        <li><strong><code>UNAUTHORIZED</code>:</strong> Authentication required</li>
                        <li><strong><code>SERVER_ERROR</code>:</strong> Internal server error</li>
                    </ul>

                    <h4>Troubleshooting</h4>
                    <ol class="step-list">
                        <li><strong>File Format:</strong> Ensure your Nmap output is in XML format (<code>-oX</code>)</li>
                        <li><strong>File Size:</strong> Large files may timeout - consider splitting scans</li>
                        <li><strong>Network:</strong> Check network connectivity to API endpoint</li>
                        <li><strong>Authentication:</strong> Verify API token is valid and not expired</li>
                        <li><strong>Permissions:</strong> Ensure user has permission to upload assets</li>
                    </ol>
                </div>

                <!-- Best Practices -->
                <div class="guide-section" id="best-practices">
                    <h3><i class="fas fa-star"></i> Best Practices</h3>
                    
                    <h4>1. Scan Optimization</h4>
                    <ul>
                        <li>Use appropriate scan types for your network</li>
                        <li>Avoid aggressive scans on production networks</li>
                        <li>Schedule scans during maintenance windows</li>
                        <li>Use targeted scans for specific subnets</li>
                    </ul>

                    <h4>2. Data Organization</h4>
                    <ul>
                        <li>Assign appropriate departments and locations</li>
                        <li>Use consistent naming conventions</li>
                        <li>Regularly review and clean up old scan data</li>
                        <li>Monitor for duplicate assets</li>
                    </ul>

                    <h4>3. Security Considerations</h4>
                    <ul>
                        <li>Secure API tokens and credentials</li>
                        <li>Use HTTPS for all API communications</li>
                        <li>Implement proper access controls</li>
                        <li>Monitor upload activities</li>
                    </ul>
                </div>

                <!-- Next Steps -->
                <div class="guide-section" id="next-steps">
                    <h3><i class="fas fa-arrow-right"></i> Next Steps</h3>
                    
                    <p>After uploading Nmap scan results:</p>
                    <ol class="step-list">
                        <li><strong>Review Assets:</strong> Check the discovered assets in the web interface</li>
                        <li><strong>Map Devices:</strong> Use the device mapping API to link assets to FDA records</li>
                        <li><strong>Vulnerability Scanning:</strong> Trigger vulnerability scans on discovered assets</li>
                        <li><strong>Compliance Monitoring:</strong> Set up recall monitoring for mapped devices</li>
                        <li><strong>Reporting:</strong> Generate reports on discovered assets and their status</li>
                    </ol>
                </div>

                <!-- Footer -->
                <div class="guide-section">
                    <h3><i class="fas fa-info-circle"></i> Documentation Info</h3>
                    <p><strong>API Endpoint:</strong> <code>POST /api/v1/assets/upload</code><br>
                    <strong>Authentication:</strong> Bearer Token Required<br>
                    <strong>Content-Type:</strong> <code>multipart/form-data</code><br>
                    <strong>File Format:</strong> Nmap XML Output (<code>-oX</code>)<br>
                    <strong>Status:</strong> ✅ <strong>IMPLEMENTED</strong><br>
                    <strong>Documentation:</strong> ✅ <strong>COMPLETE</strong></p>
                </div>
            </div>
                </div>
        </div>
    </main>
</body>
</html>
