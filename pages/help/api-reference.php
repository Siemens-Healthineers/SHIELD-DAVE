<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../includes/auth.php';

// Initialize authentication
$auth = new Auth();
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
    <title>API Reference - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/help.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Enhanced Postman-style API Documentation */
        .api-container {
            display: flex;
            gap: 2rem;
            max-width: 1440px;
            margin: 0 auto;
            padding: 2rem;
        }

        .api-sidebar {
            width: 300px;
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
            height: fit-content;
            position: sticky;
            top: 2rem;
        }

        .api-content {
            flex: 1;
            min-width: 0;
        }

        .sidebar-section {
            margin-bottom: 1.5rem;
        }

        .sidebar-section h4 {
            color: var(--siemens-petrol);
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 0.75rem;
            letter-spacing: 0.05em;
        }

        .sidebar-nav {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .sidebar-nav li {
            margin-bottom: 0.25rem;
        }

        .sidebar-nav a {
            display: block;
            padding: 0.5rem 0.75rem;
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            transition: all 0.2s;
        }

        .sidebar-nav a:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .sidebar-nav a.active {
            background: var(--siemens-petrol);
            color: white;
        }

        .api-section {
            margin-bottom: 3rem;
            scroll-margin-top: 2rem;
        }

        .api-section h3 {
            color: var(--siemens-petrol);
            border-bottom: 2px solid var(--siemens-petrol);
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .endpoint-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .endpoint-header {
            background: var(--bg-secondary);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .method {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            min-width: 60px;
            text-align: center;
        }

        .method.get { background: #10b981; color: white; }
        .method.post { background: #3b82f6; color: white; }
        .method.put { background: #f59e0b; color: white; }
        .method.delete { background: #ef4444; color: white; }

        .endpoint-url {
            font-family: 'Courier New', monospace;
            background: var(--bg-primary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            color: var(--text-primary);
            flex: 1;
            min-width: 200px;
        }

        .endpoint-description {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-left: auto;
        }

        .endpoint-body {
            padding: 1.5rem;
        }

        .endpoint-body h4 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1rem;
        }

        .param-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
        }

        .param-table th,
        .param-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-primary);
        }

        .param-table th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.875rem;
        }

        .param-table td {
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .param-name {
            font-family: 'Courier New', monospace;
            color: var(--siemens-petrol);
            font-weight: 600;
        }

        .param-type {
            color: var(--siemens-orange);
            font-size: 0.75rem;
            font-weight: 600;
        }

        .param-required {
            color: #ef4444;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .param-optional {
            color: var(--text-muted);
            font-size: 0.75rem;
        }

        .json-example {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
            overflow-x: auto;
        }

        .json-example pre {
            margin: 0;
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .json-example .json-key { color: var(--siemens-petrol); }
        .json-example .json-string { color: #10b981; }
        .json-example .json-number { color: var(--siemens-orange); }
        .json-example .json-boolean { color: #3b82f6; }
        .json-example .json-null { color: var(--text-muted); }

        .response-codes {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .response-code {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 4px;
            padding: 0.75rem;
        }

        .response-code .code {
            font-weight: 600;
            font-size: 0.875rem;
        }

        .response-code .code.success { color: #10b981; }
        .response-code .code.error { color: #ef4444; }
        .response-code .code.info { color: #3b82f6; }

        .response-code .description {
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-top: 0.25rem;
        }

        .api-note {
            background: var(--bg-secondary);
            border-left: 4px solid var(--siemens-petrol);
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 4px 4px 0;
        }

        .api-note strong {
            color: var(--siemens-petrol);
        }

        .search-box {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            color: var(--text-primary);
            margin-bottom: 1rem;
        }

        .search-box:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }

        .endpoint-card.hidden {
            display: none;
        }

        .no-results {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
        }

        .back-to-nav {
            margin-bottom: 1rem;
        }

        .back-to-nav-link {
            color: var(--siemens-petrol);
            text-decoration: none;
            font-size: 0.875rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .back-to-nav-link:hover {
            text-decoration: underline;
        }

        @media (max-width: 768px) {
            .api-container {
                flex-direction: column;
                padding: 1rem;
            }
            
            .api-sidebar {
                width: 100%;
                position: static;
            }
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="api-container">
            <!-- Sidebar Navigation -->
            <div class="api-sidebar">
                <div class="sidebar-section">
                    <h4>Search APIs</h4>
                    <input type="text" class="search-box" placeholder="Search endpoints..." id="apiSearch">
            </div>

                <div class="sidebar-section">
                    <h4>Core APIs</h4>
                    <ul class="sidebar-nav">
                        <li><a href="#authentication" class="nav-link">Authentication</a></li>
                        <li><a href="#assets" class="nav-link">Assets</a></li>
                        <li><a href="#vulnerabilities" class="nav-link">Vulnerabilities</a></li>
                        <li><a href="#components" class="nav-link">Software Components</a></li>
                        <li><a href="#recalls" class="nav-link">Recalls</a></li>
                        <li><a href="#patches" class="nav-link">Patches</a></li>
                    </ul>
                    </div>

                <div class="sidebar-section">
                    <h4>Management APIs</h4>
                    <ul class="sidebar-nav">
                        <li><a href="#users" class="nav-link">User Management</a></li>
                        <li><a href="#locations" class="nav-link">Locations</a></li>
                        <li><a href="#devices" class="nav-link">Device Mapping</a></li>
                        <li><a href="#risk-priorities" class="nav-link">Risk Priorities</a></li>
                        <li><a href="#software-packages" class="nav-link">Software Packages</a></li>
                    </ul>
                    </div>

                <div class="sidebar-section">
                    <h4>Analytics & System</h4>
                    <ul class="sidebar-nav">
                        <li><a href="#analytics" class="nav-link">Analytics</a></li>
                        <li><a href="#reports" class="nav-link">Reports</a></li>
                        <li><a href="#system" class="nav-link">System</a></li>
                        <li><a href="#admin" class="nav-link">Admin</a></li>
                        <li><a href="#sessions" class="nav-link">Sessions</a></li>
                    </ul>
                        </div>
                    </div>

            <!-- Main Content -->
            <div class="api-content">
                <div class="api-section" id="api-overview">
                    <h3><i class="fas fa-info-circle"></i> API Overview</h3>
                    <div class="api-note">
                        <strong>Base URL:</strong> <code><?php echo $_SERVER['HTTP_HOST']; ?>/api/v1/</code><br>
                        <strong>Authentication:</strong> Session-based authentication required for all endpoints<br>
                        <strong>Content-Type:</strong> application/json<br>
                        <strong>API Version:</strong> 1.0.0
                            </div>
                    <p>The  API provides comprehensive access to all system functionality including asset management, vulnerability tracking, recall management, and analytics. All endpoints require authentication and return JSON responses.</p>
                </div>

                <!-- Authentication Section -->
                <div class="api-section" id="authentication">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-lock"></i> Authentication</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/auth/login</span>
                            <span class="endpoint-description">User login</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Request Body</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">username</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>User's username</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">password</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>User's password</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">mfa_code</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>MFA code if enabled</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Request</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"username"</span>: <span class="json-string">"admin"</span>,
  <span class="json-key">"password"</span>: <span class="json-string">"password123"</span>,
  <span class="json-key">"mfa_code"</span>: <span class="json-string">"123456"</span>
}</pre>
                            </div>
                            
                            <h4>Response Codes</h4>
                            <div class="response-codes">
                                <div class="response-code">
                                    <div class="code success">200</div>
                                    <div class="description">Login successful</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">401</div>
                                    <div class="description">Invalid credentials</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">423</div>
                                    <div class="description">Account locked</div>
                                </div>
                            </div>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"user"</span>: {
    <span class="json-key">"user_id"</span>: <span class="json-string">"uuid"</span>,
    <span class="json-key">"username"</span>: <span class="json-string">"admin"</span>,
    <span class="json-key">"email"</span>: <span class="json-string">"admin@dave.local"</span>,
    <span class="json-key">"role"</span>: <span class="json-string">"Admin"</span>,
    <span class="json-key">"is_active"</span>: <span class="json-boolean">true</span>
  },
  <span class="json-key">"message"</span>: <span class="json-string">"Login successful"</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/auth/logout</span>
                            <span class="endpoint-description">User logout</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Logs out the current user and invalidates the session.</p>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"message"</span>: <span class="json-string">"Logged out successfully"</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/auth/me</span>
                            <span class="endpoint-description">Get current user info</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns information about the currently authenticated user.</p>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"user"</span>: {
    <span class="json-key">"user_id"</span>: <span class="json-string">"uuid"</span>,
    <span class="json-key">"username"</span>: <span class="json-string">"admin"</span>,
    <span class="json-key">"email"</span>: <span class="json-string">"admin@dave.local"</span>,
    <span class="json-key">"role"</span>: <span class="json-string">"Admin"</span>,
    <span class="json-key">"is_active"</span>: <span class="json-boolean">true</span>,
    <span class="json-key">"last_login"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>,
    <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-01T00:00:00Z"</span>
  }
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card" style="margin-top: 2rem; border-left: 4px solid var(--siemens-orange);">
                        <div class="endpoint-header">
                            <span class="method get">API KEY</span>
                            <span class="endpoint-url">API Key Authentication</span>
                            <span class="endpoint-description">Programmatic access for external systems</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Overview</h4>
                            <p> supports API key authentication for programmatic access to the API. API keys provide a secure way for external systems and applications to authenticate without requiring username/password credentials. API keys support scopes, IP whitelisting, rate limiting, and expiration dates.</p>
                            
                            <h4>Creating API Keys</h4>
                            <p>API keys can be created through:</p>
                            <ul>
                                <li><strong>Web Interface:</strong> Navigate to User Settings → API Keys (for your own keys) or Admin → API Keys (for managing all keys)</li>
                                <li><strong>API Endpoint:</strong> <code>POST /api/v1/admin/api-keys/create</code> (Admin only)</li>
                            </ul>
                            
                            <h4>Using API Keys</h4>
                            <p>API keys can be sent in three ways (in order of preference):</p>
                            
                            <h5>1. Authorization Header (Recommended)</h5>
                            <div class="json-example">
                                <pre><span class="json-comment">// Using Bearer token format</span>
<span class="json-key">Authorization</span>: <span class="json-string">Bearer dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</span></pre>
                            </div>
                            
                            <h5>2. X-API-Key Header</h5>
                            <div class="json-example">
                                <pre><span class="json-key">X-API-Key</span>: <span class="json-string">dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</span></pre>
                            </div>
                            
                            <h5>3. Query Parameter (Less Secure)</h5>
                            <div class="json-example">
                                <pre><span class="json-comment">// Only use when headers cannot be set</span>
<span class="json-string">GET /api/v1/assets?api_key=dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</span></pre>
                            </div>
                            
                            <h4>Example Request with API Key</h4>
                            <div class="json-example">
                                <pre><span class="json-comment">// Using curl with Authorization header</span>
<span class="json-string">curl -X GET "https://your-dave-domain.com/api/v1/assets" \
  -H "Authorization: Bearer dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json"</span>

<span class="json-comment">// Using curl with X-API-Key header</span>
<span class="json-string">curl -X GET "https://your-dave-domain.com/api/v1/assets" \
  -H "X-API-Key: dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json"</span>

<span class="json-comment">// Using JavaScript fetch</span>
<span class="json-key">fetch</span>(<span class="json-string">'https://your-dave-domain.com/api/v1/assets'</span>, {
  <span class="json-key">headers</span>: {
    <span class="json-key">'Authorization'</span>: <span class="json-string">'Bearer dave_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'</span>,
    <span class="json-key">'Content-Type'</span>: <span class="json-string">'application/json'</span>
  }
})</pre>
                            </div>
                            
                            <h4>API Key Features</h4>
                            <table class="param-table">
                                <thead>
                                    <tr>
                                        <th>Feature</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="param-name">Scopes</span></td>
                                        <td>Control which API endpoints the key can access (e.g., <code>assets:read</code>, <code>vulnerabilities:write</code>)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">IP Whitelist</span></td>
                                        <td>Restrict API key usage to specific IP addresses for enhanced security</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">Rate Limiting</span></td>
                                        <td>Configure maximum requests per hour (default: 1000 requests/hour)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">Expiration</span></td>
                                        <td>Set optional expiration date for time-limited access</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">Permissions</span></td>
                                        <td>Inherit user permissions or override with custom permissions (Admin only)</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>API Key Scopes</h4>
                            <p>Common scopes available for API keys:</p>
                            <ul>
                                <li><code>assets:read</code> - Read asset information</li>
                                <li><code>assets:write</code> - Create and update assets</li>
                                <li><code>vulnerabilities:read</code> - Read vulnerability data</li>
                                <li><code>vulnerabilities:write</code> - Update vulnerability information</li>
                                <li><code>recalls:read</code> - Read recall information</li>
                                <li><code>recalls:write</code> - Manage recalls</li>
                                <li><code>epss:read</code> - Access EPSS data</li>
                                <li><code>reports:read</code> - Generate and view reports</li>
                                <li><code>admin:*</code> - Full administrative access (Admin only)</li>
                            </ul>
                            
                            <h4>Response Codes for API Key Authentication</h4>
                            <div class="response-codes">
                                <div class="response-code">
                                    <div class="code success">200</div>
                                    <div class="description">Request successful with valid API key</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">401</div>
                                    <div class="description">Invalid or missing API key</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">403</div>
                                    <div class="description">API key lacks required scope or permission</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">423</div>
                                    <div class="description">API key is disabled or expired</div>
                                </div>
                                <div class="response-code">
                                    <div class="code error">429</div>
                                    <div class="description">Rate limit exceeded</div>
                                </div>
                            </div>
                            
                            <h4>Error Response Example</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"UNAUTHORIZED"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Invalid API key"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                            
                            <h4>Security Best Practices</h4>
                            <ul>
                                <li><strong>Use Authorization Header:</strong> Prefer the <code>Authorization: Bearer</code> header over query parameters</li>
                                <li><strong>Store Securely:</strong> Never commit API keys to version control or expose them in client-side code</li>
                                <li><strong>Use IP Whitelisting:</strong> Restrict API keys to specific IP addresses when possible</li>
                                <li><strong>Set Expiration Dates:</strong> Use time-limited keys for temporary integrations</li>
                                <li><strong>Minimal Scopes:</strong> Grant only the minimum required scopes for each use case</li>
                                <li><strong>Rotate Regularly:</strong> Periodically regenerate API keys to maintain security</li>
                                <li><strong>Monitor Usage:</strong> Review API key usage logs regularly for suspicious activity</li>
                            </ul>
                            
                            <h4>API Key Management Endpoints</h4>
                            <p>Administrators can manage API keys via the following endpoints:</p>
                            <ul>
                                <li><code>GET /api/v1/admin/api-keys</code> - List all API keys</li>
                                <li><code>POST /api/v1/admin/api-keys/create</code> - Create new API key</li>
                                <li><code>PUT /api/v1/admin/api-keys/{key_id}</code> - Update API key</li>
                                <li><code>DELETE /api/v1/admin/api-keys/{key_id}</code> - Delete API key</li>
                                <li><code>POST /api/v1/admin/api-keys/{key_id}/regenerate</code> - Regenerate API key</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- Assets Section -->
                <div class="api-section" id="assets">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-server"></i> Assets</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/assets</span>
                            <span class="endpoint-description">List all assets</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">page</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                            <td>Page number (default: 1)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">limit</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Items per page (default: 25)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">search</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Search by hostname or IP</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">department</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                            <td>Filter by department</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">criticality</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by criticality level</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"asset_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"hostname"</span>: <span class="json-string">"server-01"</span>,
      <span class="json-key">"ip_address"</span>: <span class="json-string">"192.168.1.100"</span>,
      <span class="json-key">"asset_type"</span>: <span class="json-string">"Server"</span>,
      <span class="json-key">"criticality"</span>: <span class="json-string">"Clinical-High"</span>,
      <span class="json-key">"department"</span>: <span class="json-string">"ICU"</span>,
      <span class="json-key">"status"</span>: <span class="json-string">"Active"</span>,
      <span class="json-key">"location_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-01T00:00:00Z"</span>,
      <span class="json-key">"updated_at"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
    }
  ],
  <span class="json-key">"pagination"</span>: {
    <span class="json-key">"page"</span>: <span class="json-number">1</span>,
    <span class="json-key">"limit"</span>: <span class="json-number">25</span>,
    <span class="json-key">"total"</span>: <span class="json-number">150</span>,
    <span class="json-key">"pages"</span>: <span class="json-number">6</span>
  }
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/assets/{asset_id}</span>
                            <span class="endpoint-description">Get specific asset</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Path Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">asset_id</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Asset UUID</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"asset_id"</span>: <span class="json-string">"uuid"</span>,
    <span class="json-key">"hostname"</span>: <span class="json-string">"server-01"</span>,
    <span class="json-key">"ip_address"</span>: <span class="json-string">"192.168.1.100"</span>,
    <span class="json-key">"asset_type"</span>: <span class="json-string">"Server"</span>,
    <span class="json-key">"criticality"</span>: <span class="json-string">"Clinical-High"</span>,
    <span class="json-key">"department"</span>: <span class="json-string">"ICU"</span>,
    <span class="json-key">"status"</span>: <span class="json-string">"Active"</span>,
    <span class="json-key">"location_id"</span>: <span class="json-string">"uuid"</span>,
    <span class="json-key">"asset_tag"</span>: <span class="json-string">"ASSET-001"</span>,
    <span class="json-key">"serial_number"</span>: <span class="json-string">"SN123456"</span>,
    <span class="json-key">"manufacturer"</span>: <span class="json-string">"Dell"</span>,
    <span class="json-key">"model"</span>: <span class="json-string">"PowerEdge R740"</span>,
    <span class="json-key">"os_version"</span>: <span class="json-string">"Windows Server 2019"</span>,
    <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-01T00:00:00Z"</span>,
    <span class="json-key">"updated_at"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
  }
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/assets</span>
                            <span class="endpoint-description">Create new asset</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Request Body</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">hostname</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Asset hostname</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">ip_address</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>IP address</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">asset_type</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Type of asset</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">criticality</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Criticality level</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">department</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Department</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            </div>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/assets/upload</span>
                            <span class="endpoint-description">Upload assets from scan files</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Upload assets from security scan files (nmap, Nessus, CSV) to automatically create or update assets in the system.</p>
                            
                            <div class="param-section">
                                <h4>Request Parameters</h4>
                                <table class="param-table">
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
                                            <td><span class="param-name">file</span></td>
                                            <td><span class="param-type">file</span></td>
                                            <td><span class="param-required">Yes</span></td>
                                            <td>The uploaded scan file (nmap XML, Nessus XML, or CSV)</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">type</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>Type of scan file: "nmap", "nessus", or "csv" (defaults to "nmap")</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">department</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>Department to assign to imported assets</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">location</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>Location to assign to imported assets</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div class="param-section">
                                <h4>Supported File Types</h4>
                                <ul>
                                    <li><strong>Nmap XML:</strong> Standard nmap XML output files - extracts hostnames, IP addresses, MAC addresses, OS info, and open ports</li>
                                    <li><strong>Nessus XML:</strong> Tenable Nessus scan results - extracts host information and vulnerability data</li>
                                    <li><strong>CSV:</strong> Custom CSV files with asset data - supports hostname, ip_address, mac_address, manufacturer, model, serial_number columns</li>
                                </ul>
                            </div>

                            <div class="param-section">
                                <h4>Example Request</h4>
                                <div class="json-example">
                                    <pre><code>curl -X POST https://your-dave-instance.com/api/v1/assets/upload \
  -H "Authorization: Bearer your-session-token" \
  -F "file=@network_scan.xml" \
  -F "type=nmap" \
  -F "department=IT" \
  -F "location=Data Center"</code></pre>
                                </div>
                            </div>

                            <div class="param-section">
                                <h4>Success Response</h4>
                                <div class="json-example">
                                    <pre><code>{
  "success": true,
  "data": {
    "processed": 25,
    "errors": [],
    "file_type": "nmap",
    "filename": "network_scan.xml"
  },
  "message": "File uploaded and processed successfully",
  "timestamp": "2024-01-20T10:30:00Z"
}</code></pre>
                                </div>
                            </div>

                            <div class="param-section">
                                <h4>Error Response</h4>
                                <div class="json-example">
                                    <pre><code>{
  "success": false,
  "error": {
    "code": "NO_FILE",
    "message": "No file uploaded or upload error occurred"
  }
}</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                            </div>
                            
                <!-- Continue with remaining sections... -->
                <div class="api-section" id="vulnerabilities">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                            </div>
                    <h3><i class="fas fa-bug"></i> Vulnerabilities</h3>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/vulnerabilities</span>
                            <span class="endpoint-description">List vulnerabilities</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">severity</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by severity (Critical, High, Medium, Low)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">kev_only</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Show only KEV vulnerabilities</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">asset_id</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by specific asset</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"cve_id"</span>: <span class="json-string">"CVE-2024-1234"</span>,
      <span class="json-key">"description"</span>: <span class="json-string">"Buffer overflow vulnerability"</span>,
      <span class="json-key">"severity"</span>: <span class="json-string">"Critical"</span>,
      <span class="json-key">"cvss_v4_score"</span>: <span class="json-number">9.8</span>,
      <span class="json-key">"cvss_v3_score"</span>: <span class="json-number">9.8</span>,
      <span class="json-key">"cvss_v2_score"</span>: <span class="json-number">10.0</span>,
      <span class="json-key">"is_kev"</span>: <span class="json-boolean">true</span>,
      <span class="json-key">"published_date"</span>: <span class="json-string">"2024-01-15T00:00:00Z"</span>,
      <span class="json-key">"last_modified_date"</span>: <span class="json-string">"2024-01-20T00:00:00Z"</span>,
      <span class="json-key">"kev_due_date"</span>: <span class="json-string">"2024-02-15T00:00:00Z"</span>
    }
  ]
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/vulnerabilities</span>
                            <span class="endpoint-description">Create new vulnerability</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> Admin only</p>
                            <p><strong>Content-Type:</strong> application/json</p>
                            
                            <div class="alert alert-info" style="background-color: rgba(0, 153, 153, 0.1); border-left: 4px solid var(--siemens-petrol); padding: 1rem; margin-bottom: 1.5rem; border-radius: 0.375rem;">
                                <strong><i class="fas fa-info-circle"></i> Important:</strong> Vulnerabilities must be linked to a device/asset and component. Either <code>device_id</code> OR <code>asset_id</code> is required (not both). If <code>asset_id</code> is provided, it will be automatically resolved to the corresponding <code>device_id</code>.
                            </div>
                            
                            <h4>Request Body</h4>
                            <table class="param-table">
                                <thead>
                                    <tr>
                                        <th>Field</th>
                                        <th>Type</th>
                                        <th>Required</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="param-name">device_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-required">Required*</span></td>
                                        <td>Medical device UUID to link vulnerability to. <strong>Either device_id OR asset_id required</strong> (not both).</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">asset_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-required">Required*</span></td>
                                        <td>Asset UUID (alternative to device_id). Will be automatically resolved to device_id. <strong>Either device_id OR asset_id required</strong> (not both).</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cve_id</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>CVE identifier (format: CVE-YYYY-NNNN)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">component_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Software component UUID that has this vulnerability. Must exist in the software_components table.</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">description</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Vulnerability description</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">severity</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Critical, High, Medium, Low, Info, Unknown</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">priority</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Critical-KEV, High, Medium, Low, Normal</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cvss_v3_score</span></td>
                                        <td><span class="param-type">number</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>CVSS v3.x score (0.0-10.0)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cvss_v3_vector</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>CVSS v3.x vector string</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cvss_v4_score</span></td>
                                        <td><span class="param-type">number</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>CVSS v4.0 score (0.0-10.0)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cvss_v4_vector</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>CVSS v4.0 vector string</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">published_date</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Date published (YYYY-MM-DD)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">is_kev</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Whether in CISA KEV catalog</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">epss_score</span></td>
                                        <td><span class="param-type">number</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>EPSS probability score (0.0000-1.0000)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">nvd_data</span></td>
                                        <td><span class="param-type">object</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Additional NVD data as JSON</td>
                                    </tr>
                                </tbody>
                            </table>

                            <h4>Example Requests</h4>
                            
                            <h5>Example 1: Using device_id</h5>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"cve_id"</span>: <span class="json-string">"CVE-2024-1234"</span>,
  <span class="json-key">"device_id"</span>: <span class="json-string">"123e4567-e89b-12d3-a456-426614174000"</span>,
  <span class="json-key">"component_id"</span>: <span class="json-string">"456e7890-e89b-12d3-a456-426614174001"</span>,
  <span class="json-key">"description"</span>: <span class="json-string">"Remote code execution vulnerability"</span>,
  <span class="json-key">"severity"</span>: <span class="json-string">"Critical"</span>,
  <span class="json-key">"priority"</span>: <span class="json-string">"High"</span>,
  <span class="json-key">"cvss_v3_score"</span>: <span class="json-number">9.8</span>,
  <span class="json-key">"cvss_v3_vector"</span>: <span class="json-string">"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"</span>,
  <span class="json-key">"published_date"</span>: <span class="json-string">"2024-01-15"</span>,
  <span class="json-key">"is_kev"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"epss_score"</span>: <span class="json-number">0.1234</span>
}</pre>
                            </div>
                            
                            <h5>Example 2: Using asset_id (automatically resolved to device_id)</h5>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"cve_id"</span>: <span class="json-string">"CVE-2024-5678"</span>,
  <span class="json-key">"asset_id"</span>: <span class="json-string">"789e0123-e89b-12d3-a456-426614174002"</span>,
  <span class="json-key">"component_id"</span>: <span class="json-string">"012e3456-e89b-12d3-a456-426614174003"</span>,
  <span class="json-key">"description"</span>: <span class="json-string">"SQL injection vulnerability"</span>,
  <span class="json-key">"severity"</span>: <span class="json-string">"High"</span>,
  <span class="json-key">"priority"</span>: <span class="json-string">"Medium"</span>,
  <span class="json-key">"cvss_v3_score"</span>: <span class="json-number">7.5</span>,
  <span class="json-key">"published_date"</span>: <span class="json-string">"2024-02-20"</span>
}</pre>
                            </div>

                            <h4>Success Response (201 Created)</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"message"</span>: <span class="json-string">"Vulnerability created successfully"</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"cve_id"</span>: <span class="json-string">"CVE-2024-1234"</span>,
    <span class="json-key">"created_at"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>,
    <span class="json-key">"created_by"</span>: <span class="json-string">"admin"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                            </div>

                            <h4>Error Responses</h4>
                            <div class="error-examples">
                                <div class="error-example">
                                    <h5>400 Bad Request - Missing Required Fields</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"MISSING_REQUIRED_FIELDS"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Missing required fields: device_id or asset_id, component_id. Vulnerabilities must be linked to a device/asset and component."</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>
                                
                                <div class="error-example">
                                    <h5>400 Bad Request - Device Not Found</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"DEVICE_NOT_FOUND"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Device with ID 123e4567-e89b-12d3-a456-426614174000 does not exist"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>
                                
                                <div class="error-example">
                                    <h5>400 Bad Request - Asset Not Mapped</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"ASSET_NOT_MAPPED"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Asset with ID 789e0123-e89b-12d3-a456-426614174002 is not mapped to a medical device"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>
                                
                                <div class="error-example">
                                    <h5>400 Bad Request - Component Not Found</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"COMPONENT_NOT_FOUND"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Software component with ID 456e7890-e89b-12d3-a456-426614174001 does not exist"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>

                                <div class="error-example">
                                    <h5>403 Forbidden - Insufficient Permissions</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"INSUFFICIENT_PERMISSIONS"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Only administrators can create vulnerabilities"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>

                                <div class="error-example">
                                    <h5>409 Conflict - Vulnerability Exists</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"VULNERABILITY_EXISTS"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Vulnerability with CVE ID CVE-2024-1234 already exists"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2024-01-27T10:30:00+00:00"</span>
}</pre>
                                    </div>
                                </div>
                            </div>

                            <h4>Usage Examples</h4>
                            <div class="code-examples">
                                <div class="code-example">
                                    <h5>cURL</h5>
                                    <pre><code>curl -X POST https://your-server.com/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "cve_id": "CVE-2024-1234",
    "description": "Remote code execution vulnerability",
    "severity": "Critical",
    "cvss_v3_score": 9.8,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "published_date": "2024-01-15"
  }'</code></pre>
                                </div>

                                <div class="code-example">
                                    <h5>JavaScript</h5>
                                    <pre><code>const response = await fetch('/api/v1/vulnerabilities', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-api-key'
  },
  body: JSON.stringify({
    cve_id: 'CVE-2024-1234',
    description: 'Remote code execution vulnerability',
    severity: 'Critical',
    cvss_v3_score: 9.8,
    cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    published_date: '2024-01-15'
  })
});

const result = await response.json();
console.log(result);</code></pre>
                                </div>
                            </div>

                            <h4>Field Validation Rules</h4>
                            <ul class="validation-rules">
                                <li><strong>CVE ID Format:</strong> Must match pattern <code>CVE-\d{4}-\d{4,}</code></li>
                                <li><strong>Severity Values:</strong> Critical, High, Medium, Low, Info, Unknown</li>
                                <li><strong>Priority Values:</strong> Critical-KEV, High, Medium, Low, Normal</li>
                                <li><strong>CVSS Score Ranges:</strong> 0.0 - 10.0 for all CVSS versions</li>
                                <li><strong>EPSS Score Ranges:</strong> 0.0000 - 1.0000 for both score and percentile</li>
                                <li><strong>Date Formats:</strong> YYYY-MM-DD for dates, YYYY-MM-DD HH:MM:SS for timestamps</li>
                                <li><strong>Boolean Values:</strong> true, false, "true", "false", 1, 0, "1", "0"</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- Software Components Section -->
                <div class="api-section" id="components">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-cube"></i> Software Components</h3>
                    <div class="api-note">
                        <strong>Note:</strong> Software components can be created independently of SBOM imports. Components created via this API will have <code>sbom_id = NULL</code> to indicate they were added manually.
                    </div>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/components</span>
                            <span class="endpoint-description">List all software components</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> <code>components:read</code> scope required</p>
                            <p><strong>Content-Type:</strong> application/json</p>
                            
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">limit</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Maximum number of results (default: 100, max: 1000)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">offset</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Number of results to skip for pagination (default: 0)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">search</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Search by component name, vendor, or version</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">independent_only</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>If <code>true</code>, returns only components created independently (not from SBOM)</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"component_id"</span>: <span class="json-string">"123e4567-e89b-12d3-a456-426614174000"</span>,
      <span class="json-key">"sbom_id"</span>: <span class="json-null">null</span>,
      <span class="json-key">"name"</span>: <span class="json-string">"OpenSSL"</span>,
      <span class="json-key">"version"</span>: <span class="json-string">"3.0.0"</span>,
      <span class="json-key">"vendor"</span>: <span class="json-string">"OpenSSL"</span>,
      <span class="json-key">"license"</span>: <span class="json-string">"Apache-2.0"</span>,
      <span class="json-key">"purl"</span>: <span class="json-string">"pkg:generic/openssl@3.0.0"</span>,
      <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"</span>,
      <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>,
      <span class="json-key">"package_id"</span>: <span class="json-null">null</span>,
      <span class="json-key">"version_id"</span>: <span class="json-null">null</span>
    }
  ],
  <span class="json-key">"pagination"</span>: {
    <span class="json-key">"total"</span>: <span class="json-number">150</span>,
    <span class="json-key">"limit"</span>: <span class="json-number">100</span>,
    <span class="json-key">"offset"</span>: <span class="json-number">0</span>,
    <span class="json-key">"has_more"</span>: <span class="json-boolean">true</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/components/{component_id}</span>
                            <span class="endpoint-description">Get specific software component</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> <code>components:read</code> scope required</p>
                            
                            <h4>Path Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">component_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Software component UUID</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"component_id"</span>: <span class="json-string">"123e4567-e89b-12d3-a456-426614174000"</span>,
    <span class="json-key">"sbom_id"</span>: <span class="json-null">null</span>,
    <span class="json-key">"name"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"version"</span>: <span class="json-string">"3.0.0"</span>,
    <span class="json-key">"vendor"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"license"</span>: <span class="json-string">"Apache-2.0"</span>,
    <span class="json-key">"purl"</span>: <span class="json-string">"pkg:generic/openssl@3.0.0"</span>,
    <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"</span>,
    <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>,
    <span class="json-key">"package_id"</span>: <span class="json-null">null</span>,
    <span class="json-key">"version_id"</span>: <span class="json-null">null</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/components</span>
                            <span class="endpoint-description">Create new software component</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> <code>components:write</code> scope required</p>
                            <p><strong>Content-Type:</strong> application/json</p>
                            
                            <div class="alert alert-info" style="background-color: rgba(0, 153, 153, 0.1); border-left: 4px solid var(--siemens-petrol); padding: 1rem; margin-bottom: 1.5rem; border-radius: 0.375rem;">
                                <strong><i class="fas fa-info-circle"></i> Important:</strong> Components created via this API are independent of SBOM imports and will have <code>sbom_id = NULL</code>. This allows you to add software components discovered through other means (manual inventory, network scanning, etc.).
                            </div>
                            
                            <h4>Request Body</h4>
                            <table class="param-table">
                                <thead>
                                    <tr>
                                        <th>Field</th>
                                        <th>Type</th>
                                        <th>Required</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="param-name">name</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Component name (e.g., "OpenSSL", "Apache HTTP Server")</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">version</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Component version (e.g., "3.0.0", "2.4.41")</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">vendor</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Vendor or publisher name (e.g., "OpenSSL", "Apache Software Foundation")</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">license</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>License identifier (e.g., "Apache-2.0", "MIT", "GPL-2.0")</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">purl</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Package URL (PURL) format identifier</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cpe</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Common Platform Enumeration (CPE) identifier</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Request</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"name"</span>: <span class="json-string">"OpenSSL"</span>,
  <span class="json-key">"version"</span>: <span class="json-string">"3.0.0"</span>,
  <span class="json-key">"vendor"</span>: <span class="json-string">"OpenSSL"</span>,
  <span class="json-key">"license"</span>: <span class="json-string">"Apache-2.0"</span>,
  <span class="json-key">"purl"</span>: <span class="json-string">"pkg:generic/openssl@3.0.0"</span>,
  <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"</span>
}</pre>
                            </div>
                            
                            <h4>Success Response (201 Created)</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"message"</span>: <span class="json-string">"Software component created successfully"</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"component_id"</span>: <span class="json-string">"123e4567-e89b-12d3-a456-426614174000"</span>,
    <span class="json-key">"sbom_id"</span>: <span class="json-null">null</span>,
    <span class="json-key">"name"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"version"</span>: <span class="json-string">"3.0.0"</span>,
    <span class="json-key">"vendor"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"license"</span>: <span class="json-string">"Apache-2.0"</span>,
    <span class="json-key">"purl"</span>: <span class="json-string">"pkg:generic/openssl@3.0.0"</span>,
    <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"</span>,
    <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                            
                            <h4>Error Responses</h4>
                            <div class="error-examples">
                                <div class="error-example">
                                    <h5>400 Bad Request - Missing Required Field</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"MISSING_REQUIRED_FIELD"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Field \"name\" is required"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                                    </div>
                                </div>
                                
                                <div class="error-example">
                                    <h5>403 Forbidden - Insufficient Permissions</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"FORBIDDEN"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Permission required: components:write"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method put">PUT</span>
                            <span class="endpoint-url">/api/v1/components/{component_id}</span>
                            <span class="endpoint-description">Update existing software component</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> <code>components:write</code> scope required</p>
                            <p><strong>Content-Type:</strong> application/json</p>
                            
                            <h4>Path Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">component_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Software component UUID</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Request Body</h4>
                            <p>All fields are optional. Only include fields you want to update.</p>
                            <table class="param-table">
                                <thead>
                                    <tr>
                                        <th>Field</th>
                                        <th>Type</th>
                                        <th>Required</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="param-name">name</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Component name</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">version</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Component version</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">vendor</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Vendor or publisher name</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">license</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>License identifier</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">purl</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Package URL (PURL)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">cpe</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Common Platform Enumeration (CPE)</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Request</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"version"</span>: <span class="json-string">"3.0.1"</span>,
  <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"</span>
}</pre>
                            </div>
                            
                            <h4>Success Response (200 OK)</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"message"</span>: <span class="json-string">"Software component updated successfully"</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"component_id"</span>: <span class="json-string">"123e4567-e89b-12d3-a456-426614174000"</span>,
    <span class="json-key">"name"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"version"</span>: <span class="json-string">"3.0.1"</span>,
    <span class="json-key">"vendor"</span>: <span class="json-string">"OpenSSL"</span>,
    <span class="json-key">"cpe"</span>: <span class="json-string">"cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method delete">DELETE</span>
                            <span class="endpoint-url">/api/v1/components/{component_id}</span>
                            <span class="endpoint-description">Delete software component</span>
                        </div>
                        <div class="endpoint-body">
                            <p><strong>Authentication:</strong> Required (API Key or Session)</p>
                            <p><strong>Permissions:</strong> <code>components:delete</code> scope required</p>
                            
                            <h4>Path Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">component_id</span></td>
                                        <td><span class="param-type">string (UUID)</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Software component UUID</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <div class="alert alert-warning" style="background-color: rgba(245, 158, 11, 0.1); border-left: 4px solid #f59e0b; padding: 1rem; margin-bottom: 1.5rem; border-radius: 0.375rem;">
                                <strong><i class="fas fa-exclamation-triangle"></i> Warning:</strong> Components that are linked to vulnerabilities cannot be deleted. You must first remove all vulnerability links before deleting the component.
                            </div>
                            
                            <h4>Success Response (200 OK)</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"message"</span>: <span class="json-string">"Software component deleted successfully"</span>,
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                            </div>
                            
                            <h4>Error Responses</h4>
                            <div class="error-examples">
                                <div class="error-example">
                                    <h5>404 Not Found</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"COMPONENT_NOT_FOUND"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Software component not found"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                                    </div>
                                </div>
                                
                                <div class="error-example">
                                    <h5>409 Conflict - Component In Use</h5>
                                    <div class="json-example">
                                        <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">false</span>,
  <span class="json-key">"error"</span>: {
    <span class="json-key">"code"</span>: <span class="json-string">"COMPONENT_IN_USE"</span>,
    <span class="json-key">"message"</span>: <span class="json-string">"Cannot delete component: it is linked to 5 vulnerability(ies)"</span>
  },
  <span class="json-key">"timestamp"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>
}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <h4>Usage Examples</h4>
                    <div class="code-examples">
                        <div class="code-example">
                            <h5>cURL - Create Component</h5>
                            <pre><code>curl -X POST https://your-server.com/api/v1/components \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dave_your_api_key_here" \
  -d '{
    "name": "OpenSSL",
    "version": "3.0.0",
    "vendor": "OpenSSL",
    "license": "Apache-2.0",
    "cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
  }'</code></pre>
                        </div>

                        <div class="code-example">
                            <h5>JavaScript - Create Component</h5>
                            <pre><code>const response = await fetch('/api/v1/components', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer dave_your_api_key_here'
  },
  body: JSON.stringify({
    name: 'OpenSSL',
    version: '3.0.0',
    vendor: 'OpenSSL',
    license: 'Apache-2.0',
    cpe: 'cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*'
  })
});

const result = await response.json();
console.log(result);</code></pre>
                        </div>
                    </div>
                </div>

                <!-- Recalls Section -->
                <div class="api-section" id="recalls">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-exclamation-triangle"></i> Recalls</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/recalls</span>
                            <span class="endpoint-description">List recalls</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">status</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by recall status</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">manufacturer</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by manufacturer</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"recall_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"recall_number"</span>: <span class="json-string">"Z-1234-2024"</span>,
      <span class="json-key">"product_name"</span>: <span class="json-string">"Medical Device X"</span>,
      <span class="json-key">"manufacturer"</span>: <span class="json-string">"MedCorp Inc"</span>,
      <span class="json-key">"recall_date"</span>: <span class="json-string">"2024-01-15"</span>,
      <span class="json-key">"recall_status"</span>: <span class="json-string">"Active"</span>,
      <span class="json-key">"reason"</span>: <span class="json-string">"Software vulnerability"</span>,
      <span class="json-key">"affected_devices_count"</span>: <span class="json-number">5</span>
    }
  ]
}</pre>
                            </div>
                            </div>
                        </div>
                    </div>

                <!-- Patches Section -->
                <div class="api-section" id="patches">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                        </div>
                    <h3><i class="fas fa-band-aid"></i> Patches</h3>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/patches</span>
                            <span class="endpoint-description">List patches</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">active_only</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Show only active patches</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">package_id</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by software package</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"patch_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"patch_name"</span>: <span class="json-string">"Security Update 2024.1"</span>,
      <span class="json-key">"patch_type"</span>: <span class="json-string">"Security"</span>,
      <span class="json-key">"target_package_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"target_version"</span>: <span class="json-string">"2.1.0"</span>,
      <span class="json-key">"cve_count"</span>: <span class="json-number">15</span>,
      <span class="json-key">"release_date"</span>: <span class="json-string">"2024-01-15T00:00:00Z"</span>,
      <span class="json-key">"is_active"</span>: <span class="json-boolean">true</span>
    }
  ]
}</pre>
                            </div>
                            </div>
                            </div>
                            
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/patches</span>
                            <span class="endpoint-description">Create patch</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Create a new patch for vulnerability remediation.</p>
                        </div>
                            </div>
                            
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/patches/bulk-apply</span>
                            <span class="endpoint-description">Bulk apply patches</span>
                            </div>
                        <div class="endpoint-body">
                            <p>Apply multiple patches to selected assets.</p>
                        </div>
                    </div>
                </div>

                <!-- Users Section -->
                <div class="api-section" id="users">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-users"></i> User Management</h3>
                    <div class="api-note">
                        <strong>Note:</strong> User management endpoints are only accessible to Admin users.
                    </div>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/users</span>
                            <span class="endpoint-description">List users</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"user_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"username"</span>: <span class="json-string">"admin"</span>,
      <span class="json-key">"email"</span>: <span class="json-string">"admin@dave.local"</span>,
      <span class="json-key">"role"</span>: <span class="json-string">"Admin"</span>,
      <span class="json-key">"is_active"</span>: <span class="json-boolean">true</span>,
      <span class="json-key">"last_login"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>,
      <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-01T00:00:00Z"</span>
    }
  ]
}</pre>
                        </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/users</span>
                            <span class="endpoint-description">Create user</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Request Body</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">username</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Username</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">email</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Email address</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">password</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Password</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">role</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>User role (Admin, Clinical Engineer, IT Security Analyst, Read-Only)</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            </div>
                        </div>

                <!-- Locations Section -->
                <div class="api-section" id="locations">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-map-marker-alt"></i> Locations</h3>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/locations</span>
                            <span class="endpoint-description">List locations</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"location_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"location_name"</span>: <span class="json-string">"ICU Ward 1"</span>,
      <span class="json-key">"location_type"</span>: <span class="json-string">"Clinical"</span>,
      <span class="json-key">"criticality"</span>: <span class="json-number">9</span>,
      <span class="json-key">"floor"</span>: <span class="json-number">3</span>,
      <span class="json-key">"room_number"</span>: <span class="json-string">"301"</span>,
      <span class="json-key">"asset_count"</span>: <span class="json-number">15</span>,
      <span class="json-key">"created_at"</span>: <span class="json-string">"2025-01-01T00:00:00Z"</span>
    }
  ]
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/locations/assign-assets</span>
                            <span class="endpoint-description">Auto-assign assets to locations</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Automatically assign assets to locations based on IP address ranges.</p>
                        </div>
                            </div>
                            
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/locations/simple</span>
                            <span class="endpoint-description">Get simplified location list</span>
                            </div>
                        <div class="endpoint-body">
                            <p>Returns a simplified list of locations for dropdowns and forms.</p>
                        </div>
                    </div>
                </div>

                <!-- Device Mapping Section -->
                <div class="api-section" id="devices">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-map"></i> Device Mapping</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/devices/map</span>
                            <span class="endpoint-description">Map device to asset</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Link a medical device to an asset for vulnerability tracking.</p>
                        </div>
                    </div>
                            </div>
                            
                <!-- Risk Priorities Section -->
                <div class="api-section" id="risk-priorities">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                            </div>
                    <h3><i class="fas fa-exclamation-circle"></i> Risk Priorities</h3>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/risk-priorities</span>
                            <span class="endpoint-description">List risk priorities</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">tier</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by priority tier (1, 2, 3)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">kev_only</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Show only KEV vulnerabilities</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"link_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"cve_id"</span>: <span class="json-string">"CVE-2024-1234"</span>,
      <span class="json-key">"hostname"</span>: <span class="json-string">"server-01"</span>,
      <span class="json-key">"device_name"</span>: <span class="json-string">"Medical Device X"</span>,
      <span class="json-key">"severity"</span>: <span class="json-string">"Critical"</span>,
      <span class="json-key">"asset_criticality"</span>: <span class="json-string">"Clinical-High"</span>,
      <span class="json-key">"location_criticality"</span>: <span class="json-number">9</span>,
      <span class="json-key">"is_kev"</span>: <span class="json-boolean">true</span>,
      <span class="json-key">"calculated_risk_score"</span>: <span class="json-number">95.5</span>,
      <span class="json-key">"priority_tier"</span>: <span class="json-number">1</span>
    }
  ]
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/risk-priorities/stats</span>
                            <span class="endpoint-description">Get risk priority statistics</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns summary statistics for risk priorities by tier.</p>
                        </div>
                            </div>
                            
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/risk-priorities/refresh</span>
                            <span class="endpoint-description">Refresh risk priorities</span>
                            </div>
                        <div class="endpoint-body">
                            <p>Manually trigger recalculation of risk priorities (Admin only).</p>
                        </div>
                    </div>
                </div>

                <!-- Software Packages Section -->
                <div class="api-section" id="software-packages">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-cube"></i> Software Packages</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/software-packages/risk-priorities.php</span>
                            <span class="endpoint-description">List software packages with risk priorities</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">tier</span></td>
                                        <td><span class="param-type">integer</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by tier (1, 2, 3)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">kev_only</span></td>
                                        <td><span class="param-type">boolean</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Show only packages with KEV vulnerabilities</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">search</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Search by package name</td>
                                        </tr>
                                    </tbody>
                                </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: [
    {
      <span class="json-key">"package_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"package_name"</span>: <span class="json-string">"Apache HTTP Server"</span>,
      <span class="json-key">"vendor"</span>: <span class="json-string">"Apache Software Foundation"</span>,
      <span class="json-key">"version"</span>: <span class="json-string">"2.4.41"</span>,
      <span class="json-key">"total_vulnerabilities"</span>: <span class="json-number">25</span>,
      <span class="json-key">"kev_count"</span>: <span class="json-number">3</span>,
      <span class="json-key">"critical_severity_count"</span>: <span class="json-number">8</span>,
      <span class="json-key">"affected_assets_count"</span>: <span class="json-number">12</span>,
      <span class="json-key">"aggregate_risk_score"</span>: <span class="json-number">87.5</span>
    }
  ]
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/software-packages/risk-priorities.php/{package_id}/affected-assets</span>
                            <span class="endpoint-description">Get affected assets for a package</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns all assets affected by vulnerabilities in a specific software package.</p>
                        </div>
                            </div>
                            
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/software-packages/risk-priorities.php/{package_id}/vulnerabilities</span>
                            <span class="endpoint-description">Get vulnerabilities for a package</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns all vulnerabilities affecting a specific software package.</p>
                            </div>
                        </div>
                    </div>

                <!-- Analytics Section -->
                <div class="api-section" id="analytics">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-chart-line"></i> Analytics</h3>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/analytics/dashboard</span>
                            <span class="endpoint-description">Get dashboard analytics</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Query Parameters</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">date_from</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Start date (YYYY-MM-DD)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">date_to</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>End date (YYYY-MM-DD)</td>
                                    </tr>
                                    <tr>
                                        <td><span class="param-name">department</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Filter by department</td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"summary"</span>: {
      <span class="json-key">"assets"</span>: {
        <span class="json-key">"total_assets"</span>: <span class="json-number">150</span>,
        <span class="json-key">"mapped_assets"</span>: <span class="json-number">120</span>,
        <span class="json-key">"critical_assets"</span>: <span class="json-number">45</span>,
        <span class="json-key">"active_assets"</span>: <span class="json-number">145</span>
      },
      <span class="json-key">"vulnerabilities"</span>: {
        <span class="json-key">"total_vulnerabilities"</span>: <span class="json-number">250</span>,
        <span class="json-key">"critical_vulns"</span>: <span class="json-number">15</span>,
        <span class="json-key">"high_vulns"</span>: <span class="json-number">45</span>,
        <span class="json-key">"open_vulns"</span>: <span class="json-number">180</span>
      },
      <span class="json-key">"recalls"</span>: {
        <span class="json-key">"total_recalls"</span>: <span class="json-number">8</span>,
        <span class="json-key">"active_recalls"</span>: <span class="json-number">3</span>,
        <span class="json-key">"affected_devices"</span>: <span class="json-number">25</span>
      }
    },
    <span class="json-key">"trends"</span>: {
      <span class="json-key">"assets_added"</span>: [
        {
          <span class="json-key">"date"</span>: <span class="json-string">"2025-01-01"</span>,
          <span class="json-key">"assets_added"</span>: <span class="json-number">5</span>
        }
      ]
    }
  }
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/analytics/dashboard?path=assets</span>
                            <span class="endpoint-description">Get asset analytics</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns detailed analytics about asset distribution and types.</p>
                        </div>
                            </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/analytics/dashboard?path=vulnerabilities</span>
                            <span class="endpoint-description">Get vulnerability analytics</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns detailed analytics about vulnerability distribution and severity.</p>
                    </div>
                </div>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/analytics/dashboard?path=recalls</span>
                            <span class="endpoint-description">Get recall analytics</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns detailed analytics about recall distribution and status.</p>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/analytics/dashboard?path=compliance</span>
                            <span class="endpoint-description">Get compliance analytics</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Returns compliance metrics and percentages.</p>
                        </div>
                            </div>
                        </div>

                <!-- Reports Section -->
                <div class="api-section" id="reports">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-file-alt"></i> Reports</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/reports/export</span>
                            <span class="endpoint-description">Generate report</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Request Body</h4>
                            <table class="param-table">
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
                                        <td><span class="param-name">report_type</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Type of report (vulnerabilities, assets, recalls)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">format</span></td>
                                        <td><span class="param-type">string</span></td>
                                        <td><span class="param-required">Required</span></td>
                                        <td>Export format (pdf, excel, csv)</td>
                                        </tr>
                                        <tr>
                                        <td><span class="param-name">filters</span></td>
                                        <td><span class="param-type">object</span></td>
                                        <td><span class="param-optional">Optional</span></td>
                                        <td>Report filters</td>
                                        </tr>
                                    </tbody>
                                </table>
                        </div>
                    </div>
                            </div>
                            
                <!-- System Section -->
                <div class="api-section" id="system">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                            </div>
                    <h3><i class="fas fa-cog"></i> System</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/system/status</span>
                            <span class="endpoint-description">Get system status</span>
                        </div>
                        <div class="endpoint-body">
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"data"</span>: {
    <span class="json-key">"system_status"</span>: <span class="json-string">"operational"</span>,
    <span class="json-key">"database_status"</span>: <span class="json-string">"connected"</span>,
    <span class="json-key">"api_version"</span>: <span class="json-string">"1.0.0"</span>,
    <span class="json-key">"uptime"</span>: <span class="json-string">"7 days, 12 hours"</span>,
    <span class="json-key">"last_backup"</span>: <span class="json-string">"2025-01-10T02:00:00Z"</span>
  }
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/system/clean-cache</span>
                            <span class="endpoint-description">Clean system cache</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Clear system cache to improve performance.</p>
                        </div>
                            </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/system/download-log</span>
                            <span class="endpoint-description">Download system logs</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Download system logs for troubleshooting.</p>
                        </div>
                    </div>
                </div>

                <!-- Admin Section -->
                <div class="api-section" id="admin">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-shield-alt"></i> Admin</h3>
                    <div class="api-note">
                        <strong>Note:</strong> Admin endpoints are only accessible to Admin users.
                    </div>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/admin/risk-matrix</span>
                            <span class="endpoint-description">Get risk matrix configuration</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Get the current risk matrix configuration used for priority calculations.</p>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method put">PUT</span>
                            <span class="endpoint-url">/api/v1/admin/risk-matrix</span>
                            <span class="endpoint-description">Update risk matrix configuration</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Update the risk matrix configuration and recalculate all priorities.</p>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/admin/risk-matrix/preview</span>
                            <span class="endpoint-description">Preview risk matrix changes</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Preview how risk matrix changes would affect current priorities.</p>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/v1/kev/sync</span>
                            <span class="endpoint-description">Sync KEV data</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Synchronize Known Exploited Vulnerabilities from CISA database.</p>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/assets/import</span>
                            <span class="endpoint-description">Import assets from scan files</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Import assets from security scan files (nmap, Nessus, CSV) to automatically create or update assets in the system.</p>
                            
                            <div class="param-section">
                                <h4>Request Parameters</h4>
                                <table class="param-table">
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
                                            <td><span class="param-name">scan_file</span></td>
                                            <td><span class="param-type">file</span></td>
                                            <td><span class="param-required">Yes</span></td>
                                            <td>The uploaded scan file (nmap XML, Nessus XML, or CSV)</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">file_type</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-required">Yes</span></td>
                                            <td>Type of scan file: "nmap", "nessus", or "csv"</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">import_options</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>JSON string with import configuration options</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div class="param-section">
                                <h4>Supported File Types</h4>
                                <ul>
                                    <li><strong>Nmap XML:</strong> Standard nmap XML output files - automatically detects open ports and determines asset type</li>
                                    <li><strong>Nessus XML:</strong> Tenable Nessus scan results - parses vulnerability data to determine asset criticality</li>
                                    <li><strong>CSV:</strong> Custom CSV files with asset data - flexible column mapping for various asset attributes</li>
                                </ul>
                            </div>

                            <div class="param-section">
                                <h4>Example Request</h4>
                                <div class="json-example">
                                    <pre><code>curl -X POST https://your-dave-instance.com/api/v1/assets/import \
  -H "X-API-Key: your-api-key" \
  -F "scan_file=@network_scan.xml" \
  -F "file_type=nmap" \
  -F 'import_options={"default_criticality":{"Medical Device":"Clinical-High"}}'</code></pre>
                                </div>
                            </div>

                            <div class="param-section">
                                <h4>Success Response</h4>
                                <div class="json-example">
                                    <pre><code>{
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
}</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Device SBOM Section -->
                <div class="api-section" id="device-sbom">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-file-code"></i> Device SBOM Management</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method post">POST</span>
                            <span class="endpoint-url">/api/v1/devices/sbom</span>
                            <span class="endpoint-description">Upload SBOM for medical device</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Upload Software Bill of Materials (SBOM) files for specific medical devices to track software components and vulnerabilities.</p>
                            
                            <div class="param-section">
                                <h4>Request Parameters</h4>
                                <table class="param-table">
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
                                            <td><span class="param-name">sbom_file</span></td>
                                            <td><span class="param-type">file</span></td>
                                            <td><span class="param-required">Yes</span></td>
                                            <td>The uploaded SBOM file (JSON, XML, SPDX, CycloneDX)</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">device_id</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-required">Yes</span></td>
                                            <td>UUID of the medical device</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">format</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>SBOM format: "SPDX", "CycloneDX", "spdx-tag-value", "JSON", or "XML" (defaults to "SPDX")</td>
                                        </tr>
                                        <tr>
                                            <td><span class="param-name">description</span></td>
                                            <td><span class="param-type">string</span></td>
                                            <td><span class="param-optional">No</span></td>
                                            <td>Description of the SBOM</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div class="param-section">
                                <h4>Supported SBOM Formats</h4>
                                <ul>
                                    <li><strong>SPDX:</strong> Software Package Data Exchange format - standard format for software package information</li>
                                    <li><strong>CycloneDX:</strong> Lightweight SBOM format focused on security and vulnerability management</li>
                                    <li><strong>spdx-tag-value:</strong> SPDX in human-readable tag-value format</li>
                                    <li><strong>JSON:</strong> Generic JSON format with flexible component definitions</li>
                                    <li><strong>XML:</strong> XML-based SBOM format with structured representation</li>
                                </ul>
                            </div>

                            <div class="param-section">
                                <h4>Example Request</h4>
                                <div class="json-example">
                                    <pre><code>curl -X POST https://your-dave-instance.com/api/v1/devices/sbom \
  -H "X-API-Key: your-api-key" \
  -F "sbom_file=@device-sbom.spdx.json" \
  -F "device_id=123e4567-e89b-12d3-a456-426614174000" \
  -F "format=SPDX" \
  -F "description=Medical device firmware SBOM"</code></pre>
                                </div>
                            </div>

                            <div class="param-section">
                                <h4>Success Response</h4>
                                <div class="json-example">
                                    <pre><code>{
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
}</code></pre>
                                </div>
                            </div>

                            <div class="param-section">
                                <h4>SBOM Processing Features</h4>
                                <ul>
                                    <li><strong>Component Extraction:</strong> Automatically extracts software components from SBOM files</li>
                                    <li><strong>Vulnerability Evaluation:</strong> Queues SBOM for background vulnerability analysis</li>
                                    <li><strong>Format Support:</strong> Handles multiple SBOM formats (SPDX, CycloneDX, JSON, XML)</li>
                                    <li><strong>Background Processing:</strong> Automatically queues SBOMs for vulnerability evaluation</li>
                                    <li><strong>Component Tracking:</strong> Links components to known vulnerabilities in the database</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sessions Section -->
                <div class="api-section" id="sessions">
                    <div class="back-to-nav">
                        <a href="#api-overview" class="back-to-nav-link">
                            <i class="fas fa-arrow-up"></i> Back to Overview
                        </a>
                    </div>
                    <h3><i class="fas fa-user-clock"></i> Sessions</h3>
                    
                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method get">GET</span>
                            <span class="endpoint-url">/api/sessions</span>
                            <span class="endpoint-description">Get user sessions</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Get all active sessions for the current user.</p>
                            
                            <h4>Example Response</h4>
                            <div class="json-example">
                                <pre>{
  <span class="json-key">"success"</span>: <span class="json-boolean">true</span>,
  <span class="json-key">"sessions"</span>: [
    {
      <span class="json-key">"session_id"</span>: <span class="json-string">"session123"</span>,
      <span class="json-key">"user_id"</span>: <span class="json-string">"uuid"</span>,
      <span class="json-key">"ip_address"</span>: <span class="json-string">"192.168.1.100"</span>,
      <span class="json-key">"location"</span>: <span class="json-string">"Local Network"</span>,
      <span class="json-key">"device_type"</span>: <span class="json-string">"desktop"</span>,
      <span class="json-key">"device_name"</span>: <span class="json-string">"Windows PC"</span>,
      <span class="json-key">"browser"</span>: <span class="json-string">"Chrome"</span>,
      <span class="json-key">"login_time"</span>: <span class="json-string">"2025-01-10T10:30:00Z"</span>,
      <span class="json-key">"last_activity"</span>: <span class="json-string">"2025-01-10T11:45:00Z"</span>,
      <span class="json-key">"is_current"</span>: <span class="json-boolean">true</span>
    }
  ],
  <span class="json-key">"total"</span>: <span class="json-number">3</span>
}</pre>
                            </div>
                        </div>
                    </div>

                    <div class="endpoint-card">
                        <div class="endpoint-header">
                            <span class="method delete">DELETE</span>
                            <span class="endpoint-url">/api/v1/security/sessions/{session_id}</span>
                            <span class="endpoint-description">Terminate session</span>
                        </div>
                        <div class="endpoint-body">
                            <p>Terminate a specific user session.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        // Search functionality
        document.getElementById('apiSearch').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const endpointCards = document.querySelectorAll('.endpoint-card');
            const sections = document.querySelectorAll('.api-section');
            let hasResults = false;

            endpointCards.forEach(card => {
                const header = card.querySelector('.endpoint-header');
                const url = header.querySelector('.endpoint-url').textContent.toLowerCase();
                const description = header.querySelector('.endpoint-description').textContent.toLowerCase();
                
                if (url.includes(searchTerm) || description.includes(searchTerm)) {
                    card.classList.remove('hidden');
                    hasResults = true;
                } else {
                    card.classList.add('hidden');
                }
            });

            // Show/hide sections based on visible cards
            sections.forEach(section => {
                const visibleCards = section.querySelectorAll('.endpoint-card:not(.hidden)');
                if (visibleCards.length > 0 || searchTerm === '') {
                    section.style.display = 'block';
                } else {
                    section.style.display = 'none';
                }
            });

            // Show no results message
            const noResults = document.getElementById('noResults');
            if (noResults) {
                noResults.remove();
            }

            if (!hasResults && searchTerm !== '') {
                const content = document.querySelector('.api-content');
                const noResultsDiv = document.createElement('div');
                noResultsDiv.id = 'noResults';
                noResultsDiv.className = 'no-results';
                noResultsDiv.innerHTML = '<i class="fas fa-search"></i><p>No endpoints found matching your search.</p>';
                content.appendChild(noResultsDiv);
            }
        });

        // Navigation highlighting
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                    
                    // Update active nav link
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                }
            });
        });

        // Highlight current section in navigation
        window.addEventListener('scroll', function() {
            const sections = document.querySelectorAll('.api-section');
            const navLinks = document.querySelectorAll('.nav-link');
            
            let current = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 100;
                if (window.pageYOffset >= sectionTop) {
                    current = section.getAttribute('id');
                }
            });

            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {
                    link.classList.add('active');
                }
            });
        });
    </script>

</body>
</html>
