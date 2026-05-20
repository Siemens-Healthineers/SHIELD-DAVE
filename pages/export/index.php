<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

$auth->requireAuth();
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Export field metadata 
// 'type': text | number | date | boolean | select
// 'label': human-readable label

$entityFields = [
    'asset' => [
        'table'  => 'assets',
        'label'  => 'Asset',
        'fields' => [
            ['key' => 'hostname',                      'label' => 'Hostname',                       'type' => 'text'],
            ['key' => 'ip_address',                    'label' => 'IP Address',                     'type' => 'text'],
            ['key' => 'mac_address',                   'label' => 'MAC Address',                    'type' => 'text'],
            ['key' => 'source',                        'label' => 'Source',                         'type' => 'text'],
            ['key' => 'asset_tag',                     'label' => 'Asset Tag',                      'type' => 'text'],
            ['key' => 'asset_type',                    'label' => 'Asset Type',                     'type' => 'select',
             'options' => ['Server','Laptop','Switch','Software','Cloud Resource','IoT Gateway','IoMT Sensor','Smart Device','Medical Device']],
            ['key' => 'asset_subtype',                 'label' => 'Asset Subtype',                  'type' => 'text'],
            ['key' => 'manufacturer',                  'label' => 'Manufacturer',                   'type' => 'text'],
            ['key' => 'model',                         'label' => 'Model',                          'type' => 'text'],
            ['key' => 'serial_number',                 'label' => 'Serial Number',                  'type' => 'text'],
            ['key' => 'location',                      'label' => 'Location',                       'type' => 'text'],
            ['key' => 'firmware_version',              'label' => 'Firmware Version',               'type' => 'text'],
            ['key' => 'cpu',                           'label' => 'CPU',                            'type' => 'text'],
            ['key' => 'memory_ram',                    'label' => 'Memory / RAM',                   'type' => 'text'],
            ['key' => 'storage',                       'label' => 'Storage',                        'type' => 'text'],
            ['key' => 'primary_communication_protocol','label' => 'Primary Communication Protocol', 'type' => 'select',
             'options' => ['Wi-Fi','Ethernet','Bluetooth/BLE','Zigbee','LoRaWAN','Cellular (4G/5G)']],
            ['key' => 'assigned_admin_user',           'label' => 'Assigned Admin User',            'type' => 'text'],
            ['key' => 'business_unit',                 'label' => 'Business Unit',                  'type' => 'text'],
            ['key' => 'department',                    'label' => 'Department',                     'type' => 'text'],
            ['key' => 'cost_center',                   'label' => 'Cost Center',                    'type' => 'text'],
            ['key' => 'criticality',                   'label' => 'Criticality',                    'type' => 'select',
             'options' => ['Clinical-High','Business-Medium','Non-Essential']],
            ['key' => 'regulatory_classification',     'label' => 'Regulatory Classification',      'type' => 'text'],
            ['key' => 'phi_status',                    'label' => 'PHI Status',                     'type' => 'select',
             'options' => ['true','false']],
            ['key' => 'data_encryption_transit',       'label' => 'Data Encryption (Transit)',      'type' => 'text'],
            ['key' => 'data_encryption_rest',          'label' => 'Data Encryption (Rest)',         'type' => 'text'],
            ['key' => 'authentication_method',         'label' => 'Authentication Method',          'type' => 'text'],
            ['key' => 'status',                        'label' => 'Status',                         'type' => 'select',
             'options' => ['Active','Inactive','Retired','Disposed']],
            ['key' => 'warranty_expiration_date',      'label' => 'Warranty Expiration Date',       'type' => 'date'],
            ['key' => 'scheduled_replacement_date',    'label' => 'Scheduled Replacement Date',     'type' => 'date'],
            ['key' => 'disposal_date',                 'label' => 'Disposal Date',                  'type' => 'date'],
            ['key' => 'patch_level_last_update',       'label' => 'Patch Level Last Update',        'type' => 'date'],
            ['key' => 'last_audit_date',               'label' => 'Last Audit Date',                'type' => 'date'],
            ['key' => 'first_seen',                    'label' => 'First Seen',                     'type' => 'date'],
            ['key' => 'last_seen',                     'label' => 'Last Seen',                      'type' => 'date'],
            ['key' => 'created_at',                    'label' => 'Created At',                     'type' => 'date'],
            ['key' => 'updated_at',                    'label' => 'Updated At',                     'type' => 'date'],
        ],
    ],
    'vulnerability' => [
        'table'  => 'vulnerabilities',
        'label'  => 'Vulnerability',
        'fields' => [
            ['key' => 'cve_id',             'label' => 'CVE ID',                  'type' => 'text'],
            ['key' => 'description',        'label' => 'Description',             'type' => 'text'],
            ['key' => 'severity',           'label' => 'Severity',                'type' => 'select',
             'options' => ['Critical','High','Medium','Low','Info','Unknown']],
            ['key' => 'cvss_v4_score',      'label' => 'CVSS v4 Score',           'type' => 'number'],
            ['key' => 'cvss_v3_score',      'label' => 'CVSS v3 Score',           'type' => 'number'],
            ['key' => 'cvss_v2_score',      'label' => 'CVSS v2 Score',           'type' => 'number'],
            ['key' => 'cvss_v3_vector',     'label' => 'CVSS v3 Vector',          'type' => 'text'],
            ['key' => 'cvss_v4_vector',     'label' => 'CVSS v4 Vector',          'type' => 'text'],
            ['key' => 'priority',           'label' => 'Priority',                'type' => 'select',
             'options' => ['Critical-KEV','High','Medium','Low','Normal']],
            ['key' => 'is_kev',             'label' => 'Is KEV',                  'type' => 'select',
             'options' => ['true','false']],
            ['key' => 'epss_score',         'label' => 'EPSS Score',              'type' => 'number'],
            ['key' => 'epss_percentile',    'label' => 'EPSS Percentile',         'type' => 'number'],
            ['key' => 'epss_date',          'label' => 'EPSS Date',               'type' => 'date'],
            ['key' => 'published_date',     'label' => 'Published Date',          'type' => 'date'],
            ['key' => 'last_modified_date', 'label' => 'Last Modified Date',      'type' => 'date'],
            ['key' => 'kev_date_added',     'label' => 'KEV Date Added',          'type' => 'date'],
            ['key' => 'kev_due_date',       'label' => 'KEV Due Date',            'type' => 'date'],
            ['key' => 'kev_required_action','label' => 'KEV Required Action',     'type' => 'text'],
            ['key' => 'created_at',         'label' => 'Created At',              'type' => 'date'],
            ['key' => 'updated_at',         'label' => 'Updated At',              'type' => 'date'],
        ],
    ],
    'patch' => [
        'table'  => 'patches',
        'label'  => 'Patch',
        'fields' => [
            ['key' => 'patch_name',              'label' => 'Patch Name',               'type' => 'text'],
            ['key' => 'patch_type',              'label' => 'Patch Type',               'type' => 'select',
             'options' => ['Source','Binary','Firmware','Emulator','Documentation','Configuration','Security Patch']],
            ['key' => 'target_device_type',      'label' => 'Target Device Type',       'type' => 'text'],
            ['key' => 'target_version',          'label' => 'Target Version',           'type' => 'text'],
            ['key' => 'description',             'label' => 'Description',              'type' => 'text'],
            ['key' => 'release_date',            'label' => 'Release Date',             'type' => 'date'],
            ['key' => 'vendor',                  'label' => 'Vendor',                   'type' => 'text'],
            ['key' => 'kb_article',              'label' => 'KB Article',               'type' => 'text'],
            ['key' => 'requires_reboot',         'label' => 'Requires Reboot',          'type' => 'select',
             'options' => ['true','false']],
            ['key' => 'is_active',               'label' => 'Is Active',                'type' => 'select',
             'options' => ['true','false']],
            ['key' => 'estimated_install_time',  'label' => 'Estimated Install Time (min)', 'type' => 'number'],
            ['key' => 'estimated_downtime',      'label' => 'Estimated Downtime (min)', 'type' => 'number'],
            ['key' => 'created_at',              'label' => 'Created At',               'type' => 'date'],
            ['key' => 'updated_at',              'label' => 'Updated At',               'type' => 'date'],
        ],
    ],
    'remediation' => [
        'table'  => 'remediation_actions',
        'label'  => 'Remediation',
        'fields' => [
            ['key' => 'action_type',        'label' => 'Action Type',        'type' => 'select',
             'options' => ['Patch','Upgrade','Configuration','Disable','Mitigation']],
            ['key' => 'action_description', 'label' => 'Action Description', 'type' => 'text'],
            ['key' => 'target_version',     'label' => 'Target Version',     'type' => 'text'],
            ['key' => 'patch_reference',    'label' => 'Patch Reference',    'type' => 'text'],
            ['key' => 'vendor',             'label' => 'Vendor',             'type' => 'text'],
            ['key' => 'status',             'label' => 'Status',             'type' => 'select',
             'options' => ['Pending','In Progress','Completed','Cancelled']],
            ['key' => 'cve_id',             'label' => 'CVE ID',             'type' => 'text'],
            ['key' => 'due_date',           'label' => 'Due Date',           'type' => 'date'],
            ['key' => 'completed_at',       'label' => 'Completed At',       'type' => 'date'],
            ['key' => 'notes',              'label' => 'Notes',              'type' => 'text'],
            ['key' => 'created_at',         'label' => 'Created At',         'type' => 'date'],
            ['key' => 'updated_at',         'label' => 'Updated At',         'type' => 'date'],
        ],
    ],
];

// Encode for JavaScript injection
$entityFieldsJson = json_encode($entityFields, JSON_PRETTY_PRINT);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Export Data - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Two-column main grid */
        .export-main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            align-items: start;
        }
        @media (max-width: 1100px) { .export-main-grid { grid-template-columns: 1fr; } }

        /* Cards */
        .export-card {
            background: var(--card-bg, #1e293b);
            border-radius: 10px;
            padding: 1.5rem;
        }
        .export-card-header {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            margin-bottom: 0.25rem;
        }
        .export-card-header h2 {
            margin: 0;
            font-size: 1.05rem;
            color: var(--text-primary, #fff);
            display: flex;
            align-items: center;
            gap: 0.45rem;
        }
        .export-card .card-desc {
            font-size: 0.82rem;
            color: var(--text-secondary, #94a3b8);
            margin: 0 0 1.1rem;
        }
        .entity-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .badge-asset        { background: rgba(0,153,153,.15);  color: #5eead4; border: 1px solid rgba(0,153,153,.35); }
        .badge-vulnerability{ background: rgba(239,68,68,.12);  color: #f87171; border: 1px solid rgba(239,68,68,.3); }
        .badge-patch        { background: rgba(59,130,246,.12); color: #93c5fd; border: 1px solid rgba(59,130,246,.3); }
        .badge-remediation  { background: rgba(139,92,246,.12); color: #c4b5fd; border: 1px solid rgba(139,92,246,.3); }
        .badge-required     { background: rgba(251,191,36,.12); color: #fcd34d; border: 1px solid rgba(251,191,36,.3); font-size: 0.65rem; }

        /* Right column stacked panels */
        .right-panels { display: flex; flex-direction: column; gap: 1rem; }

        .join-panel {
            background: var(--card-bg, #1e293b);
            border-radius: 10px;
            border: 1.5px solid var(--border-color, #334155);
            overflow: hidden;
            transition: border-color 0.2s;
        }
        .join-panel.panel-active { border-color: var(--panel-color, #334155); }
        .join-panel-header {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            padding: 0.875rem 1.1rem;
            cursor: pointer;
            user-select: none;
            transition: background 0.15s;
        }
        .join-panel-header:hover { background: rgba(255,255,255,.04); }
        .join-panel-header h3 {
            margin: 0;
            font-size: 0.95rem;
            color: var(--text-primary, #fff);
            flex: 1;
            display: flex;
            align-items: center;
            gap: 0.45rem;
        }
        .join-panel-sub {
            font-size: 0.75rem;
            color: var(--text-secondary, #64748b);
            font-weight: 400;
        }

        /* Toggle switch */
        .toggle-switch {
            position: relative;
            width: 36px;
            height: 20px;
            flex-shrink: 0;
        }
        .toggle-switch input { display: none; }
        .toggle-track {
            position: absolute;
            inset: 0;
            background: #374151;
            border-radius: 20px;
            transition: background 0.2s;
        }
        .toggle-switch input:checked ~ .toggle-track { background: var(--toggle-on, #009999); }
        .toggle-thumb {
            position: absolute;
            top: 3px;
            left: 3px;
            width: 14px;
            height: 14px;
            background: #fff;
            border-radius: 50%;
            transition: transform 0.2s;
        }
        .toggle-switch input:checked ~ .toggle-track > .toggle-thumb { transform: translateX(16px); }

        .join-panel-body {
            padding: 0 1.1rem 1.1rem;
            display: none;
        }
        .join-panel.panel-active .join-panel-body { display: block; }

        .join-panel-hint {
            font-size: 0.78rem;
            color: var(--text-secondary, #64748b);
            margin-bottom: 0.85rem;
            padding: 0.5rem 0.75rem;
            background: rgba(255,255,255,.03);
            border-left: 3px solid var(--panel-color, #334155);
            border-radius: 0 4px 4px 0;
        }

        /* Condition builder (shared) */
        .cb-group {
            border: 1.5px solid var(--border-color, #334155);
            border-radius: 8px;
            background: var(--bg-secondary, #0f172a);
        }
        .cb-group-header {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.6rem 0.85rem;
            border-bottom: 1px solid var(--border-color, #334155);
            background: rgba(0,0,0,.18);
            border-radius: 8px 8px 0 0;
            flex-wrap: wrap;
        }
        .cb-group-header .group-label {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: var(--text-secondary, #94a3b8);
        }
        .cb-operator-toggle {
            display: inline-flex;
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid var(--border-color, #334155);
        }
        .cb-operator-toggle button {
            background: transparent;
            border: none;
            color: var(--text-secondary, #94a3b8);
            padding: 0.2rem 0.6rem;
            cursor: pointer;
            font-size: 0.76rem;
            font-weight: 700;
            transition: background 0.15s, color 0.15s;
        }
        .cb-operator-toggle button.active-and { background: #2563eb; color: #fff; }
        .cb-operator-toggle button.active-or  { background: #7c3aed; color: #fff; }
        .cb-operator-toggle button:hover:not(.active-and):not(.active-or) { background: rgba(255,255,255,.06); }
        .cb-group-actions { margin-left: auto; display: flex; gap: 0.35rem; flex-wrap: wrap; }
        .btn-add-condition, .btn-add-group, .btn-remove-group {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.25rem 0.6rem; border-radius: 4px;
            border: 1px solid transparent; cursor: pointer;
            font-size: 0.76rem; font-weight: 600;
            transition: background 0.15s, color 0.15s;
        }
        .btn-add-condition { background: rgba(0,153,153,.12); color: #5eead4; border-color: rgba(0,153,153,.3); }
        .btn-add-condition:hover { background: rgba(0,153,153,.25); }
        .btn-add-group     { background: rgba(124,58,237,.12); color: #a78bfa; border-color: rgba(124,58,237,.3); }
        .btn-add-group:hover { background: rgba(124,58,237,.25); }
        .btn-remove-group  { background: rgba(239,68,68,.1); color: #f87171; border-color: rgba(239,68,68,.25); }
        .btn-remove-group:hover { background: rgba(239,68,68,.22); }

        .cb-group-body { padding: 0.65rem 0.85rem; display: flex; flex-direction: column; gap: 0.5rem; }
        .cb-item-sep {
            display: flex; align-items: center; gap: 0.4rem;
            font-size: 0.68rem; font-weight: 700;
            color: var(--text-secondary, #64748b);
            padding: 0 0.2rem; text-transform: uppercase;
        }
        .cb-item-sep::before, .cb-item-sep::after {
            content: ''; flex: 1; height: 1px; background: var(--border-color, #334155);
        }
        .cb-item-sep.sep-and span { color: #4ade80; }
        .cb-item-sep.sep-or  span { color: #c084fc; }

        .cb-condition {
            display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap;
            background: rgba(255,255,255,.03);
            border: 1px solid var(--border-color, #2d3f52);
            border-radius: 5px; padding: 0.5rem 0.65rem;
        }
        .cb-condition select,
        .cb-condition input[type="text"],
        .cb-condition input[type="number"],
        .cb-condition input[type="date"] {
            background: var(--bg-secondary, #0f172a);
            border: 1px solid var(--border-color, #334155);
            color: var(--text-primary, #e2e8f0);
            border-radius: 4px; padding: 0.38rem 0.55rem;
            font-size: 0.82rem; outline: none;
            transition: border-color 0.15s; font-family: inherit;
        }
        .cb-condition select:focus, .cb-condition input:focus { border-color: var(--siemens-petrol, #009999); }
        .cb-condition select:disabled, .cb-condition input:disabled { opacity: 0.4; cursor: not-allowed; }
        .cb-condition .sel-field    { min-width: 160px; }
        .cb-condition .sel-operator { min-width: 175px; }
        .cb-condition .inp-value    { min-width: 130px; flex: 1; }
        .cb-condition .sel-value    { min-width: 130px; flex: 1; }
        .btn-remove-condition {
            background: transparent; border: none; color: #475569;
            cursor: pointer; padding: 0.25rem; border-radius: 3px;
            transition: color 0.15s, background 0.15s;
            margin-left: auto; flex-shrink: 0; font-size: 0.85rem;
        }
        .btn-remove-condition:hover { color: #f87171; background: rgba(239,68,68,.1); }
        .cb-group-body > .cb-nested-group-wrapper {
            border-left: 2px solid rgba(124,58,237,.35);
            padding-left: 0.5rem; margin-left: 0.15rem;
        }
        .cb-empty-root {
            padding: 1.5rem; text-align: center;
            color: var(--text-secondary, #64748b); font-size: 0.85rem;
        }

        /* Bottom action bar */
        .export-action-bar {
            background: var(--card-bg, #1e293b);
            border-radius: 10px;
            padding: 1.1rem 1.5rem;
            margin-top: 1.5rem;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .format-options { display: flex; gap: 0.65rem; flex-wrap: wrap; }
        .format-option {
            display: flex; align-items: center; gap: 0.35rem;
            background: rgba(255,255,255,.04);
            border: 1.5px solid var(--border-color, #334155);
            border-radius: 6px; padding: 0.45rem 0.85rem;
            cursor: pointer; font-size: 0.82rem;
            color: var(--text-secondary, #94a3b8);
            transition: border-color 0.15s, background 0.15s, color 0.15s;
            user-select: none;
        }
        .format-option input[type="radio"] { display: none; }
        .format-option.selected {
            border-color: var(--siemens-petrol, #009999);
            color: var(--text-primary, #fff);
            background: rgba(0,153,153,.12);
        }
        .bar-sep { width: 1px; height: 28px; background: var(--border-color, #334155); }
        .btn-preview {
            background: var(--siemens-petrol, #009999); color: #fff;
            border: none; padding: 0.6rem 1.35rem; border-radius: 6px;
            cursor: pointer; font-size: 0.9rem; font-weight: 700;
            display: inline-flex; align-items: center; gap: 0.4rem;
            transition: background 0.2s;
        }
        .btn-preview:hover { background: #00797a; }
        .btn-export-dl {
            background: #0f766e; color: #fff;
            border: none; padding: 0.6rem 1.35rem; border-radius: 6px;
            cursor: pointer; font-size: 0.9rem; font-weight: 700;
            display: inline-flex; align-items: center; gap: 0.4rem;
            transition: background 0.2s;
        }
        .btn-export-dl:hover { background: #115e59; }
        .btn-clear-all {
            background: transparent; border: 1px solid var(--border-color, #334155);
            color: var(--text-secondary, #94a3b8); padding: 0.6rem 1rem;
            border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600;
            display: inline-flex; align-items: center; gap: 0.35rem;
            transition: border-color 0.15s, color 0.15s;
        }
        .btn-clear-all:hover { border-color: #94a3b8; color: #fff; }
        .limit-select {
            background: var(--bg-secondary, #0f172a);
            border: 1px solid var(--border-color, #334155);
            color: var(--text-primary, #e2e8f0);
            border-radius: 5px; padding: 0.38rem 0.5rem;
            font-size: 0.8rem; cursor: pointer;
        }
        .bar-info { font-size: 0.8rem; color: var(--text-secondary, #94a3b8); margin-left: auto; }

        /* SQL preview box */
        .query-preview {
            background: var(--bg-secondary, #0f172a);
            border: 1px solid var(--border-color, #334155);
            border-radius: 6px; padding: 0.75rem 1rem;
            font-family: 'Consolas','Courier New',monospace;
            font-size: 0.76rem; color: #7dd3fc;
            white-space: pre-wrap; word-break: break-all;
            max-height: 160px; overflow-y: auto; line-height: 1.55;
            margin-top: 0.5rem;
        }
        .preview-label {
            font-size: 0.78rem; font-weight: 600;
            color: var(--text-secondary, #94a3b8);
            text-transform: uppercase; letter-spacing: .05em;
        }

        /* Results panel */
        .results-panel {
            margin-top: 1.5rem;
            background: var(--card-bg, #1e293b);
            border-radius: 10px; padding: 1.5rem;
        }
        .results-toolbar {
            display: flex; align-items: center;
            justify-content: space-between; flex-wrap: wrap;
            gap: 0.75rem; margin-bottom: 1rem;
        }
        .results-toolbar h3 { margin: 0; font-size: 1rem; color: var(--text-primary,#fff); display:flex;align-items:center;gap:.4rem; }
        .results-meta { font-size: 0.8rem; color: var(--text-secondary, #94a3b8); }
        .results-meta strong { color: var(--text-primary, #e2e8f0); }
        .results-sql-toggle {
            background: transparent; border: 1px solid var(--border-color,#334155);
            color: var(--text-secondary,#94a3b8); padding: 0.28rem 0.65rem;
            border-radius: 4px; cursor: pointer; font-size: 0.76rem; font-weight: 600;
            transition: border-color .15s, color .15s;
        }
        .results-sql-toggle:hover { color:#fff; border-color:#94a3b8; }
        .results-sql-box {
            background: var(--bg-secondary,#0f172a); border: 1px solid var(--border-color,#334155);
            border-radius: 5px; padding: 0.7rem 1rem;
            font-family: 'Consolas','Courier New',monospace; font-size: 0.76rem;
            color: #7dd3fc; white-space: pre-wrap; word-break: break-all;
            margin-bottom: 1rem; max-height: 140px; overflow-y: auto;
        }
        .results-table-wrap { overflow-x: auto; border-radius: 6px; border: 1px solid var(--border-color,#334155); }
        .results-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        .results-table thead th {
            background: rgba(0,0,0,.25); color: var(--text-secondary,#94a3b8);
            font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
            font-size: 0.7rem; padding: 0.5rem 0.7rem; text-align: left;
            border-bottom: 1px solid var(--border-color,#334155); white-space: nowrap;
            position: sticky; top: 0; z-index: 1;
        }
        .results-table thead th.col-vuln { color: #f87171; }
        .results-table thead th.col-patch { color: #93c5fd; }
        .results-table thead th.col-rem   { color: #c4b5fd; }
        .results-table tbody tr:hover { background: rgba(255,255,255,.04); }
        .results-table tbody td {
            padding: 0.45rem 0.7rem; border-bottom: 1px solid rgba(51,65,85,.5);
            color: var(--text-primary,#e2e8f0); max-width: 240px;
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .results-table tbody td.null-cell { color: var(--text-secondary,#64748b); font-style: italic; font-size: 0.72rem; }
        .results-table tbody tr:last-child td { border-bottom: none; }
        .results-pagination {
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 0.5rem; margin-top: 0.85rem;
        }
        .results-pagination .page-info { font-size: 0.8rem; color: var(--text-secondary,#94a3b8); }
        .results-pagination .pag-btns  { display: flex; gap: 0.4rem; }
        .btn-pag {
            background: rgba(255,255,255,.05); border: 1px solid var(--border-color,#334155);
            color: var(--text-secondary,#94a3b8); padding: 0.28rem 0.65rem;
            border-radius: 4px; cursor: pointer; font-size: 0.8rem;
            transition: background .15s, color .15s;
        }
        .btn-pag:hover:not(:disabled) { background: rgba(0,153,153,.15); color: var(--siemens-petrol,#009999); border-color: var(--siemens-petrol,#009999); }
        .btn-pag:disabled { opacity: .35; cursor: not-allowed; }
        .results-loading {
            display: flex; align-items: center; gap: 0.7rem;
            padding: 2rem; justify-content: center;
            color: var(--text-secondary,#94a3b8); font-size: 0.9rem;
        }
        .mini-spinner {
            width: 1.2rem; height: 1.2rem;
            border: 2px solid var(--border-color,#334155);
            border-top-color: var(--siemens-petrol,#009999);
            border-radius: 50%; animation: ai-spin .7s linear infinite; flex-shrink: 0;
        }
        @keyframes ai-spin { to { transform: rotate(360deg); } }
        .results-empty { padding: 2rem; text-align: center; color: var(--text-secondary,#64748b); font-size: 0.875rem; }
        .results-error {
            padding: 0.8rem 1rem; background: rgba(239,68,68,.09);
            border: 1px solid rgba(239,68,68,.3); border-radius: 5px;
            color: #f87171; font-size: 0.875rem;
        }
        .results-table thead th.col-asset { color: #5eead4; }

        /* ── Primary entity mode selector ── */
        .mode-selector {
            display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;
            margin-top: 0.5rem;
        }
        .mode-btn {
            display: flex; flex-direction: column; align-items: center;
            justify-content: center; gap: 0.35rem; padding: 1.2rem 0.75rem;
            border-radius: 8px; border: 2px solid var(--border-color, #334155);
            background: rgba(255,255,255,.03); color: var(--text-secondary,#94a3b8);
            cursor: pointer; transition: border-color .2s, background .2s;
            text-align: center; font-family: inherit; width: 100%;
        }
        .mode-btn i    { font-size: 1.4rem; pointer-events: none; }
        .mode-btn span { font-size: 0.9rem; font-weight: 700; color: var(--text-primary,#fff); pointer-events: none; }
        .mode-btn small { font-size: 0.72rem; color: var(--text-secondary,#64748b); margin-top: 0.1rem; pointer-events: none; }
        .mode-btn:hover { background: rgba(255,255,255,.06); }
        .mode-btn-vuln.mode-active  { border-color: #ef4444; background: rgba(239,68,68,.1); }
        .mode-btn-patch.mode-active { border-color: #3b82f6; background: rgba(59,130,246,.1); }

        /* ── Primary builder area (sits below mode selector) ── */
        .primary-builder-area { margin-top: 1rem; }
    </style>
</head>
<body>
<div class="dashboard-container">
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="dashboard-main">
        <div class="page-header">
            <div class="page-title">
                <h1><i class="fas fa-file-export"></i> Export Data</h1>
                <p>Choose Vulnerabilities or Patches as the primary entity, add filter conditions, then optionally join the other entity, Assets, or Remediations on the right.</p>
            </div>
            <div class="page-actions">
                <a href="/pages/dashboard.php" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </a>
            </div>
        </div>

        <!-- Hidden inputs for form POST -->
        <input type="hidden" id="exportFormatInput" value="csv">

        <!-- Two-column builder grid -->
        <div class="export-main-grid">

            <!--
                 LEFT  Asset conditions (required)
            -->
            <div class="export-card">
                <div class="export-card-header">
                    <h2><i class="fas fa-filter"></i> Primary Entity</h2>
                    <span class="entity-badge badge-vulnerability" id="primaryEntityBadge"><i class="fas fa-bug"></i> vulnerabilities</span>
                </div>
                <p class="card-desc">Select what to export, then add filter conditions below. Leave conditions empty to export all records.</p>
                <div class="mode-selector">
                    <button type="button" class="mode-btn mode-btn-vuln mode-active" id="modeBtnVuln" onclick="switchMode('vulnerability')">
                        <i class="fas fa-bug" style="color:#f87171;"></i>
                        <span>Vulnerabilities</span>
                        <small>Export vuln records</small>
                    </button>
                    <button type="button" class="mode-btn mode-btn-patch" id="modeBtnPatch" onclick="switchMode('patch')">
                        <i class="fas fa-band-aid" style="color:#93c5fd;"></i>
                        <span>Patches</span>
                        <small>Export patch records</small>
                    </button>
                </div>
                <div class="primary-builder-area">
                    <div id="primaryVulnBuilder"></div>
                    <div id="primaryPatchBuilder" style="display:none;"></div>
                </div>
            </div>

            <!-- 
                 RIGHT  Join panels (optional)
            -->
            <div class="right-panels">

                <!-- Assets (optional join conditions) -->
                <div class="join-panel" id="panelAsset" style="--panel-color:#009999; --toggle-on:#009999;">
                    <div class="join-panel-header" onclick="togglePanel('asset')">
                        <h3>
                            <i class="fas fa-server" style="color:#5eead4;"></i>
                            Assets
                            <span class="join-panel-sub" id="assetCondCount"></span>
                        </h3>
                        <span class="entity-badge badge-asset">assets</span>
                        <label class="toggle-switch" onclick="event.stopPropagation()">
                            <input type="checkbox" id="toggleAsset" onchange="onPanelToggle('asset', this.checked)">
                            <div class="toggle-track"><div class="toggle-thumb"></div></div>
                        </label>
                    </div>
                    <div class="join-panel-body">
                        <p class="join-panel-hint" id="assetJoinHint" style="border-left-color:#009999;">
                            Assets are always JOINed. Add conditions here to filter which assets are included.
                        </p>
                        <div id="assetBuilder"></div>
                    </div>
                </div>

                <!-- Counterpart: opposite entity (Patches when Vuln, Vulnerabilities when Patch) -->
                <div class="join-panel" id="panelCounterpart" style="--panel-color:#3b82f6; --toggle-on:#3b82f6;">
                    <div class="join-panel-header" onclick="togglePanel('counterpart')">
                        <h3 id="counterpartPanelTitle">
                            <i class="fas fa-band-aid" style="color:#93c5fd;"></i>
                            Patches
                            <span class="join-panel-sub" id="counterpartCondCount"></span>
                        </h3>
                        <span class="entity-badge badge-patch" id="counterpartPanelBadge">patches</span>
                        <label class="toggle-switch" onclick="event.stopPropagation()">
                            <input type="checkbox" id="toggleCounterpart" onchange="onPanelToggle('counterpart', this.checked)">
                            <div class="toggle-track"><div class="toggle-thumb"></div></div>
                        </label>
                    </div>
                    <div class="join-panel-body">
                        <p class="join-panel-hint" id="counterpartPanelHint" style="border-left-color:#3b82f6;">
                            INNER JOINed via <code>patch_applications</code>. Only rows where matching patches exist are included.
                        </p>
                        <div id="counterpartPatchBuilder"></div>
                        <div id="counterpartVulnBuilder" style="display:none;"></div>
                    </div>
                </div>                

                <!-- Remediations (optional) -->
                <div class="join-panel" id="panelRemediation" style="--panel-color:#8b5cf6; --toggle-on:#8b5cf6;">
                    <div class="join-panel-header" onclick="togglePanel('remediation')">
                        <h3>
                            <i class="fas fa-wrench" style="color:#c4b5fd;"></i>
                            Remediations
                            <span class="join-panel-sub" id="remCondCount"></span>
                        </h3>
                        <span class="entity-badge badge-remediation">remediation_actions</span>
                        <label class="toggle-switch" onclick="event.stopPropagation()">
                            <input type="checkbox" id="toggleRemediation" onchange="onPanelToggle('remediation', this.checked)">
                            <div class="toggle-track"><div class="toggle-thumb"></div></div>
                        </label>
                    </div>
                    <div class="join-panel-body">
                        <p class="join-panel-hint" style="border-left-color:#8b5cf6;">
                            LEFT JOINed via <code>remediation_assets_link</code>. Add conditions to filter which remediation records are included.
                        </p>
                        <div id="remBuilder"></div>
                    </div>
                </div>

            </div><!-- .right-panels -->
        </div><!-- .export-main-grid -->

        <!-- Action bar -->
        <div class="export-action-bar">
            <div class="format-options" id="formatOptions">
                <label class="format-option selected">
                    <input type="radio" name="fmt" value="csv" checked>
                    <i class="fas fa-file-csv"></i> CSV
                </label>
                <label class="format-option">
                    <input type="radio" name="fmt" value="json">
                    <i class="fas fa-file-code"></i> JSON
                </label>
                <label class="format-option">
                    <input type="radio" name="fmt" value="excel">
                    <i class="fas fa-file-excel"></i> Excel
                </label>
            </div>
            <div class="bar-sep"></div>
            <button type="button" class="btn-preview" id="btnPreview">
                <i class="fas fa-search"></i> Preview Results
            </button>
            <button type="button" class="btn-export-dl" id="btnExport">
                <i class="fas fa-download"></i> Export
            </button>
            <button type="button" class="btn-clear-all" id="btnClearAll">
                <i class="fas fa-trash-alt"></i> Clear All
            </button>
            <label style="display:inline-flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--text-secondary,#94a3b8);">
                Rows:
                <select class="limit-select" id="previewLimit">
                    <option value="50">50</option>
                    <option value="100" selected>100</option>
                    <option value="200">200</option>
                    <option value="500">500</option>
                </select>
            </label>
            <span class="bar-info" id="barInfo"></span>
        </div>

        <!-- Results panel -->
        <div class="results-panel" id="resultsPanel" style="display:none;">
            <div class="results-toolbar">
                <h3><i class="fas fa-table"></i> Results</h3>
                <div style="display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;">
                    <span class="results-meta" id="resultsMeta"></span>
                    <button type="button" class="results-sql-toggle" id="btnToggleSql">Show SQL</button>
                </div>
            </div>
            <div id="resultsSqlBox" class="results-sql-box" style="display:none;"></div>
            <div id="resultsBody"></div>
            <div class="results-pagination" id="resultsPagination" style="display:none;">
                <span class="page-info" id="pagInfo"></span>
                <div class="pag-btns">
                    <button class="btn-pag" id="btnPrevPage"><i class="fas fa-chevron-left"></i> Prev</button>
                    <button class="btn-pag" id="btnNextPage">Next <i class="fas fa-chevron-right"></i></button>
                </div>
            </div>
        </div>

    </main>
</div>

<script>
//  Entity / field metadata injected from PHP
var ENTITY_FIELDS = <?php echo $entityFieldsJson; ?>;

// â”€Operator lists â””””””””””””””””””””””””””””””””””””””””””””””””””””””””””€
var OPERATORS_TEXT = [
    {value:'=',label:'Equals'},{value:'!=',label:'Not Equals'},
    {value:'LIKE',label:'Contains'},{value:'NOT LIKE',label:'Does Not Contain'},
    {value:'STARTS',label:'Starts With'},{value:'ENDS',label:'Ends With'},
    {value:'IS NULL',label:'Is Empty'},{value:'NOT NULL',label:'Is Not Empty'},
];
var OPERATORS_NUMBER = [
    {value:'=',label:'Equals'},{value:'!=',label:'Not Equals'},
    {value:'<',label:'Less Than'},{value:'>',label:'Greater Than'},
    {value:'<=',label:'Less Than or Equal To'},{value:'>=',label:'Greater Than or Equal To'},
    {value:'IS NULL',label:'Is Empty'},{value:'NOT NULL',label:'Is Not Empty'},
];
var OPERATORS_DATE = [
    {value:'=',label:'Equals'},{value:'!=',label:'Not Equals'},
    {value:'<',label:'Before'},{value:'>',label:'After'},
    {value:'<=',label:'On or Before'},{value:'>=',label:'On or After'},
    {value:'IS NULL',label:'Is Empty'},{value:'NOT NULL',label:'Is Not Empty'},
];
var OPERATORS_SELECT = [
    {value:'=',label:'Equals'},{value:'!=',label:'Not Equals'},
    {value:'IS NULL',label:'Is Empty'},{value:'NOT NULL',label:'Is Not Empty'},
];

function getOperatorsForType(t) {
    if (t==='number') return OPERATORS_NUMBER;
    if (t==='date')   return OPERATORS_DATE;
    if (t==='select'||t==='boolean') return OPERATORS_SELECT;
    return OPERATORS_TEXT;
}
function noValueNeeded(op) { return op==='IS NULL'||op==='NOT NULL'; }
function getFieldMeta(entityKey, fieldKey) {
    var ent = ENTITY_FIELDS[entityKey];
    if (!ent) return null;
    for (var i=0;i<ent.fields.length;i++) if (ent.fields[i].key===fieldKey) return ent.fields[i];
    return null;
}

// â”€Tree utilities (global, pure) â””””””””””””””””””””””””””””””””””””””””””€
var _uid = 1;
function uid() { return 'n'+(++_uid); }

function makeGroup(op) { return {id:uid(),type:'group',operator:op||'AND',children:[]}; }
function makeCond()    { return {id:uid(),type:'condition',field:'',operator:'=',value:''}; }

function findNode(node, id) {
    if (node.id===id) return node;
    if (node.type==='group') {
        for (var i=0;i<node.children.length;i++) {
            var f=findNode(node.children[i],id); if (f) return f;
        }
    }
    return null;
}
function removeNode(root, id) {
    if (root.type==='group') {
        for (var i=0;i<root.children.length;i++) {
            if (root.children[i].id===id) { root.children.splice(i,1); return true; }
            if (removeNode(root.children[i],id)) return true;
        }
    }
    return false;
}
function countConds(node) {
    if (node.type==='condition') return node.field?1:0;
    var c=0; node.children.forEach(function(ch){c+=countConds(ch);}); return c;
}


//  Builder factory  creates an isolated condition builder instance
//  with a fixed entity (no entity dropdown shown)

function createBuilder(entityKey, containerId, onUpdate) {
    var tree = makeGroup('AND');
    var container = document.getElementById(containerId);

    // Condition row â””€
    function renderCond(cond) {
        var div = document.createElement('div');
        div.className = 'cb-condition'; div.dataset.id = cond.id;

        var selField = document.createElement('select');
        selField.className = 'sel-field'; selField.title = 'Field';
        var fOpt = document.createElement('option');
        fOpt.value=''; fOpt.textContent=' Select Field ';
        selField.appendChild(fOpt);
        (ENTITY_FIELDS[entityKey]||{fields:[]}).fields.forEach(function(f){
            var o=document.createElement('option');
            o.value=f.key; o.textContent=f.label;
            if(f.key===cond.field) o.selected=true;
            selField.appendChild(o);
        });

        var selOp = document.createElement('select');
        selOp.className = 'sel-operator'; selOp.title='Operator';
        selOp.disabled = !cond.field;
        var meta = getFieldMeta(entityKey, cond.field);
        var ops  = meta ? getOperatorsForType(meta.type) : OPERATORS_TEXT;
        ops.forEach(function(op){
            var o=document.createElement('option');
            o.value=op.value; o.textContent=op.label;
            if(op.value===cond.operator) o.selected=true;
            selOp.appendChild(o);
        });

        var valWrap = document.createElement('span');
        valWrap.className='val-wrapper'; valWrap.style.flex='1';
        buildVal(valWrap, cond);

        var btnRm = document.createElement('button');
        btnRm.type='button'; btnRm.className='btn-remove-condition';
        btnRm.title='Remove'; btnRm.innerHTML='<i class="fas fa-times"></i>';

        div.appendChild(selField); div.appendChild(selOp);
        div.appendChild(valWrap);  div.appendChild(btnRm);

        selField.addEventListener('change', function(){
            var n=findNode(tree,cond.id); n.field=this.value; n.operator='='; n.value='';
            render(); if (onUpdate) onUpdate();
        });
        selOp.addEventListener('change', function(){
            var n=findNode(tree,cond.id); n.operator=this.value;
            render(); if (onUpdate) onUpdate();
        });
        btnRm.addEventListener('click', function(){
            removeNode(tree, cond.id); render(); if (onUpdate) onUpdate();
        });
        return div;
    }

    // Value input â””€
    function buildVal(wrapper, cond) {
        wrapper.innerHTML='';
        var meta    = getFieldMeta(entityKey, cond.field);
        var disabled= !cond.field || noValueNeeded(cond.operator);
        function onChange(val){ var n=findNode(tree,cond.id); n.value=val; if(onUpdate) onUpdate(); }

        if (!meta || meta.type==='text') {
            var inp=document.createElement('input'); inp.type='text';
            inp.className='inp-value'; inp.placeholder='Enter valueâ€¦';
            inp.value=cond.value||''; inp.disabled=disabled;
            inp.addEventListener('input',function(){ onChange(this.value); });
            wrapper.appendChild(inp);
        } else if (meta.type==='number') {
            var inp=document.createElement('input'); inp.type='number';
            inp.className='inp-value'; inp.placeholder='0'; inp.step='any';
            inp.value=cond.value||''; inp.disabled=disabled;
            inp.addEventListener('input',function(){ onChange(this.value); });
            wrapper.appendChild(inp);
        } else if (meta.type==='date') {
            var inp=document.createElement('input'); inp.type='date';
            inp.className='inp-value'; inp.value=cond.value||''; inp.disabled=disabled;
            inp.addEventListener('change',function(){ onChange(this.value); });
            wrapper.appendChild(inp);
        } else if (meta.type==='select'||meta.type==='boolean') {
            var sel=document.createElement('select'); sel.className='sel-value'; sel.disabled=disabled;
            var eO=document.createElement('option'); eO.value=''; eO.textContent=' Select ';
            sel.appendChild(eO);
            (meta.options||[]).forEach(function(v){
                var o=document.createElement('option'); o.value=v; o.textContent=v;
                if(v===cond.value) o.selected=true; sel.appendChild(o);
            });
            sel.addEventListener('change',function(){ onChange(this.value); });
            wrapper.appendChild(sel);
        }
    }

    // Group â””€
    function renderGroup(group, isRoot) {
        var div=document.createElement('div');
        div.className='cb-group'; div.dataset.id=group.id;

        // Header
        var hdr=document.createElement('div'); hdr.className='cb-group-header';
        var lbl=document.createElement('span'); lbl.className='group-label';
        lbl.textContent=isRoot?'Conditions':'Group';

        var tog=document.createElement('div'); tog.className='cb-operator-toggle';
        var bAnd=document.createElement('button'); bAnd.type='button'; bAnd.textContent='AND'; bAnd.dataset.op='AND';
        bAnd.className=group.operator==='AND'?'active-and':'';
        var bOr=document.createElement('button');  bOr.type='button';  bOr.textContent='OR';  bOr.dataset.op='OR';
        bOr.className=group.operator==='OR'?'active-or':'';
        tog.appendChild(bAnd); tog.appendChild(bOr);
        [bAnd,bOr].forEach(function(b){
            b.addEventListener('click',function(){
                var n=findNode(tree,group.id); n.operator=this.dataset.op;
                render(); if(onUpdate) onUpdate();
            });
        });

        var acts=document.createElement('div'); acts.className='cb-group-actions';
        var bAdd=document.createElement('button'); bAdd.type='button';
        bAdd.className='btn-add-condition';
        bAdd.innerHTML='<i class="fas fa-plus"></i> Add Condition';
        bAdd.addEventListener('click',function(){
            var n=findNode(tree,group.id); n.children.push(makeCond());
            render(); if(onUpdate) onUpdate();
        });
        var bGrp=document.createElement('button'); bGrp.type='button';
        bGrp.className='btn-add-group';
        bGrp.innerHTML='<i class="fas fa-layer-group"></i> Add Group';
        bGrp.addEventListener('click',function(){
            var n=findNode(tree,group.id); n.children.push(makeGroup('AND'));
            render(); if(onUpdate) onUpdate();
        });
        acts.appendChild(bAdd); acts.appendChild(bGrp);

        if (!isRoot) {
            var bRm=document.createElement('button'); bRm.type='button';
            bRm.className='btn-remove-group';
            bRm.innerHTML='<i class="fas fa-trash"></i> Remove';
            bRm.addEventListener('click',function(){
                removeNode(tree,group.id); render(); if(onUpdate) onUpdate();
            });
            acts.appendChild(bRm);
        }
        hdr.appendChild(lbl); hdr.appendChild(tog); hdr.appendChild(acts);
        div.appendChild(hdr);

        // Body
        var body=document.createElement('div'); body.className='cb-group-body';
        if (group.children.length===0 && isRoot) {
            var em=document.createElement('div'); em.className='cb-empty-root';
            em.innerHTML='<i class="fas fa-filter" style="font-size:1.2rem;opacity:.25;display:block;margin-bottom:.4rem;"></i>'
                        +'Click <strong>+ Add Condition</strong> to filter.';
            body.appendChild(em);
        } else {
            group.children.forEach(function(child,idx){
                if (idx>0) {
                    var sep=document.createElement('div');
                    sep.className='cb-item-sep '+(group.operator==='AND'?'sep-and':'sep-or');
                    sep.innerHTML='<span>'+group.operator+'</span>';
                    body.appendChild(sep);
                }
                if (child.type==='condition') {
                    body.appendChild(renderCond(child));
                } else {
                    var wr=document.createElement('div'); wr.className='cb-nested-group-wrapper';
                    wr.appendChild(renderGroup(child,false)); body.appendChild(wr);
                }
            });
        }
        div.appendChild(body);
        return div;
    }

    function render() {
        container.innerHTML='';
        container.appendChild(renderGroup(tree, true));
    }

    render(); // initial render

    return {
        getTree: function() { return tree; },
        condCount: function() { return countConds(tree); },
        reset: function() { tree=makeGroup('AND'); render(); if(onUpdate) onUpdate(); },
    };
}


//  Panel toggle state

var panelEnabled = { counterpart: false, asset: false, remediation: false };

// ─── Primary mode ─────────────────────────────────────────────────────────────
var primaryMode = 'vulnerability'; // 'vulnerability' | 'patch'

function switchMode(mode) {
    primaryMode = mode;
    var isVuln = (mode === 'vulnerability');

    // Mode buttons
    document.getElementById('modeBtnVuln').classList.toggle('mode-active',  isVuln);
    document.getElementById('modeBtnPatch').classList.toggle('mode-active', !isVuln);

    // Primary card badge
    var pBadge = document.getElementById('primaryEntityBadge');
    pBadge.className   = 'entity-badge ' + (isVuln ? 'badge-vulnerability' : 'badge-patch');
    pBadge.innerHTML   = isVuln ? '<i class="fas fa-bug"></i> vulnerabilities' : '<i class="fas fa-band-aid"></i> patches';

    // Show/hide primary builders in left card
    document.getElementById('primaryVulnBuilder').style.display  = isVuln ? '' : 'none';
    document.getElementById('primaryPatchBuilder').style.display = isVuln ? 'none' : '';

    // Counterpart panel (opposite entity)
    var cIsVuln = !isVuln; // counterpart is opposite of primary
    document.getElementById('counterpartVulnBuilder').style.display  = cIsVuln ? '' : 'none';
    document.getElementById('counterpartPatchBuilder').style.display = cIsVuln ? 'none' : '';

    var cTitle = document.getElementById('counterpartPanelTitle');
    cTitle.innerHTML = cIsVuln
        ? '<i class="fas fa-bug" style="color:#f87171;"></i> Vulnerabilities <span class="join-panel-sub" id="counterpartCondCount"></span>'
        : '<i class="fas fa-band-aid" style="color:#93c5fd;"></i> Patches <span class="join-panel-sub" id="counterpartCondCount"></span>';

    var cBadge = document.getElementById('counterpartPanelBadge');
    cBadge.className   = 'entity-badge ' + (cIsVuln ? 'badge-vulnerability' : 'badge-patch');
    cBadge.textContent = cIsVuln ? 'vulnerabilities' : 'patches';

    var cPanel = document.getElementById('panelCounterpart');
    var cColor = cIsVuln ? '#ef4444' : '#3b82f6';
    cPanel.style.setProperty('--panel-color', cColor);
    cPanel.style.setProperty('--toggle-on',   cColor);

    var cHint = document.getElementById('counterpartPanelHint');
    cHint.style.borderLeftColor = cColor;
    cHint.innerHTML = cIsVuln
        ? 'INNER JOINed via <code>device_vulnerabilities_link</code>. Only rows where matching vulnerabilities exist are included.'
        : 'INNER JOINed via <code>patch_applications</code>. Only rows where matching patches exist are included.';

    updateBarInfo();
}

function togglePanel(key) {
    var id  = 'toggle' + key.charAt(0).toUpperCase() + key.slice(1);
    var chk = document.getElementById(id);
    chk.checked = !chk.checked;
    onPanelToggle(key, chk.checked);
}

function onPanelToggle(key, enabled) {
    panelEnabled[key] = enabled;
    var panelId = 'panel' + key.charAt(0).toUpperCase() + key.slice(1);
    var panel   = document.getElementById(panelId);
    if (enabled) { panel.classList.add('panel-active'); }
    else         { panel.classList.remove('panel-active'); }
    updateBarInfo();
}

// ─── Builder instances ────────────────────────────────────────────────────────
// Left card: two primary builders (only one shown at a time based on mode)
var primaryVulnBuilder      = createBuilder('vulnerability', 'primaryVulnBuilder',      updateBarInfo);
var primaryPatchBuilder     = createBuilder('patch',         'primaryPatchBuilder',      updateBarInfo);
// Right panel counterpart: two builders (opposite entity, only one shown at a time)
var counterpartPatchBuilder = createBuilder('patch',         'counterpartPatchBuilder',  updateBarInfo);
var counterpartVulnBuilder  = createBuilder('vulnerability', 'counterpartVulnBuilder',   updateBarInfo);
// Right panels: assets + remediations
var assetBuilder            = createBuilder('asset',         'assetBuilder',             updateBarInfo);
var remBuilder              = createBuilder('remediation',   'remBuilder',               updateBarInfo);

function getPrimaryBuilder() {
    return primaryMode === 'vulnerability' ? primaryVulnBuilder : primaryPatchBuilder;
}
function getCounterpartBuilder() {
    return primaryMode === 'vulnerability' ? counterpartPatchBuilder : counterpartVulnBuilder;
}

function updateBarInfo() {
    var p = getPrimaryBuilder().condCount();
    var c = panelEnabled.counterpart ? getCounterpartBuilder().condCount() : 0;
    var a = panelEnabled.asset       ? assetBuilder.condCount()            : 0;
    var r = panelEnabled.remediation ? remBuilder.condCount()              : 0;
    var total = p + c + a + r;

    function badge(n) { return n ? ' \u2014 ' + n + ' condition' + (n !== 1 ? 's' : '') : ''; }
    var ccEl = document.getElementById('counterpartCondCount');
    if (ccEl) ccEl.textContent = badge(getCounterpartBuilder().condCount());
    document.getElementById('assetCondCount').textContent = badge(assetBuilder.condCount());
    document.getElementById('remCondCount').textContent   = badge(remBuilder.condCount());

    var entLabel = primaryMode === 'vulnerability' ? 'vulnerability' : 'patch';
    var tables   = 1 + (panelEnabled.counterpart ? 1 : 0) + (panelEnabled.asset ? 1 : 0) + (panelEnabled.remediation ? 1 : 0);
    document.getElementById('barInfo').textContent = total === 0
        ? 'No conditions \u2014 will export all ' + entLabel + ' records'
        : total + ' condition' + (total !== 1 ? 's' : '') + ' across ' + tables + ' table' + (tables !== 1 ? 's' : '');
}
updateBarInfo();

//  Format picker

document.querySelectorAll('.format-option').forEach(function(lbl){
    lbl.addEventListener('click', function(){
        document.querySelectorAll('.format-option').forEach(function(l){ l.classList.remove('selected'); });
        this.classList.add('selected');
        document.getElementById('exportFormatInput').value = this.querySelector('input').value;
    });
});


//  Clear all

document.getElementById('btnClearAll').addEventListener('click', function(){
    if (!confirm('Clear all conditions in all panels?')) return;
    primaryVulnBuilder.reset(); primaryPatchBuilder.reset();
    counterpartPatchBuilder.reset(); counterpartVulnBuilder.reset();
    assetBuilder.reset(); remBuilder.reset();
    document.getElementById('resultsPanel').style.display = 'none';
});


//  Helper: build FormData from current builder state

function buildFormData(extra) {
    var fd = new FormData();
    fd.append('primary_mode', primaryMode);
    fd.append('primary_conditions_json', JSON.stringify(getPrimaryBuilder().getTree()));
    if (panelEnabled.counterpart) fd.append('counterpart_conditions_json', JSON.stringify(getCounterpartBuilder().getTree()));
    if (panelEnabled.asset)       fd.append('asset_conditions_json',       JSON.stringify(assetBuilder.getTree()));
    if (panelEnabled.remediation) fd.append('remediation_conditions_json', JSON.stringify(remBuilder.getTree()));
    if (extra) Object.keys(extra).forEach(function(k){ fd.append(k, extra[k]); });
    return fd;
}


//  Preview

var _lastData  = null;
var _curOffset = 0;

function runPreview(offset) {
    _curOffset = offset || 0;
    var limit  = parseInt(document.getElementById('previewLimit').value, 10) || 100;

    var panel  = document.getElementById('resultsPanel');
    var body   = document.getElementById('resultsBody');
    panel.style.display = 'block';
    body.innerHTML = '<div class="results-loading"><div class="mini-spinner"></div> Queryingâ€¦</div>';
    document.getElementById('resultsPagination').style.display = 'none';
    document.getElementById('resultsMeta').textContent = '';

    var fd = buildFormData({ limit: limit, offset: _curOffset });

    fetch('/pages/export/query.php?action=preview', {method:'POST', body: fd})
        .then(function(r){ return r.json(); })
        .then(function(data){
            if (data.error) {
                body.innerHTML='<div class="results-error"><i class="fas fa-exclamation-circle"></i> '+escHtml(data.error)+'</div>';
                return;
            }
            _lastData = data;
            renderResultsTable(data);
        })
        .catch(function(err){
            body.innerHTML='<div class="results-error"><i class="fas fa-exclamation-circle"></i> Network error: '+escHtml(String(err))+'</div>';
        });
}

function renderResultsTable(data) {
    var body = document.getElementById('resultsBody');
    document.getElementById('resultsSqlBox').textContent = data.sql_preview || '';
    var from = data.offset+1, to = data.offset+data.returned;
    var mLabel  = (data.mode === 'vulnerability') ? 'Vulnerabilities' : 'Patches';
    var mColor  = (data.mode === 'vulnerability') ? '#f87171' : '#93c5fd';
    var cpLabel = (data.mode === 'vulnerability') ? 'Patches' : 'Vulnerabilities';
    var cpColor = (data.mode === 'vulnerability') ? '#93c5fd' : '#f87171';
    var joinInfo = [];
    if (panelEnabled.counterpart) joinInfo.push('<span style="color:'+cpColor+'">+ '+cpLabel+'</span>');
    if (panelEnabled.asset)       joinInfo.push('<span style="color:#5eead4">+ Assets</span>');
    if (panelEnabled.remediation) joinInfo.push('<span style="color:#c4b5fd">+ Remediations</span>');
    document.getElementById('resultsMeta').innerHTML =
        '<strong style="color:'+mColor+'">'+ mLabel+'</strong> '+(joinInfo.length?joinInfo.join(' '):'')+' &mdash; '+data.total.toLocaleString()+' total row'+(data.total!==1?'s':'')+' '+(data.total>data.returned?' &mdash; showing '+from+'&ndash;'+to:'');

    if (!data.rows||data.rows.length===0) {
        body.innerHTML='<div class="results-empty"><i class="fas fa-inbox" style="font-size:1.3rem;opacity:.3;display:block;margin-bottom:.4rem;"></i>No records matched your conditions.</div>';
        document.getElementById('resultsPagination').style.display='none';
        return;
    }

    var table=document.createElement('table'); table.className='results-table';
    var thead=document.createElement('thead'), hrow=document.createElement('tr');
    data.columns.forEach(function(col){
        var th=document.createElement('th');
        if (col.startsWith('asset_'))       th.className='col-asset';
        if (col.startsWith('counterpart_')) th.className=(data.mode==='vulnerability'?'col-patch':'col-vuln');
        if (col.startsWith('rem_'))         th.className='col-rem';
        th.title=col; th.textContent=col.replace(/_/g,' ');
        hrow.appendChild(th);
    });
    thead.appendChild(hrow); table.appendChild(thead);

    var tbody=document.createElement('tbody');
    data.rows.forEach(function(row){
        var tr=document.createElement('tr');
        data.columns.forEach(function(col){
            var td=document.createElement('td');
            var val=row[col];
            if (val===null||val===undefined||val==='') {
                td.className='null-cell'; td.textContent='null';
            } else {
                td.textContent=String(val); td.title=String(val);
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    body.innerHTML='';
    var wrap=document.createElement('div'); wrap.className='results-table-wrap';
    wrap.appendChild(table); body.appendChild(wrap);

    var limit=data.limit, total=data.total;
    var curPage=Math.floor(data.offset/limit)+1, pages=Math.ceil(total/limit);
    var pag=document.getElementById('resultsPagination');
    if (pages>1) {
        pag.style.display='flex';
        document.getElementById('pagInfo').textContent='Page '+curPage+' of '+pages;
        document.getElementById('btnPrevPage').disabled=curPage<=1;
        document.getElementById('btnNextPage').disabled=curPage>=pages;
    } else { pag.style.display='none'; }
    document.getElementById('resultsPanel').scrollIntoView({behavior:'smooth',block:'start'});
}

document.getElementById('btnPreview').addEventListener('click', function(){ runPreview(0); });
document.getElementById('btnPrevPage').addEventListener('click', function(){
    if (_lastData) runPreview(Math.max(0, _curOffset - _lastData.limit));
});
document.getElementById('btnNextPage').addEventListener('click', function(){
    if (_lastData) runPreview(_curOffset + _lastData.limit);
});
document.getElementById('btnToggleSql').addEventListener('click', function(){
    var box=document.getElementById('resultsSqlBox');
    var vis=box.style.display!=='none';
    box.style.display=vis?'none':'block';
    this.textContent=vis?'Show SQL':'Hide SQL';
});


//  Export (native file download via hidden form POST)

document.getElementById('btnExport').addEventListener('click', function(){
    var fmt = document.getElementById('exportFormatInput').value;
    var f   = document.createElement('form');
    f.method='POST'; f.action='/pages/export/query.php?action=export';
    f.style.display='none';
    function addField(n,v){ var i=document.createElement('input'); i.type='hidden'; i.name=n; i.value=v; f.appendChild(i); }
    addField('primary_mode', primaryMode);
    addField('primary_conditions_json', JSON.stringify(getPrimaryBuilder().getTree()));
    if (panelEnabled.counterpart) addField('counterpart_conditions_json', JSON.stringify(getCounterpartBuilder().getTree()));
    if (panelEnabled.asset)       addField('asset_conditions_json',       JSON.stringify(assetBuilder.getTree()));
    if (panelEnabled.remediation) addField('remediation_conditions_json', JSON.stringify(remBuilder.getTree()));
    addField('export_format', fmt);
    document.body.appendChild(f);
    f.submit();
    setTimeout(function(){ document.body.removeChild(f); }, 3000);
});

// â”€Utility â”””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””€
function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>
