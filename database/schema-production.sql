-- ====================================================================================
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
-- ====================================================================================
--
-- INSTRUCTIONS:
-- This is a consolidated schema that includes all database changes.
-- For fresh production installations, use this file instead of applying individual migrations.
-- For existing installations, use scripts/apply-migrations.sh to apply only new migrations.
--
-- For single-instance dev setups, this is the primary schema file.
--
-- ====================================================================================

-- Generated: 2026-02-11 14:28:51

\restrict 7n2HHSFEePEEgKGTLQhc4IHni2VDzecQhQdxCmL05Ur3RFw0HINscoKu1eiGZwn
SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';
CREATE FUNCTION public.archive_epss_historical_scores() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    archived_count INTEGER;
BEGIN
    -- Archive current EPSS scores for vulnerabilities that have EPSS data
    INSERT INTO epss_score_history (cve_id, epss_score, epss_percentile, recorded_date)
    SELECT 
        cve_id,
        epss_score,
        epss_percentile,
        CURRENT_DATE
    FROM vulnerabilities 
    WHERE epss_score IS NOT NULL 
      AND epss_percentile IS NOT NULL
      AND epss_date = CURRENT_DATE
    ON CONFLICT DO NOTHING;
    
    GET DIAGNOSTICS archived_count = ROW_COUNT;
    
    -- Log the archival
    INSERT INTO system_logs (log_level, message, context, created_at)
    VALUES ('INFO', 'EPSS historical scores archived', 
            json_build_object('archived_count', archived_count, 'date', CURRENT_DATE), 
            CURRENT_TIMESTAMP);
    
    RETURN archived_count;
END;
$$;
CREATE FUNCTION public.assign_cve_remediation_task(p_cve_id character varying, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_task_description text DEFAULT NULL::text, p_notes text DEFAULT NULL::text, p_action_id uuid DEFAULT NULL::uuid) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_task_id UUID;
    v_cve_description TEXT;
    v_cve_severity VARCHAR(20);
    v_cvss_v3_score DECIMAL(3,1);
    v_cve_published_date DATE;
    v_cve_modified_date DATE;
    v_device_name VARCHAR(200);
    v_brand_name VARCHAR(100);
    v_model_number VARCHAR(100);
    v_device_identifier VARCHAR(100);
    v_k_number VARCHAR(20);
    v_udi VARCHAR(100);
    v_ip_address INET;
    v_hostname VARCHAR(100);
    v_location VARCHAR(200);
    v_department VARCHAR(100);
BEGIN
    -- Get CVE information
    SELECT 
        description,
        severity,
        cvss_v3_score,
        published_date,
        last_modified_date
    INTO 
        v_cve_description,
        v_cve_severity,
        v_cvss_v3_score,
        v_cve_published_date,
        v_cve_modified_date
    FROM vulnerabilities 
    WHERE cve_id = p_cve_id;
    
    -- Get device and asset information
    SELECT 
        md.device_name,
        md.brand_name,
        md.model_number,
        md.device_identifier,
        md.k_number,
        md.udi,
        a.ip_address,
        a.hostname,
        COALESCE(a.location, l.location_name) as location,
        a.department
    INTO 
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_location,
        v_department
    FROM medical_devices md
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    WHERE md.device_id = p_device_id;
    
    -- Insert the task with original information
    INSERT INTO scheduled_tasks (
        task_type,
        cve_id,
        action_id,
        device_id,
        assigned_to,
        assigned_by,
        scheduled_date,
        estimated_downtime,
        task_description,
        notes,
        status,
        -- Original CVE information
        original_cve_id,
        original_cve_description,
        original_cve_severity,
        original_cvss_v3_score,
        original_cve_published_date,
        original_cve_modified_date,
        -- Original device information
        original_device_name,
        original_brand_name,
        original_model_number,
        original_device_identifier,
        original_k_number,
        original_udi,
        original_ip_address,
        original_hostname,
        original_location,
        original_department
    ) VALUES (
        'cve_remediation',
        p_cve_id,
        p_action_id,
        p_device_id,
        p_assigned_to,
        p_assigned_by,
        p_scheduled_date,
        p_estimated_downtime,
        p_task_description,
        p_notes,
        'Scheduled',
        -- Original CVE information
        p_cve_id,
        v_cve_description,
        v_cve_severity,
        v_cvss_v3_score,
        v_cve_published_date,
        v_cve_modified_date,
        -- Original device information
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_location,
        v_department
    ) RETURNING task_id INTO v_task_id;
    
    RETURN v_task_id;
END;
$$;
COMMENT ON FUNCTION public.assign_cve_remediation_task(p_cve_id character varying, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_task_description text, p_notes text, p_action_id uuid) IS 'Creates a new CVE remediation task assignment with original CVE and device information preserved for comprehensive tracking. Links task to remediation action if action_id is provided.';
CREATE FUNCTION public.assign_patch_application_task(p_patch_id uuid, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_task_description text DEFAULT NULL::text, p_notes text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_task_id UUID;
    v_patch_name VARCHAR(100);
    v_patch_type VARCHAR(50);
    v_patch_vendor VARCHAR(100);
    v_patch_version VARCHAR(50);
    v_patch_description TEXT;
    v_patch_release_date DATE;
    v_patch_requires_reboot BOOLEAN;
    v_target_package_id UUID;  -- Added
    v_device_name VARCHAR(200);
    v_brand_name VARCHAR(100);
    v_model_number VARCHAR(100);
    v_device_identifier VARCHAR(100);
    v_k_number VARCHAR(20);
    v_udi VARCHAR(100);
    v_ip_address INET;
    v_hostname VARCHAR(100);
    v_asset_tag VARCHAR(100);
    v_location VARCHAR(200);
    v_department VARCHAR(100);
    v_cve_list JSONB;
    v_cve_info TEXT;
BEGIN
    -- Get patch information including CVE list and target_package_id
    SELECT 
        patch_name,
        patch_type,
        vendor,
        target_version,
        description,
        release_date,
        requires_reboot,
        cve_list,
        target_package_id  -- Added
    INTO 
        v_patch_name,
        v_patch_type,
        v_patch_vendor,
        v_patch_version,
        v_patch_description,
        v_patch_release_date,
        v_patch_requires_reboot,
        v_cve_list,
        v_target_package_id  -- Added
    FROM patches 
    WHERE patch_id = p_patch_id;
    
    -- Get device and asset information
    SELECT 
        md.device_name,
        md.brand_name,
        md.model_number,
        md.device_identifier,
        md.k_number,
        md.udi,
        a.ip_address,
        a.hostname,
        a.asset_tag,
        COALESCE(a.location, l.location_name) as location,
        a.department
    INTO 
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_asset_tag,
        v_location,
        v_department
    FROM medical_devices md
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    WHERE md.device_id = p_device_id;
    
    -- Construct device name if not available
    IF v_device_name IS NULL OR v_device_name = '' THEN
        IF v_hostname IS NOT NULL AND v_hostname != '' THEN
            v_device_name := v_hostname;
        ELSIF v_brand_name IS NOT NULL THEN
            v_device_name := v_brand_name;
            IF v_model_number IS NOT NULL AND v_model_number != '' THEN
                v_device_name := v_device_name || ' ' || v_model_number;
            END IF;
        ELSE
            v_device_name := 'Unknown Device';
        END IF;
    END IF;
    
    -- Format CVE list as comma-separated string for display
    IF v_cve_list IS NOT NULL AND jsonb_array_length(v_cve_list) > 0 THEN
        v_cve_info := array_to_string(
            ARRAY(SELECT jsonb_array_elements_text(v_cve_list)), 
            ', '
        );
    ELSE
        v_cve_info := NULL;
    END IF;
    
    -- Insert the task with original information including CVE list and package_id
    INSERT INTO scheduled_tasks (
        task_type,
        patch_id,
        package_id,  -- Added
        device_id,
        assigned_to,
        assigned_by,
        scheduled_date,
        estimated_downtime,
        task_description,
        notes,
        status,
        -- Original patch information
        original_patch_name,
        original_patch_type,
        original_patch_vendor,
        original_patch_version,
        original_patch_description,
        original_patch_release_date,
        original_patch_requires_reboot,
        -- Original CVE information (from patch CVE list)
        original_cve_id,
        original_cve_description,
        original_cve_severity,
        original_cvss_v3_score,
        original_cve_published_date,
        original_cve_modified_date,
        -- Original device information
        original_device_name,
        original_brand_name,
        original_model_number,
        original_device_identifier,
        original_k_number,
        original_udi,
        original_ip_address,
        original_hostname,
        original_location,
        original_department
    ) VALUES (
        'patch_application',
        p_patch_id,
        v_target_package_id,  -- Added (can be NULL)
        p_device_id,
        p_assigned_to,
        p_assigned_by,
        p_scheduled_date,
        p_estimated_downtime,
        p_task_description,
        p_notes,
        'Scheduled',
        -- Original patch information
        v_patch_name,
        v_patch_type,
        v_patch_vendor,
        v_patch_version,
        v_patch_description,
        v_patch_release_date,
        v_patch_requires_reboot,
        -- Original CVE information (from patch CVE list)
        v_cve_info, -- Store CVE list as comma-separated string
        NULL, -- No separate description needed (same as CVE list)
        NULL, -- No single severity for multiple CVEs
        NULL, -- No single CVSS score for multiple CVEs
        NULL, -- No single published date for multiple CVEs
        NULL, -- No single modified date for multiple CVEs
        -- Original device information
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_location,
        v_department
    ) RETURNING task_id INTO v_task_id;
    
    RETURN v_task_id;
END;
$$;
COMMENT ON FUNCTION public.assign_patch_application_task(p_patch_id uuid, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_task_description text, p_notes text) IS 'Creates a new patch application task assignment with original patch, CVE list, device information, and package_id (from patches.target_package_id) preserved for comprehensive tracking';
CREATE FUNCTION public.assign_recall_maintenance_task(p_recall_id uuid, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_recall_priority character varying DEFAULT 'Medium'::character varying, p_remediation_type character varying DEFAULT 'Inspection'::character varying, p_task_description text DEFAULT NULL::text, p_notes text DEFAULT NULL::text, p_affected_serial_numbers text DEFAULT NULL::text, p_vendor_contact_required boolean DEFAULT false, p_fda_notification_required boolean DEFAULT false, p_patient_safety_impact boolean DEFAULT false) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_task_id UUID;
    v_recall_classification VARCHAR(50);
    v_fda_recall_number VARCHAR(50);
    v_manufacturer_name VARCHAR(100);
    v_product_description TEXT;
    v_recall_date DATE;
    v_reason_for_recall TEXT;
    v_product_code TEXT;
    v_recall_status VARCHAR(20);
    v_device_name VARCHAR(200);
    v_brand_name VARCHAR(100);
    v_model_number VARCHAR(100);
    v_device_identifier VARCHAR(100);
    v_k_number VARCHAR(20);
    v_udi VARCHAR(100);
    v_ip_address INET;
    v_hostname VARCHAR(100);
    v_location VARCHAR(200);
    v_department VARCHAR(100);
BEGIN
    -- Get recall information
    SELECT 
        recall_classification,
        fda_recall_number,
        manufacturer_name,
        product_description,
        recall_date,
        reason_for_recall,
        product_code,
        recall_status
    INTO 
        v_recall_classification,
        v_fda_recall_number,
        v_manufacturer_name,
        v_product_description,
        v_recall_date,
        v_reason_for_recall,
        v_product_code,
        v_recall_status
    FROM recalls 
    WHERE recall_id = p_recall_id;
    
    -- Get device and asset information
    SELECT 
        md.device_name,
        md.brand_name,
        md.model_number,
        md.device_identifier,
        md.k_number,
        md.udi,
        a.ip_address,
        a.hostname,
        COALESCE(a.location, l.location_name) as location,
        a.department
    INTO 
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_location,
        v_department
    FROM medical_devices md
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    WHERE md.device_id = p_device_id;
    
    -- Insert the task with original information
    INSERT INTO scheduled_tasks (
        task_type,
        recall_id,
        device_id,
        assigned_to,
        assigned_by,
        scheduled_date,
        estimated_downtime,
        recall_priority,
        recall_classification,
        remediation_type,
        task_description,
        notes,
        affected_serial_numbers,
        vendor_contact_required,
        fda_notification_required,
        patient_safety_impact,
        status,
        -- Original recall information
        original_fda_recall_number,
        original_manufacturer_name,
        original_product_description,
        original_recall_date,
        original_reason_for_recall,
        original_product_code,
        original_recall_status,
        -- Original device information
        original_device_name,
        original_brand_name,
        original_model_number,
        original_device_identifier,
        original_k_number,
        original_udi,
        original_ip_address,
        original_hostname,
        original_location,
        original_department
    ) VALUES (
        'recall_maintenance',
        p_recall_id,
        p_device_id,
        p_assigned_to,
        p_assigned_by,
        p_scheduled_date,
        p_estimated_downtime,
        p_recall_priority,
        v_recall_classification,
        p_remediation_type,
        p_task_description,
        p_notes,
        p_affected_serial_numbers,
        p_vendor_contact_required,
        p_fda_notification_required,
        p_patient_safety_impact,
        'Scheduled',
        -- Original recall information
        v_fda_recall_number,
        v_manufacturer_name,
        v_product_description,
        v_recall_date,
        v_reason_for_recall,
        v_product_code,
        v_recall_status,
        -- Original device information
        v_device_name,
        v_brand_name,
        v_model_number,
        v_device_identifier,
        v_k_number,
        v_udi,
        v_ip_address,
        v_hostname,
        v_location,
        v_department
    ) RETURNING task_id INTO v_task_id;
    
    RETURN v_task_id;
END;
$$;
COMMENT ON FUNCTION public.assign_recall_maintenance_task(p_recall_id uuid, p_device_id uuid, p_assigned_to uuid, p_assigned_by uuid, p_scheduled_date timestamp without time zone, p_estimated_downtime integer, p_recall_priority character varying, p_remediation_type character varying, p_task_description text, p_notes text, p_affected_serial_numbers text, p_vendor_contact_required boolean, p_fda_notification_required boolean, p_patient_safety_impact boolean) IS 'Creates a new recall maintenance task assignment with original recall and device information preserved for comprehensive tracking';
CREATE FUNCTION public.calculate_action_efficiency_score(p_action_id uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    total_score INTEGER := 0;
BEGIN
    SELECT COALESCE(SUM(device_risk_score), 0)
    INTO total_score
    FROM action_device_links
    WHERE action_id = p_action_id;
    
    RETURN total_score;
END;
$$;
CREATE FUNCTION public.calculate_action_urgency_score(p_action_id uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    max_score INTEGER := 0;
BEGIN
    SELECT COALESCE(MAX(device_risk_score), 0)
    INTO max_score
    FROM action_device_links
    WHERE action_id = p_action_id;
    
    RETURN max_score;
END;
$$;
CREATE FUNCTION public.calculate_device_risk_score(p_device_id uuid, p_config record) RETURNS integer
    LANGUAGE plpgsql
    AS $$
    DECLARE
        risk_score INTEGER := 0;
        asset_data RECORD;
        vulnerability_data RECORD;
    BEGIN
        -- Get asset data for this device
        SELECT a.criticality, l.criticality as location_criticality
        INTO asset_data
        FROM medical_devices md
        JOIN assets a ON md.asset_id = a.asset_id
        LEFT JOIN locations l ON a.location_id = l.location_id
        WHERE md.device_id = p_device_id;
        -- Get vulnerability data for this device
        SELECT
            v.severity,
            v.is_kev,
            v.epss_score
        INTO vulnerability_data
        FROM device_vulnerabilities_link dvl
        JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        WHERE dvl.device_id = p_device_id
        ORDER BY
            CASE v.severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5  -- Handle unknown severity values
            END,
            v.cvss_v3_score DESC
        LIMIT 1;
        -- Calculate base risk score components
        -- KEV bonus
        IF vulnerability_data.is_kev THEN
            risk_score := risk_score + p_config.kev_weight;
        END IF;
        -- Asset criticality score
        CASE asset_data.criticality
            WHEN 'Clinical-High' THEN
                risk_score := risk_score + p_config.clinical_high_score;
            WHEN 'Business-Medium' THEN
                risk_score := risk_score + p_config.business_medium_score;
            WHEN 'Non-Essential' THEN
                risk_score := risk_score + p_config.non_essential_score;
            ELSE
                -- Handle unknown criticality values - use default score
                risk_score := risk_score + p_config.non_essential_score;
        END CASE;
        -- Location criticality score
        IF asset_data.location_criticality IS NOT NULL THEN
            risk_score := risk_score + ROUND(asset_data.location_criticality * p_config.location_weight_multiplier);
        END IF;
        -- Vulnerability severity score
        IF vulnerability_data.severity IS NOT NULL THEN
            CASE vulnerability_data.severity
                WHEN 'Critical' THEN
                    risk_score := risk_score + p_config.critical_severity_score;
                WHEN 'High' THEN
                    risk_score := risk_score + p_config.high_severity_score;
                WHEN 'Medium' THEN
                    risk_score := risk_score + p_config.medium_severity_score;
                WHEN 'Low' THEN
                    risk_score := risk_score + p_config.low_severity_score;
                ELSE
                    -- Handle unknown severity values - use low severity score as default
                    risk_score := risk_score + p_config.low_severity_score;
            END CASE;
        END IF;
        -- EPSS bonus
        IF p_config.epss_weight_enabled AND vulnerability_data.epss_score IS NOT NULL THEN
            IF vulnerability_data.epss_score >= p_config.epss_high_threshold THEN
                risk_score := risk_score + p_config.epss_weight_score;
            END IF;
        END IF;
        RETURN COALESCE(risk_score, 0);
    END;
$$;
CREATE FUNCTION public.calculate_priority_tier(p_link_id uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_tier INTEGER;
BEGIN
    SELECT 
        CASE 
            WHEN v.is_kev = TRUE THEN 1
            WHEN a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) >= 8 
                 AND v.severity IN ('Critical', 'High') THEN 2
            ELSE 3
        END INTO v_tier
    FROM device_vulnerabilities_link dvl
    JOIN medical_devices md ON dvl.device_id = md.device_id
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
    WHERE dvl.link_id = p_link_id;
    
    RETURN v_tier;
END;
$$;
CREATE FUNCTION public.calculate_risk_based_tier(risk_score integer, is_kev boolean) RETURNS integer
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Tier 1: Very high risk (score >= 1000) OR KEV with high risk (score >= 180)
    IF risk_score >= 1000 OR (is_kev = TRUE AND risk_score >= 180) THEN
        RETURN 1;
    END IF;
    
    -- Tier 2: High risk (score >= 180 AND < 1000) OR KEV with medium risk (score >= 160)
    IF risk_score >= 180 OR (is_kev = TRUE AND risk_score >= 160) THEN
        RETURN 2;
    END IF;
    
    -- Tier 3: Medium risk (score >= 160 AND < 180)
    IF risk_score >= 160 THEN
        RETURN 3;
    END IF;
    
    -- Tier 4: Low risk (score < 160)
    RETURN 4;
END;
$$;
CREATE FUNCTION public.calculate_risk_score(p_link_id uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_score INTEGER;
    epss_weight INTEGER;
    epss_threshold DECIMAL(5,4);
    epss_enabled BOOLEAN;
BEGIN
    -- Get EPSS configuration
    SELECT epss_weight_enabled, epss_high_threshold, epss_weight_score
    INTO epss_enabled, epss_threshold, epss_weight
    FROM risk_matrix_config 
    WHERE is_active = TRUE 
    ORDER BY created_at DESC 
    LIMIT 1;
    
    -- Default values if no config found
    epss_enabled := COALESCE(epss_enabled, TRUE);
    epss_threshold := COALESCE(epss_threshold, 0.7000);
    epss_weight := COALESCE(epss_weight, 20);
    
    SELECT 
        (CASE 
            WHEN v.is_kev = TRUE THEN 1000
            ELSE 0
        END +
        CASE a.criticality 
            WHEN 'Clinical-High' THEN 100
            WHEN 'Business-Medium' THEN 50
            WHEN 'Non-Essential' THEN 10
            ELSE 0
        END +
        COALESCE(l.criticality * 5, 0) +
        CASE v.severity
            WHEN 'Critical' THEN 40
            WHEN 'High' THEN 28
            WHEN 'Medium' THEN 16
            WHEN 'Low' THEN 4
            ELSE 0
        END +
        -- EPSS component
        CASE 
            WHEN epss_enabled = TRUE AND v.epss_score >= epss_threshold THEN epss_weight
            ELSE 0
        END) INTO v_score
    FROM device_vulnerabilities_link dvl
    JOIN medical_devices md ON dvl.device_id = md.device_id
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
    WHERE dvl.link_id = p_link_id;
    
    RETURN v_score;
END;
$$;
CREATE FUNCTION public.check_ip_range_overlap(p_location_id uuid, p_cidr_notation cidr DEFAULT NULL::cidr, p_start_ip inet DEFAULT NULL::inet, p_end_ip inet DEFAULT NULL::inet) RETURNS TABLE(overlapping_location_id uuid, overlapping_location_name character varying, overlapping_location_code character varying, overlap_type character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Check CIDR overlaps
    IF p_cidr_notation IS NOT NULL THEN
        RETURN QUERY
        SELECT DISTINCT
            l.location_id,
            l.location_name,
            l.location_code,
            'CIDR'::VARCHAR(20) as overlap_type
        FROM locations l
        JOIN location_ip_ranges lir ON l.location_id = lir.location_id
        WHERE l.location_id != p_location_id
        AND l.is_active = TRUE
        AND (
            (lir.range_format = 'CIDR' AND lir.cidr_notation && p_cidr_notation) OR
            (lir.range_format = 'StartEnd' AND lir.start_ip <= p_cidr_notation AND lir.end_ip >= p_cidr_notation)
        );
    END IF;
    
    -- Check StartEnd overlaps
    IF p_start_ip IS NOT NULL AND p_end_ip IS NOT NULL THEN
        RETURN QUERY
        SELECT DISTINCT
            l.location_id,
            l.location_name,
            l.location_code,
            'StartEnd'::VARCHAR(20) as overlap_type
        FROM locations l
        JOIN location_ip_ranges lir ON l.location_id = lir.location_id
        WHERE l.location_id != p_location_id
        AND l.is_active = TRUE
        AND (
            (lir.range_format = 'CIDR' AND lir.cidr_notation && inet_range(p_start_ip, p_end_ip)) OR
            (lir.range_format = 'StartEnd' AND lir.start_ip <= p_end_ip AND lir.end_ip >= p_start_ip)
        );
    END IF;
    
    RETURN;
END;
$$;
CREATE FUNCTION public.complete_scheduled_task(p_task_id uuid, p_completion_notes text, p_actual_downtime integer, p_completed_by uuid) RETURNS json
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_task RECORD;
    v_original_task RECORD;
    v_updated_patches INTEGER := 0;
    v_updated_cves INTEGER := 0;
    v_updated_recalls INTEGER := 0;
    v_completed_tasks INTEGER := 0;
    v_cve_list JSONB;
    v_total_devices INTEGER;
    v_completed_devices INTEGER;
    v_action_id_to_update UUID;
BEGIN
    -- Load task (lock it first with FOR UPDATE)
    SELECT st.*
      INTO v_task
      FROM scheduled_tasks st
     WHERE st.task_id = p_task_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Task % not found', p_task_id;
    END IF;
    
    -- Get CVE list from patch if patch_id exists (separate query, no FOR UPDATE needed)
    IF v_task.patch_id IS NOT NULL THEN
        SELECT cve_list INTO v_cve_list
        FROM patches
        WHERE patch_id = v_task.patch_id;
    END IF;
    -- Update task completion fields
    UPDATE scheduled_tasks
       SET status = 'Completed',
           completed_at = CURRENT_TIMESTAMP,
           implementation_date = COALESCE(implementation_date, CURRENT_TIMESTAMP),
           completion_notes = COALESCE(p_completion_notes, completion_notes),
           actual_downtime = COALESCE(p_actual_downtime, actual_downtime),
           completed_by = p_completed_by,
           updated_at = CURRENT_TIMESTAMP
     WHERE task_id = p_task_id;
    -- Cascade by task type (device-specific)
    IF v_task.task_type = 'patch_application' THEN
        -- Mark patch applied for device
        UPDATE patches
           SET applied_devices = COALESCE(applied_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
         WHERE patch_id = v_task.patch_id;
        v_updated_patches := 1;
        -- If patch has CVE list, mark each CVE as patched for the device
        IF v_cve_list IS NOT NULL AND jsonb_typeof(v_cve_list) = 'array' THEN
            UPDATE vulnerabilities v
               SET patched_devices = COALESCE(v.patched_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
              FROM (
                SELECT jsonb_array_elements_text(v_cve_list) AS cve_id
              ) c
             WHERE v.cve_id = c.cve_id;
            -- approximate count
            v_updated_cves := COALESCE(jsonb_array_length(v_cve_list), 0);
        END IF;
        
        -- Update action_device_links if task is linked to a remediation action
        -- If action_id is not set, try to find it from cve_id and device_id
        -- Get action_id from task or find it by cve_id and device_id
        v_action_id_to_update := v_task.action_id;
        IF v_action_id_to_update IS NULL AND v_task.cve_id IS NOT NULL THEN
            -- Try to find the action_id from remediation_actions that matches this CVE
            SELECT ra.action_id INTO v_action_id_to_update
            FROM remediation_actions ra
            WHERE ra.cve_id = v_task.cve_id
              AND EXISTS (
                  SELECT 1 FROM action_device_links adl 
                  WHERE adl.action_id = ra.action_id 
                    AND adl.device_id = v_task.device_id
              )
            LIMIT 1;
        END IF;
        
        -- If we have an action_id (from task or lookup), update action_device_links
        IF v_action_id_to_update IS NOT NULL THEN
            UPDATE action_device_links
               SET patch_status = 'Completed',
                   patched_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
             WHERE action_id = v_action_id_to_update
               AND device_id = v_task.device_id
               AND patch_status != 'Completed';
            
            -- Also update the task's action_id if it was NULL (for future reference)
            IF v_task.action_id IS NULL THEN
                UPDATE scheduled_tasks
                   SET action_id = v_action_id_to_update
                 WHERE task_id = p_task_id;
            END IF;
            
            -- Check if all devices for this action are completed
            SELECT COUNT(*), COUNT(*) FILTER (WHERE patch_status = 'Completed')
              INTO v_total_devices, v_completed_devices
              FROM action_device_links
             WHERE action_id = v_action_id_to_update;
            
            -- If all devices are completed, mark the remediation action as Completed
            IF v_completed_devices > 0 AND v_completed_devices = v_total_devices THEN
                UPDATE remediation_actions
                   SET status = 'Completed',
                       completed_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE action_id = v_action_id_to_update
                   AND status != 'Completed';
            ELSIF v_completed_devices > 0 AND v_completed_devices < v_total_devices THEN
                -- Some devices completed but not all - mark as In Progress
                UPDATE remediation_actions
                   SET status = 'In Progress',
                       updated_at = CURRENT_TIMESTAMP
                 WHERE action_id = v_action_id_to_update
                   AND status = 'Pending';
            END IF;
        END IF;
    ELSIF v_task.task_type = 'cve_remediation' THEN
        -- Single CVE remediated for device
        UPDATE vulnerabilities
           SET patched_devices = COALESCE(patched_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
         WHERE cve_id = v_task.cve_id;
        v_updated_cves := 1;
        
        -- Update device_vulnerabilities_link to mark as Resolved for this device
        UPDATE device_vulnerabilities_link
           SET remediation_status = 'Resolved',
               updated_at = CURRENT_TIMESTAMP
         WHERE device_id = v_task.device_id
           AND cve_id = v_task.cve_id
           AND remediation_status != 'Resolved';
        
        -- Update action_device_links if task is linked to a remediation action
        -- If action_id is not set, try to find it from cve_id and device_id
        -- Get action_id from task or find it by cve_id and device_id
        v_action_id_to_update := v_task.action_id;
        IF v_action_id_to_update IS NULL AND v_task.cve_id IS NOT NULL THEN
            -- Try to find the action_id from remediation_actions that matches this CVE
            SELECT ra.action_id INTO v_action_id_to_update
            FROM remediation_actions ra
            WHERE ra.cve_id = v_task.cve_id
              AND EXISTS (
                  SELECT 1 FROM action_device_links adl 
                  WHERE adl.action_id = ra.action_id 
                    AND adl.device_id = v_task.device_id
              )
            LIMIT 1;
        END IF;
        
        -- If we have an action_id (from task or lookup), update action_device_links
        IF v_action_id_to_update IS NOT NULL THEN
            UPDATE action_device_links
               SET patch_status = 'Completed',
                   patched_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
             WHERE action_id = v_action_id_to_update
               AND device_id = v_task.device_id
               AND patch_status != 'Completed';
            
            -- Also update the task's action_id if it was NULL (for future reference)
            IF v_task.action_id IS NULL THEN
                UPDATE scheduled_tasks
                   SET action_id = v_action_id_to_update
                 WHERE task_id = p_task_id;
            END IF;
            
            -- Check if all devices for this action are completed
            SELECT COUNT(*), COUNT(*) FILTER (WHERE patch_status = 'Completed')
              INTO v_total_devices, v_completed_devices
              FROM action_device_links
             WHERE action_id = v_action_id_to_update;
            
            -- If all devices are completed, mark the remediation action as Completed
            IF v_completed_devices > 0 AND v_completed_devices = v_total_devices THEN
                UPDATE remediation_actions
                   SET status = 'Completed',
                       completed_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE action_id = v_action_id_to_update
                   AND status != 'Completed';
            ELSIF v_completed_devices > 0 AND v_completed_devices < v_total_devices THEN
                -- Some devices completed but not all - mark as In Progress
                UPDATE remediation_actions
                   SET status = 'In Progress',
                       updated_at = CURRENT_TIMESTAMP
                 WHERE action_id = v_action_id_to_update
                   AND status = 'Pending';
            END IF;
        END IF;
    ELSIF v_task.task_type = 'recall_maintenance' THEN
        -- Mark recall resolved for device
        UPDATE device_recalls_link drl
           SET remediation_status = 'Resolved',
               remediation_date = CURRENT_TIMESTAMP
         WHERE drl.device_id = v_task.device_id
           AND drl.recall_id = v_task.recall_id;
        GET DIAGNOSTICS v_updated_recalls = ROW_COUNT;
    ELSIF v_task.task_type = 'package_remediation' THEN
        -- Packages are consolidated/rollup tasks - complete all associated tasks
        -- First, mark package-level remediation if package_id is set
        IF v_task.package_id IS NOT NULL THEN
            UPDATE software_packages
               SET remediated_devices = COALESCE(remediated_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
             WHERE package_id = v_task.package_id;
            -- Also mark any known package versions (if present) as remediated for this device
            UPDATE software_package_versions spv
               SET remediated_devices = COALESCE(remediated_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
             WHERE spv.package_id = v_task.package_id;
            v_updated_patches := 1;
            
            -- Mark all CVEs associated with this package as patched for the device
            UPDATE vulnerabilities v
               SET patched_devices = COALESCE(v.patched_devices, '[]'::jsonb) || to_jsonb(v_task.device_id::text)
             WHERE v.cve_id IN (
                 SELECT DISTINCT spv.cve_id 
                 FROM software_package_vulnerabilities spv 
                 WHERE spv.package_id = v_task.package_id
             );
            -- Count updated CVEs from package
            SELECT COUNT(DISTINCT cve_id) INTO v_updated_cves
            FROM software_package_vulnerabilities 
            WHERE package_id = v_task.package_id;
        END IF;
        
        -- Find all tasks consolidated into this package task
        FOR v_original_task IN 
            SELECT st.*, p.cve_list as patch_cve_list
            FROM task_consolidation_mapping tcm
            JOIN scheduled_tasks st ON tcm.original_task_id = st.task_id
            LEFT JOIN patches p ON st.patch_id = p.patch_id
            WHERE tcm.consolidated_task_id = p_task_id
              AND st.status NOT IN ('Completed', 'Cancelled')
        LOOP
            -- Mark original task as Completed
            UPDATE scheduled_tasks
               SET status = 'Completed',
                   completed_at = CURRENT_TIMESTAMP,
                   implementation_date = COALESCE(implementation_date, CURRENT_TIMESTAMP),
                   completion_notes = COALESCE(p_completion_notes, completion_notes),
                   actual_downtime = COALESCE(p_actual_downtime, actual_downtime),
                   completed_by = p_completed_by,
                   updated_at = CURRENT_TIMESTAMP
             WHERE task_id = v_original_task.task_id;
            
            v_completed_tasks := v_completed_tasks + 1;
            
            -- Cascade based on original task type (device-specific)
            IF v_original_task.task_type = 'patch_application' AND v_original_task.patch_id IS NOT NULL THEN
                -- Mark patch applied for device
                UPDATE patches
                   SET applied_devices = COALESCE(applied_devices, '[]'::jsonb) || to_jsonb(v_original_task.device_id::text)
                 WHERE patch_id = v_original_task.patch_id;
                
                -- Mark all CVEs in patch as patched for device
                IF v_original_task.patch_cve_list IS NOT NULL AND jsonb_typeof(v_original_task.patch_cve_list) = 'array' THEN
                    UPDATE vulnerabilities v
                       SET patched_devices = COALESCE(v.patched_devices, '[]'::jsonb) || to_jsonb(v_original_task.device_id::text)
                     FROM (
                       SELECT jsonb_array_elements_text(v_original_task.patch_cve_list) AS cve_id
                     ) c
                     WHERE v.cve_id = c.cve_id;
                    v_updated_cves := v_updated_cves + COALESCE(jsonb_array_length(v_original_task.patch_cve_list), 0);
                END IF;
                
            ELSIF v_original_task.task_type = 'cve_remediation' AND v_original_task.cve_id IS NOT NULL THEN
                -- Mark CVE as patched for device
                UPDATE vulnerabilities
                   SET patched_devices = COALESCE(patched_devices, '[]'::jsonb) || to_jsonb(v_original_task.device_id::text)
                 WHERE cve_id = v_original_task.cve_id;
                v_updated_cves := v_updated_cves + 1;
                
                -- Update device_vulnerabilities_link to mark as Resolved for this device
                UPDATE device_vulnerabilities_link
                   SET remediation_status = 'Resolved',
                       updated_at = CURRENT_TIMESTAMP
                 WHERE device_id = v_original_task.device_id
                   AND cve_id = v_original_task.cve_id
                   AND remediation_status != 'Resolved';
                
            ELSIF v_original_task.task_type = 'recall_maintenance' THEN
                -- Mark recall resolved for device
                UPDATE device_recalls_link drl
                   SET remediation_status = 'Resolved',
                       remediation_date = CURRENT_TIMESTAMP
                 WHERE drl.device_id = v_original_task.device_id
                   AND drl.recall_id = v_original_task.recall_id;
                v_updated_recalls := v_updated_recalls + 1;
            END IF;
        END LOOP;
    END IF;
    RETURN json_build_object(
        'task_id', p_task_id,
        'device_id', v_task.device_id,
        'task_type', v_task.task_type,
        'updated_patches', v_updated_patches,
        'updated_cves', v_updated_cves,
        'updated_recalls', v_updated_recalls,
        'completed_tasks', CASE WHEN v_task.task_type = 'package_remediation' THEN v_completed_tasks ELSE 0 END
    );
END;
$$;
CREATE FUNCTION public.determine_action_tier(p_urgency_score integer, p_kev_count integer) RETURNS integer
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Tier 1: Very high urgency OR KEV with high urgency
    IF p_urgency_score >= 1000 OR (p_kev_count > 0 AND p_urgency_score >= 180) THEN
        RETURN 1;
    END IF;
    
    -- Tier 2: High urgency OR KEV with medium urgency
    IF p_urgency_score >= 180 OR (p_kev_count > 0 AND p_urgency_score >= 160) THEN
        RETURN 2;
    END IF;
    
    -- Tier 3: Medium urgency
    IF p_urgency_score >= 160 THEN
        RETURN 3;
    END IF;
    
    -- Tier 4: Low urgency
    RETURN 4;
END;
$$;
CREATE FUNCTION public.find_location_by_ip(p_ip_address inet) RETURNS TABLE(location_id uuid, location_name character varying, location_code character varying, hierarchy_path text, criticality integer, range_id uuid, range_format character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        l.location_id,
        l.location_name,
        l.location_code,
        lh.hierarchy_path,
        l.criticality,
        lir.range_id,
        lir.range_format
    FROM locations l
    JOIN location_hierarchy lh ON l.location_id = lh.location_id
    JOIN location_ip_ranges lir ON l.location_id = lir.location_id
    WHERE l.is_active = TRUE
    AND (
        (lir.range_format = 'CIDR' AND p_ip_address << lir.cidr_notation) OR
        (lir.range_format = 'StartEnd' AND p_ip_address >= lir.start_ip AND p_ip_address <= lir.end_ip)
    )
    ORDER BY 
        -- Prefer most specific CIDR (smallest network)
        CASE WHEN lir.range_format = 'CIDR' THEN masklen(lir.cidr_notation) ELSE 0 END DESC,
        -- Then by criticality (highest first)
        l.criticality DESC;
END;
$$;
CREATE FUNCTION public.get_epss_trend_data(p_cve_id character varying, p_days integer DEFAULT 30) RETURNS TABLE(recorded_date date, epss_score numeric, epss_percentile numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        h.recorded_date,
        h.epss_score,
        h.epss_percentile
    FROM epss_score_history h
    WHERE h.cve_id = p_cve_id
      AND h.recorded_date >= (CURRENT_DATE - INTERVAL '1 day' * p_days)
    ORDER BY h.recorded_date ASC;
END;
$$;
CREATE FUNCTION public.get_recall_maintenance_stats() RETURNS TABLE(total_tasks bigint, scheduled_tasks bigint, in_progress_tasks bigint, completed_tasks bigint, cancelled_tasks bigint, failed_tasks bigint, critical_priority_tasks bigint, high_priority_tasks bigint, medium_priority_tasks bigint, low_priority_tasks bigint, patient_safety_tasks bigint, overdue_tasks bigint, avg_completion_time_hours numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_tasks,
        COUNT(*) FILTER (WHERE st.status = 'Scheduled') as scheduled_tasks,
        COUNT(*) FILTER (WHERE st.status = 'In Progress') as in_progress_tasks,
        COUNT(*) FILTER (WHERE st.status = 'Completed') as completed_tasks,
        COUNT(*) FILTER (WHERE st.status = 'Cancelled') as cancelled_tasks,
        COUNT(*) FILTER (WHERE st.status = 'Failed') as failed_tasks,
        COUNT(*) FILTER (WHERE st.recall_priority = 'Critical') as critical_priority_tasks,
        COUNT(*) FILTER (WHERE st.recall_priority = 'High') as high_priority_tasks,
        COUNT(*) FILTER (WHERE st.recall_priority = 'Medium') as medium_priority_tasks,
        COUNT(*) FILTER (WHERE st.recall_priority = 'Low') as low_priority_tasks,
        COUNT(*) FILTER (WHERE st.patient_safety_impact = true) as patient_safety_tasks,
        COUNT(*) FILTER (WHERE st.scheduled_date < CURRENT_TIMESTAMP AND st.status IN ('Scheduled', 'In Progress')) as overdue_tasks,
        ROUND(AVG(EXTRACT(EPOCH FROM (st.completed_at - st.created_at)) / 3600)::numeric, 2) as avg_completion_time_hours
    FROM scheduled_tasks st
    WHERE st.task_type = 'recall_maintenance';
END;
$$;
CREATE FUNCTION public.get_tier1_vulnerabilities() RETURNS TABLE(link_id uuid, cve_id character varying, is_kev boolean, calculated_risk_score integer, priority_tier integer, asset_criticality character varying, location_criticality character varying, severity character varying, epss_score numeric, epss_percentile numeric, remediation_status character varying, created_at timestamp without time zone, updated_at timestamp without time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rpv.link_id,
        rpv.cve_id,
        rpv.is_kev,
        rpv.calculated_risk_score,
        rpv.priority_tier,
        rpv.asset_criticality,
        rpv.location_criticality,
        rpv.severity,
        v.epss_score,
        v.epss_percentile,
        rpv.remediation_status,
        rpv.created_at,
        rpv.updated_at
    FROM risk_priority_view rpv
    LEFT JOIN vulnerabilities v ON rpv.cve_id = v.cve_id
    WHERE rpv.priority_tier = 1
    ORDER BY rpv.calculated_risk_score DESC;
END;
$$;
CREATE FUNCTION public.get_tier2_vulnerabilities() RETURNS TABLE(link_id uuid, cve_id character varying, is_kev boolean, calculated_risk_score integer, priority_tier integer, asset_criticality character varying, location_criticality character varying, severity character varying, epss_score numeric, epss_percentile numeric, remediation_status character varying, created_at timestamp without time zone, updated_at timestamp without time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rpv.link_id,
        rpv.cve_id,
        rpv.is_kev,
        rpv.calculated_risk_score,
        rpv.priority_tier,
        rpv.asset_criticality,
        rpv.location_criticality,
        rpv.severity,
        v.epss_score,
        v.epss_percentile,
        rpv.remediation_status,
        rpv.created_at,
        rpv.updated_at
    FROM risk_priority_view rpv
    LEFT JOIN vulnerabilities v ON rpv.cve_id = v.cve_id
    WHERE rpv.priority_tier = 2
    ORDER BY rpv.calculated_risk_score DESC;
END;
$$;
CREATE FUNCTION public.get_tier_promotion_candidates() RETURNS TABLE(link_id uuid, cve_id character varying, is_kev boolean, calculated_risk_score integer, current_tier integer, recommended_tier integer, promotion_reason text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rpv.link_id,
        rpv.cve_id,
        rpv.is_kev,
        rpv.calculated_risk_score,
        rpv.priority_tier as current_tier,
        calculate_risk_based_tier(rpv.calculated_risk_score, rpv.is_kev) as recommended_tier,
        CASE 
            WHEN rpv.priority_tier != calculate_risk_based_tier(rpv.calculated_risk_score, rpv.is_kev) THEN
                'Risk score ' || rpv.calculated_risk_score || ' suggests tier ' || calculate_risk_based_tier(rpv.calculated_risk_score, rpv.is_kev)
            ELSE NULL
        END as promotion_reason
    FROM risk_priority_view rpv
    WHERE rpv.priority_tier != calculate_risk_based_tier(rpv.calculated_risk_score, rpv.is_kev)
    ORDER BY rpv.calculated_risk_score DESC;
END;
$$;
CREATE FUNCTION public.get_tier_statistics() RETURNS TABLE(tier integer, count bigint, percentage numeric, min_score integer, max_score integer, kev_count bigint, non_kev_count bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rpv.priority_tier,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM risk_priority_view), 1) as percentage,
        MIN(rpv.calculated_risk_score) as min_score,
        MAX(rpv.calculated_risk_score) as max_score,
        COUNT(*) FILTER (WHERE rpv.is_kev = TRUE) as kev_count,
        COUNT(*) FILTER (WHERE rpv.is_kev = FALSE) as non_kev_count
    FROM risk_priority_view rpv
    GROUP BY rpv.priority_tier
    ORDER BY rpv.priority_tier;
END;
$$;
CREATE FUNCTION public.invalidate_dashboard_cache() RETURNS void
    LANGUAGE plpgsql
    AS $$
    BEGIN
        -- This function can be called to invalidate dashboard cache
        -- when risk scores are updated
        PERFORM 1; -- Placeholder for future cache invalidation logic
    END;
    $$;
CREATE FUNCTION public.log_tier_change(p_link_id uuid, p_cve_id character varying, p_old_tier integer, p_new_tier integer, p_change_reason character varying, p_changed_by character varying, p_risk_score integer, p_is_kev boolean) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO tier_change_audit (
        link_id, cve_id, old_tier, new_tier, change_reason, 
        changed_by, risk_score, is_kev
    ) VALUES (
        p_link_id, p_cve_id, p_old_tier, p_new_tier, p_change_reason,
        p_changed_by, p_risk_score, p_is_kev
    );
END;
$$;
CREATE FUNCTION public.preserve_completed_tasks_on_device_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Before deleting the device, set device_id to NULL for completed tasks
    -- This preserves the historical record of completed tasks
    UPDATE public.scheduled_tasks
    SET device_id = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE device_id = OLD.device_id
      AND status = 'Completed';
    
    -- Return OLD to allow the device deletion to proceed
    -- Non-completed tasks will have device_id set to NULL by the foreign key constraint (ON DELETE SET NULL)
    RETURN OLD;
END;
$$;
COMMENT ON FUNCTION public.preserve_completed_tasks_on_device_delete() IS 'Preserves completed scheduled tasks when medical devices are deleted by setting device_id to NULL before deletion. Non-completed tasks will have device_id set to NULL by the foreign key constraint (ON DELETE SET NULL).';
CREATE FUNCTION public.promote_tier2_to_tier1() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    tier1_count INTEGER;
    promoted_count INTEGER := 0;
BEGIN
    -- Check if Tier 1 has < 5 vulnerabilities
    SELECT COUNT(*) INTO tier1_count 
    FROM risk_priority_view 
    WHERE priority_tier = 1;
    
    -- Promote highest risk from Tier 2 if Tier 1 is low
    IF tier1_count < 5 THEN
        UPDATE risk_priority_view 
        SET priority_tier = 1 
        WHERE link_id IN (
            SELECT link_id 
            FROM risk_priority_view 
            WHERE priority_tier = 2 
            ORDER BY calculated_risk_score DESC 
            LIMIT 5
        );
        
        GET DIAGNOSTICS promoted_count = ROW_COUNT;
        
        -- Log the promotion
        INSERT INTO epss_sync_log (sync_date, status, message, records_processed)
        VALUES (CURRENT_DATE, 'success', 'Promoted ' || promoted_count || ' vulnerabilities from Tier 2 to Tier 1', promoted_count);
    END IF;
    
    RETURN promoted_count;
END;
$$;
CREATE FUNCTION public.promote_vulnerability_to_tier1(vuln_link_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_tier INTEGER;
    current_score INTEGER;
    current_kev BOOLEAN;
BEGIN
    -- Get current tier, score, and KEV status
    SELECT priority_tier, calculated_risk_score, is_kev
    INTO current_tier, current_score, current_kev
    FROM risk_priority_view
    WHERE link_id = vuln_link_id;
    
    -- Check if vulnerability exists
    IF current_tier IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Promote to Tier 1
    UPDATE risk_priority_view 
    SET priority_tier = 1
    WHERE link_id = vuln_link_id;
    
    -- Log the manual promotion
    INSERT INTO epss_sync_log (sync_date, status, message, records_processed)
    VALUES (CURRENT_DATE, 'success', 'Manually promoted vulnerability ' || vuln_link_id || ' to Tier 1', 1);
    
    RETURN TRUE;
END;
$$;
CREATE FUNCTION public.recalculate_action_urgency_score(action_uuid uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    config_record RECORD;
    action_record RECORD;
    calculated_score INTEGER := 0;
    calculated_efficiency INTEGER := 100;
BEGIN
    -- Get current risk matrix configuration
    SELECT * INTO config_record 
    FROM risk_matrix_config 
    WHERE is_active = TRUE 
    ORDER BY created_at DESC 
    LIMIT 1;
    
    -- Get action data
    SELECT 
        ra.action_id,
        v.cve_id,
        v.severity,
        v.is_kev,
        v.epss_score,
        a.criticality as asset_criticality,
        l.criticality as location_criticality,
        adl.device_risk_score,
        ra.action_type
    INTO action_record
    FROM remediation_actions ra
    LEFT JOIN vulnerabilities v ON ra.cve_id = v.cve_id
    LEFT JOIN action_device_links adl ON ra.action_id = adl.action_id
    LEFT JOIN medical_devices md ON adl.device_id = md.device_id
    LEFT JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    WHERE ra.action_id = action_uuid;
    
    -- Skip if no configuration or action data
    IF config_record IS NULL OR action_record IS NULL THEN
        RETURN;
    END IF;
    
    -- Calculate urgency score
    calculated_score := COALESCE(action_record.device_risk_score, 0);
    
    -- KEV weight
    IF action_record.is_kev THEN
        calculated_score := calculated_score + config_record.kev_weight;
    END IF;
    
    -- Asset criticality scoring
    IF action_record.asset_criticality = 'Clinical-High' THEN
        calculated_score := calculated_score + config_record.clinical_high_score;
    ELSIF action_record.asset_criticality = 'Business-Medium' THEN
        calculated_score := calculated_score + config_record.business_medium_score;
    ELSIF action_record.asset_criticality = 'Non-Essential' THEN
        calculated_score := calculated_score + config_record.non_essential_score;
    END IF;
    
    -- Location criticality multiplier (integer 1-10)
    IF action_record.location_criticality IS NOT NULL THEN
        IF action_record.location_criticality >= 9 THEN
            calculated_score := calculated_score * config_record.location_weight_multiplier;
        ELSIF action_record.location_criticality >= 7 THEN
            calculated_score := calculated_score * (config_record.location_weight_multiplier * 0.8);
        ELSIF action_record.location_criticality >= 5 THEN
            calculated_score := calculated_score * (config_record.location_weight_multiplier * 0.6);
        END IF;
    END IF;
    
    -- Vulnerability severity scoring
    IF action_record.severity = 'Critical' THEN
        calculated_score := calculated_score + config_record.critical_severity_score;
    ELSIF action_record.severity = 'High' THEN
        calculated_score := calculated_score + config_record.high_severity_score;
    ELSIF action_record.severity = 'Medium' THEN
        calculated_score := calculated_score + config_record.medium_severity_score;
    ELSIF action_record.severity = 'Low' THEN
        calculated_score := calculated_score + config_record.low_severity_score;
    END IF;
    
    -- EPSS scoring
    IF config_record.epss_weight_enabled AND action_record.epss_score IS NOT NULL THEN
        IF action_record.epss_score >= config_record.epss_high_threshold THEN
            calculated_score := calculated_score + config_record.epss_weight_score;
        END IF;
    END IF;
    
    -- Calculate efficiency score
    IF action_record.action_type = 'Patch' THEN
        calculated_efficiency := 90;
    ELSIF action_record.action_type = 'Upgrade' THEN
        calculated_efficiency := 80;
    ELSIF action_record.action_type = 'Configuration' THEN
        calculated_efficiency := 95;
    ELSIF action_record.action_type = 'Disable' THEN
        calculated_efficiency := 100;
    ELSIF action_record.action_type = 'Mitigation' THEN
        calculated_efficiency := 85;
    ELSE
        calculated_efficiency := 100;
    END IF;
    
    -- Adjust efficiency based on severity
    IF action_record.severity = 'Critical' THEN
        calculated_efficiency := calculated_efficiency + 10;
    ELSIF action_record.severity = 'High' THEN
        calculated_efficiency := calculated_efficiency + 5;
    ELSIF action_record.severity = 'Low' THEN
        calculated_efficiency := calculated_efficiency - 5;
    END IF;
    
    calculated_efficiency := GREATEST(0, LEAST(100, calculated_efficiency));
    
    -- Update or insert the action risk score
    INSERT INTO action_risk_scores (action_id, urgency_score, efficiency_score, calculated_at)
    VALUES (action_uuid, calculated_score, calculated_efficiency, CURRENT_TIMESTAMP)
    ON CONFLICT (action_id) 
    DO UPDATE SET 
        urgency_score = EXCLUDED.urgency_score,
        efficiency_score = EXCLUDED.efficiency_score,
        calculated_at = EXCLUDED.calculated_at;
        
END;
$$;
CREATE FUNCTION public.recalculate_all_tiers() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    updated_count INTEGER := 0;
BEGIN
    -- Update all vulnerabilities with new risk-based tier classification
    UPDATE risk_priority_view 
    SET priority_tier = calculate_risk_based_tier(calculated_risk_score, is_kev);
    
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    
    -- Log the recalculation
    INSERT INTO epss_sync_log (sync_date, status, message, records_processed)
    VALUES (CURRENT_DATE, 'success', 'Recalculated tiers for ' || updated_count || ' vulnerabilities', updated_count);
    
    RETURN updated_count;
END;
$$;
CREATE FUNCTION public.recalculate_all_tiers_workaround() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    updated_count INTEGER := 0;
BEGIN
    -- Update the risk_priorities table directly
    UPDATE risk_priorities 
    SET priority_tier = calculate_risk_based_tier(
        (SELECT calculated_risk_score FROM risk_priority_view WHERE risk_priority_view.link_id = risk_priorities.link_id),
        (SELECT is_kev FROM risk_priority_view WHERE risk_priority_view.link_id = risk_priorities.link_id)
    );
    
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    
    -- Log the recalculation
    INSERT INTO epss_sync_log (sync_date, status, message, records_processed)
    VALUES (CURRENT_DATE, 'success', 'Recalculated tiers for ' || updated_count || ' vulnerabilities (workaround)', updated_count);
    
    RETURN updated_count;
END;
$$;
CREATE FUNCTION public.recalculate_asset_action_scores(asset_uuid uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    action_record RECORD;
BEGIN
    FOR action_record IN 
        SELECT DISTINCT ra.action_id
        FROM remediation_actions ra
        JOIN action_device_links adl ON ra.action_id = adl.action_id
        JOIN medical_devices md ON adl.device_id = md.device_id
        WHERE md.asset_id = asset_uuid
    LOOP
        PERFORM recalculate_action_urgency_score(action_record.action_id);
    END LOOP;
END;
$$;
CREATE FUNCTION public.recalculate_vulnerability_action_scores(vuln_cve_id character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    action_record RECORD;
BEGIN
    FOR action_record IN 
        SELECT DISTINCT ra.action_id
        FROM remediation_actions ra
        WHERE ra.cve_id = vuln_cve_id
    LOOP
        PERFORM recalculate_action_urgency_score(action_record.action_id);
    END LOOP;
END;
$$;
CREATE FUNCTION public.refresh_risk_priorities() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Refresh the materialized view
    REFRESH MATERIALIZED VIEW CONCURRENTLY risk_priority_view;
    
    -- Log the refresh
    INSERT INTO system_logs (log_level, message, context, created_at)
    VALUES ('INFO', 'Risk priority view refreshed with EPSS data', 
            json_build_object('view', 'risk_priority_view', 'includes_epss', true), 
            CURRENT_TIMESTAMP);
END;
$$;
CREATE FUNCTION public.refresh_software_package_risk_priority_view() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY software_package_risk_priority_view;
END;
$$;
CREATE FUNCTION public.trigger_recalculate_all_actions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    action_record RECORD;
BEGIN
    -- Recalculate all action scores when risk matrix configuration changes
    FOR action_record IN 
        SELECT action_id FROM action_risk_scores
    LOOP
        PERFORM recalculate_action_urgency_score(action_record.action_id);
    END LOOP;
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.trigger_recalculate_asset_actions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Recalculate actions for the affected asset
    IF TG_OP = 'DELETE' THEN
        PERFORM recalculate_asset_action_scores(OLD.asset_id);
        RETURN OLD;
    ELSE
        PERFORM recalculate_asset_action_scores(NEW.asset_id);
        RETURN NEW;
    END IF;
END;
$$;
CREATE FUNCTION public.trigger_recalculate_device_risk_scores() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
        device_record RECORD;
        new_risk_score INTEGER;
        current_config RECORD;
    BEGIN
        -- Get current risk matrix configuration
        SELECT * INTO current_config
        FROM risk_matrix_config
        WHERE is_active = TRUE
        ORDER BY created_at DESC
        LIMIT 1;
        -- If no configuration found, use defaults (with decimal support)
        IF current_config IS NULL THEN
            current_config.kev_weight := 1000;
            current_config.clinical_high_score := 100;
            current_config.business_medium_score := 50;
            current_config.non_essential_score := 10;
            current_config.location_weight_multiplier := 2.0;  -- Changed from 5 to 2.0 (decimal)
            current_config.critical_severity_score := 40;
            current_config.high_severity_score := 28;
            current_config.medium_severity_score := 16;
            current_config.low_severity_score := 4;
            current_config.epss_weight_enabled := TRUE;
            current_config.epss_high_threshold := 0.7;
            current_config.epss_weight_score := 20;
        END IF;
        -- Recalculate risk scores for all devices
        FOR device_record IN
            SELECT DISTINCT device_id FROM medical_devices
        LOOP
            new_risk_score := calculate_device_risk_score(device_record.device_id, current_config);
            UPDATE device_vulnerabilities_link
            SET risk_score = new_risk_score
            WHERE device_id = device_record.device_id;
        END LOOP;
        RETURN NULL;
    END;
$$;
CREATE FUNCTION public.trigger_recalculate_location_actions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    asset_record RECORD;
BEGIN
    -- Recalculate actions for all assets in the affected location
    IF TG_OP = 'DELETE' THEN
        FOR asset_record IN 
            SELECT asset_id FROM assets WHERE location_id = OLD.location_id
        LOOP
            PERFORM recalculate_asset_action_scores(asset_record.asset_id);
        END LOOP;
        RETURN OLD;
    ELSE
        FOR asset_record IN 
            SELECT asset_id FROM assets WHERE location_id = NEW.location_id
        LOOP
            PERFORM recalculate_asset_action_scores(asset_record.asset_id);
        END LOOP;
        RETURN NEW;
    END IF;
END;
$$;
CREATE FUNCTION public.trigger_recalculate_location_risk_scores() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
        device_record RECORD;
        new_risk_score INTEGER;
        current_config RECORD;
    BEGIN
        -- Get current risk matrix configuration
        SELECT * INTO current_config 
        FROM risk_matrix_config 
        WHERE is_active = TRUE 
        ORDER BY created_at DESC 
        LIMIT 1;
        
        -- If no configuration found, use defaults (with decimal support)
        IF current_config IS NULL THEN
            current_config.kev_weight := 1000;
            current_config.clinical_high_score := 100;
            current_config.business_medium_score := 50;
            current_config.non_essential_score := 10;
            current_config.location_weight_multiplier := 2.0;  -- Changed from 5 to 2.0 (decimal)
            current_config.critical_severity_score := 40;
            current_config.high_severity_score := 28;
            current_config.medium_severity_score := 16;
            current_config.low_severity_score := 4;
            current_config.epss_weight_enabled := TRUE;
            current_config.epss_high_threshold := 0.7;
            current_config.epss_weight_score := 20;
        END IF;
        
        -- Recalculate risk scores for all devices in this location
        FOR device_record IN
            SELECT DISTINCT md.device_id
            FROM medical_devices md
            JOIN assets a ON md.asset_id = a.asset_id
            WHERE a.location_id = COALESCE(NEW.location_id, OLD.location_id)
        LOOP
            new_risk_score := calculate_device_risk_score(device_record.device_id, current_config);
            
            UPDATE device_vulnerabilities_link 
            SET device_risk_score = new_risk_score
            WHERE device_id = device_record.device_id;
        END LOOP;
        
        RETURN COALESCE(NEW, OLD);
    END;
    $$;
CREATE FUNCTION public.trigger_recalculate_vulnerability_actions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Recalculate actions for the affected vulnerability
    IF TG_OP = 'DELETE' THEN
        PERFORM recalculate_vulnerability_action_scores(OLD.cve_id);
        RETURN OLD;
    ELSE
        PERFORM recalculate_vulnerability_action_scores(NEW.cve_id);
        RETURN NEW;
    END IF;
END;
$$;
CREATE FUNCTION public.trigger_refresh_risk_priority_view() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Refresh the materialized view after changes to key tables
    PERFORM refresh_risk_priorities();
    RETURN NULL;
END;
$$;
CREATE FUNCTION public.update_package_risk_scores() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- This will be called when vulnerabilities are added/removed
    -- Implementation will recalculate risk scores for affected packages
    PERFORM refresh_software_package_risk_priority_view();
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_risk_priority() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.priority_tier := calculate_priority_tier(NEW.link_id);
    NEW.risk_score := calculate_risk_score(NEW.link_id);
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_risks_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_sbom_evaluation_status() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.status = 'Completed' THEN
        UPDATE sboms 
        SET last_evaluated_at = NEW.completed_at,
            evaluation_status = 'Completed',
            vulnerabilities_count = NEW.vulnerabilities_found
        WHERE sbom_id = NEW.sbom_id;
    ELSIF NEW.status = 'Failed' THEN
        UPDATE sboms 
        SET evaluation_status = 'Failed'
        WHERE sbom_id = NEW.sbom_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_scheduled_tasks_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_tiers_based_on_risk() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    updated_count INTEGER := 0;
    vuln_record RECORD;
BEGIN
    -- Loop through all vulnerabilities and update their tiers
    FOR vuln_record IN 
        SELECT 
            v.cve_id,
            v.epss_score,
            v.epss_percentile,
            v.epss_date,
            v.epss_last_updated,
            -- Calculate risk score components
            CASE 
                WHEN kv.kev_id IS NOT NULL THEN 1000
                ELSE 0
            END as kev_points,
            CASE 
                WHEN a.criticality = 'Clinical-High' THEN 100
                WHEN a.criticality = 'Clinical-Medium' THEN 50
                WHEN a.criticality = 'Clinical-Low' THEN 25
                ELSE 0
            END as asset_points,
            CASE 
                WHEN l.criticality = '10/10' THEN 50
                WHEN l.criticality = '9/10' THEN 45
                WHEN l.criticality = '8/10' THEN 40
                WHEN l.criticality = '7/10' THEN 35
                WHEN l.criticality = '6/10' THEN 30
                WHEN l.criticality = '5/10' THEN 25
                WHEN l.criticality = '4/10' THEN 20
                WHEN l.criticality = '3/10' THEN 15
                WHEN l.criticality = '2/10' THEN 10
                WHEN l.criticality = '1/10' THEN 5
                ELSE 0
            END as location_points,
            CASE 
                WHEN v.severity = 'Critical' THEN 40
                WHEN v.severity = 'High' THEN 30
                WHEN v.severity = 'Medium' THEN 20
                WHEN v.severity = 'Low' THEN 10
                ELSE 0
            END as severity_points,
            CASE 
                WHEN v.epss_score >= 0.7 THEN 20
                ELSE 0
            END as epss_points
        FROM vulnerabilities v
        LEFT JOIN cisa_kev_catalog kv ON v.cve_id = kv.cve_id
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
        LEFT JOIN assets a ON md.asset_id = a.asset_id
        LEFT JOIN locations l ON a.location_id = l.location_id
    LOOP
        -- Calculate total risk score
        DECLARE
            total_score INTEGER;
            new_tier INTEGER;
        BEGIN
            total_score := vuln_record.kev_points + vuln_record.asset_points + 
                          vuln_record.location_points + vuln_record.severity_points + 
                          vuln_record.epss_points;
            
            -- Determine tier based on risk score
            new_tier := calculate_risk_based_tier(total_score, vuln_record.kev_points > 0);
            
            -- Update the vulnerability with new tier (if we had a table to update)
            -- For now, just count the updates
            updated_count := updated_count + 1;
        END;
    END LOOP;
    
    -- Log the update
    INSERT INTO epss_sync_log (sync_date, status, message, records_processed)
    VALUES (CURRENT_DATE, 'success', 'Updated tiers for ' || updated_count || ' vulnerabilities', updated_count);
    
    RETURN updated_count;
END;
$$;
CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;
CREATE FUNCTION public.update_vulnerability_kev_status() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- When a KEV entry is added or updated, mark matching vulnerabilities
    UPDATE vulnerabilities v
    SET is_kev = TRUE,
        kev_id = NEW.kev_id,
        kev_date_added = NEW.date_added,
        kev_due_date = NEW.due_date,
        kev_required_action = NEW.required_action,
        updated_at = CURRENT_TIMESTAMP
    WHERE v.cve_id = NEW.cve_id
      AND v.is_kev = FALSE; -- Only update if not already marked
    
    RETURN NEW;
END;
$$;
SET default_tablespace = '';
SET default_table_access_method = heap;
CREATE TABLE public.action_device_links (
    link_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    action_id uuid NOT NULL,
    device_id uuid NOT NULL,
    device_risk_score integer DEFAULT 0 NOT NULL,
    patch_status character varying(20) DEFAULT 'Pending'::character varying,
    patched_at timestamp without time zone,
    patched_by uuid,
    patch_notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT action_device_links_patch_status_check CHECK (((patch_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('In Progress'::character varying)::text, ('Completed'::character varying)::text, ('Failed'::character varying)::text, ('Skipped'::character varying)::text])))
);
CREATE TABLE public.action_risk_scores (
    score_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    action_id uuid NOT NULL,
    urgency_score integer DEFAULT 0 NOT NULL,
    efficiency_score integer DEFAULT 0 NOT NULL,
    affected_device_count integer DEFAULT 0 NOT NULL,
    highest_risk_device_id uuid,
    kev_count integer DEFAULT 0,
    critical_asset_count integer DEFAULT 0,
    calculated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_updated timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.remediation_actions (
    action_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    cve_id character varying(20),
    action_type character varying(50) DEFAULT 'Patch'::character varying NOT NULL,
    action_description text NOT NULL,
    target_version character varying(100),
    patch_reference character varying(255),
    vendor character varying(255),
    status character varying(20) DEFAULT 'Pending'::character varying,
    assigned_to uuid,
    due_date date,
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp without time zone,
    notes text,
    threat_id uuid,
    CONSTRAINT remediation_actions_action_type_check CHECK (((action_type)::text = ANY (ARRAY[('Patch'::character varying)::text, ('Upgrade'::character varying)::text, ('Configuration'::character varying)::text, ('Disable'::character varying)::text, ('Mitigation'::character varying)::text]))),
    CONSTRAINT remediation_actions_status_check CHECK (((status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('In Progress'::character varying)::text, ('Completed'::character varying)::text, ('Cancelled'::character varying)::text]))),
    CONSTRAINT remediation_actions_threat_or_cve_check CHECK (((cve_id IS NOT NULL) OR (threat_id IS NOT NULL)))
);
COMMENT ON COLUMN public.remediation_actions.action_type IS 'Type of remediation: Patch, Upgrade, Configuration, Disable, Mitigation';
COMMENT ON COLUMN public.remediation_actions.action_description IS 'Human-readable description of the action to be taken';
COMMENT ON COLUMN public.remediation_actions.target_version IS 'Target version to upgrade to (for upgrade actions)';
COMMENT ON COLUMN public.remediation_actions.patch_reference IS 'Patch reference number or KB article';
COMMENT ON COLUMN public.remediation_actions.status IS 'Current status of the remediation action';
CREATE TABLE public.users (
    user_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(100) NOT NULL,
    password_hash character varying(255) NOT NULL,
    role character varying(20) NOT NULL,
    mfa_enabled boolean DEFAULT false,
    mfa_secret character varying(32),
    last_login timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    is_active boolean DEFAULT true,
    mfa_backup_codes jsonb,
    CONSTRAINT users_role_check CHECK (((role)::text = ANY (ARRAY[('Admin'::character varying)::text, ('User'::character varying)::text])))
);
COMMENT ON COLUMN public.users.role IS 'User role: Admin (full access) or User (standard access)';
COMMENT ON COLUMN public.users.mfa_enabled IS 'Whether MFA is enabled for this user';
COMMENT ON COLUMN public.users.mfa_secret IS 'TOTP secret key for MFA';
COMMENT ON COLUMN public.users.mfa_backup_codes IS 'JSON array of backup codes for MFA recovery';
CREATE MATERIALIZED VIEW public.action_priority_view AS
 SELECT ra.action_id,
    ra.cve_id,
    ra.action_type,
    ra.action_description,
    ra.target_version,
    ra.patch_reference,
    ra.vendor,
    ra.status,
    ra.assigned_to,
    ra.due_date,
    ra.created_at,
    ra.updated_at,
    ra.completed_at,
    ra.notes,
    ars.urgency_score,
    ars.efficiency_score,
    ars.affected_device_count,
    ars.highest_risk_device_id,
    ars.kev_count,
    ars.critical_asset_count,
    ars.calculated_at,
    ars.last_updated,
        CASE
            WHEN ((ars.urgency_score >= 1000) OR ((ars.kev_count > 0) AND (ars.urgency_score >= 180))) THEN 1
            WHEN ((ars.urgency_score >= 180) OR ((ars.kev_count > 0) AND (ars.urgency_score >= 160))) THEN 2
            WHEN (ars.urgency_score >= 160) THEN 3
            ELSE 4
        END AS priority_tier,
        CASE
            WHEN (ars.kev_count > 0) THEN true
            ELSE false
        END AS is_kev,
        CASE
            WHEN ((ra.due_date IS NOT NULL) AND ((ra.status)::text <> 'Completed'::text)) THEN GREATEST(0, (CURRENT_DATE - ra.due_date))
            ELSE 0
        END AS days_overdue,
    u.username AS assigned_to_username,
    u.email AS assigned_to_email,
    uc.username AS created_by_username,
    uc.email AS created_by_email
   FROM (((public.remediation_actions ra
     LEFT JOIN public.action_risk_scores ars ON ((ra.action_id = ars.action_id)))
     LEFT JOIN public.users u ON ((ra.assigned_to = u.user_id)))
     LEFT JOIN public.users uc ON ((ra.created_by = uc.user_id)))
  WHERE ((ra.status)::text <> 'Cancelled'::text)
  WITH NO DATA;
CREATE TABLE public.api_keys (
    key_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    key_name character varying(100) NOT NULL,
    api_key character varying(255) NOT NULL,
    service character varying(50) NOT NULL,
    is_active boolean DEFAULT true,
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone
);
CREATE TABLE public.assets (
    asset_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    hostname character varying(255),
    ip_address inet,
    mac_address macaddr,
    source character varying(50) NOT NULL,
    raw_data jsonb,
    first_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    asset_tag character varying(100),
    asset_type character varying(50) NOT NULL,
    asset_subtype character varying(50),
    manufacturer character varying(100),
    model character varying(100),
    serial_number character varying(100),
    location character varying(255),
    firmware_version character varying(50),
    cpu character varying(100),
    memory_ram character varying(50),
    storage character varying(100),
    power_requirements character varying(100),
    primary_communication_protocol character varying(50),
    assigned_admin_user character varying(100),
    business_unit character varying(100),
    department character varying(100),
    cost_center character varying(50),
    warranty_expiration_date date,
    scheduled_replacement_date date,
    disposal_date date,
    disposal_method character varying(100),
    criticality character varying(20),
    regulatory_classification character varying(50),
    phi_status character varying(10) DEFAULT 'false'::character varying,
    data_encryption_transit character varying(50),
    data_encryption_rest character varying(50),
    authentication_method character varying(100),
    patch_level_last_update date,
    last_audit_date date,
    status character varying(20) DEFAULT 'Active'::character varying,
    location_id uuid,
    location_assignment_method character varying(20),
    location_assigned_at timestamp without time zone,
    metadata character varying(512),
    CONSTRAINT assets_asset_type_check CHECK (((asset_type)::text = ANY (ARRAY[('Server'::character varying)::text, ('Laptop'::character varying)::text, ('Switch'::character varying)::text, ('Software'::character varying)::text, ('Cloud Resource'::character varying)::text, ('IoT Gateway'::character varying)::text, ('IoMT Sensor'::character varying)::text, ('Smart Device'::character varying)::text, ('Medical Device'::character varying)::text]))),
    CONSTRAINT assets_criticality_check CHECK (((criticality)::text = ANY (ARRAY[('Clinical-High'::character varying)::text, ('Business-Medium'::character varying)::text, ('Non-Essential'::character varying)::text]))),
    CONSTRAINT assets_location_assignment_method_check CHECK (((location_assignment_method)::text = ANY (ARRAY[('Manual'::character varying)::text, ('Auto-IP'::character varying)::text, ('Inherited'::character varying)::text]))),
    CONSTRAINT assets_primary_communication_protocol_check CHECK (((primary_communication_protocol)::text = ANY (ARRAY[('Wi-Fi'::character varying)::text, ('Ethernet'::character varying)::text, ('Bluetooth/BLE'::character varying)::text, ('Zigbee'::character varying)::text, ('LoRaWAN'::character varying)::text, ('Cellular (4G/5G)'::character varying)::text]))),
    CONSTRAINT assets_status_check CHECK (((status)::text = ANY (ARRAY[('Active'::character varying)::text, ('Inactive'::character varying)::text, ('Retired'::character varying)::text, ('Disposed'::character varying)::text])))
);
COMMENT ON COLUMN public.assets.phi_status IS 'PHI (Protected Health Information) status - stores "true" or "false" as VARCHAR';
COMMENT ON COLUMN public.assets.metadata IS 'Additional metadata information for the asset (max 512 characters)';
CREATE TABLE public.medical_devices (
    device_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid,
    device_identifier character varying(100),
    brand_name character varying(100),
    model_number character varying(100),
    manufacturer_name character varying(100),
    device_description text,
    gmdn_term character varying(100),
    is_implantable character varying(10) DEFAULT false,
    fda_class character varying(10),
    udi character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    mapping_confidence numeric(3,2),
    mapping_method character varying(50),
    mapped_by uuid,
    mapped_at timestamp without time zone,
    catalog_number character varying(100),
    gmdn_code character varying(50),
    gmdn_definition text,
    fda_class_name character varying(200),
    regulation_number character varying(50),
    medical_specialty character varying(100),
    primary_udi character varying(100),
    package_udi character varying(100),
    issuing_agency character varying(50),
    commercial_status character varying(50),
    record_status character varying(50),
    is_single_use character varying(10) DEFAULT false,
    is_kit character varying(10) DEFAULT false,
    is_combination_product character varying(10) DEFAULT false,
    is_otc character varying(10) DEFAULT false,
    is_rx character varying(10) DEFAULT false,
    is_sterile character varying(10) DEFAULT false,
    sterilization_methods character varying(200),
    is_sterilization_prior_use character varying(10) DEFAULT false,
    is_pm_exempt character varying(10) DEFAULT false,
    is_direct_marking_exempt character varying(10) DEFAULT false,
    has_serial_number character varying(10) DEFAULT false,
    has_lot_batch_number character varying(10) DEFAULT false,
    has_expiration_date character varying(10) DEFAULT false,
    has_manufacturing_date character varying(10) DEFAULT false,
    mri_safety character varying(100),
    product_code character varying(50),
    product_code_name character varying(200),
    customer_phone character varying(50),
    customer_email character varying(100),
    public_version_number character varying(20),
    public_version_date date,
    public_version_status character varying(50),
    publish_date date,
    device_count_in_base_package integer,
    labeler_duns_number character varying(50),
    k_number character varying(20),
    decision_code character varying(10),
    decision_date date,
    decision_description character varying(200),
    clearance_type character varying(50),
    date_received date,
    statement_or_summary character varying(50),
    applicant character varying(200),
    contact character varying(200),
    address_1 character varying(200),
    address_2 character varying(200),
    city character varying(100),
    state character varying(50),
    zip_code character varying(20),
    postal_code character varying(20),
    country_code character varying(10),
    advisory_committee character varying(10),
    advisory_committee_description character varying(200),
    review_advisory_committee character varying(10),
    expedited_review_flag character varying(10),
    third_party_flag character varying(10),
    device_class character varying(10),
    medical_specialty_description character varying(200),
    registration_numbers text,
    fei_numbers text,
    device_name character varying(255),
    raw_510k_data jsonb
);
COMMENT ON COLUMN public.medical_devices.raw_510k_data IS 'Complete raw 510k data from FDA API in JSON format - captures all fields for future-proofing';
CREATE VIEW public.asset_summary AS
 SELECT a.asset_id,
    a.hostname,
    a.ip_address,
    a.mac_address,
    a.asset_type,
    a.manufacturer,
    a.model,
    a.department,
    a.criticality,
    a.status,
        CASE
            WHEN (md.device_id IS NOT NULL) THEN 'Mapped'::text
            ELSE 'Unmapped'::text
        END AS mapping_status,
    a.last_seen
   FROM (public.assets a
     LEFT JOIN public.medical_devices md ON ((a.asset_id = md.asset_id)));
CREATE TABLE public.audit_logs (
    log_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    action character varying(100) NOT NULL,
    table_name character varying(50),
    record_id uuid,
    old_values jsonb,
    new_values jsonb,
    ip_address inet,
    user_agent text,
    "timestamp" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.cisa_kev_catalog (
    kev_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    cve_id character varying(20) NOT NULL,
    vendor_project character varying(255),
    product character varying(255),
    vulnerability_name text,
    date_added date NOT NULL,
    short_description text,
    required_action text,
    due_date date,
    known_ransomware_campaign_use boolean DEFAULT false,
    notes text,
    cwes text[],
    catalog_version character varying(50),
    last_synced_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.cisa_kev_catalog IS 'CISA Known Exploited Vulnerabilities (KEV) catalog - actively exploited vulnerabilities';
COMMENT ON COLUMN public.cisa_kev_catalog.required_action IS 'CISA-specified remediation action required';
COMMENT ON COLUMN public.cisa_kev_catalog.due_date IS 'CISA-mandated remediation due date for Federal agencies';
COMMENT ON COLUMN public.cisa_kev_catalog.known_ransomware_campaign_use IS 'TRUE if vulnerability is known to be used in ransomware campaigns';
CREATE TABLE public.cisa_kev_sync_log (
    sync_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    sync_started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    sync_completed_at timestamp without time zone,
    sync_status character varying(20),
    total_kev_entries integer DEFAULT 0,
    new_entries integer DEFAULT 0,
    updated_entries integer DEFAULT 0,
    vulnerabilities_matched integer DEFAULT 0,
    catalog_version character varying(50),
    catalog_title character varying(255),
    catalog_count integer,
    error_message text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT cisa_kev_sync_log_sync_status_check CHECK (((sync_status)::text = ANY (ARRAY[('Success'::character varying)::text, ('Failed'::character varying)::text, ('Partial'::character varying)::text])))
);
COMMENT ON TABLE public.cisa_kev_sync_log IS 'Log of KEV catalog synchronization operations';
CREATE TABLE public.compensating_controls_checklist (
    control_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    link_id uuid,
    control_type character varying(50),
    control_description text,
    is_implemented boolean DEFAULT false,
    implemented_date date,
    verified_by uuid,
    notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT compensating_controls_checklist_control_type_check CHECK (((control_type)::text = ANY (ARRAY[('Network Isolation'::character varying)::text, ('Access Control'::character varying)::text, ('Monitoring'::character varying)::text, ('Physical Security'::character varying)::text, ('Procedural Control'::character varying)::text, ('Other'::character varying)::text])))
);
CREATE TABLE public.cwe_reference (
    cwe_id character varying(20) NOT NULL,
    cwe_name character varying(255) NOT NULL,
    cwe_description text,
    category character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.dave_api_key_usage (
    usage_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    key_id uuid,
    endpoint character varying(255) NOT NULL,
    method character varying(10) NOT NULL,
    ip_address inet,
    user_agent text,
    response_code integer,
    response_time_ms integer,
    request_size integer,
    response_size integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.dave_api_key_usage IS 'Log of API key usage for monitoring and analytics';
COMMENT ON COLUMN public.dave_api_key_usage.endpoint IS 'API endpoint that was called';
COMMENT ON COLUMN public.dave_api_key_usage.method IS 'HTTP method used (GET, POST, etc.)';
COMMENT ON COLUMN public.dave_api_key_usage.response_time_ms IS 'Response time in milliseconds';
CREATE TABLE public.dave_api_keys (
    key_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    key_name character varying(100) NOT NULL,
    description text,
    api_key character varying(255) NOT NULL,
    key_hash character varying(255) NOT NULL,
    user_id uuid,
    permissions jsonb DEFAULT '{}'::jsonb,
    scopes jsonb DEFAULT '[]'::jsonb,
    is_active boolean DEFAULT true,
    last_used timestamp without time zone,
    usage_count integer DEFAULT 0,
    rate_limit_per_hour integer DEFAULT 1000,
    ip_whitelist text[],
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_by uuid
);
COMMENT ON TABLE public.dave_api_keys IS 'API keys for external systems to authenticate with  API';
COMMENT ON COLUMN public.dave_api_keys.key_name IS 'Human-readable name for the API key';
COMMENT ON COLUMN public.dave_api_keys.description IS 'Description of what this API key is used for';
COMMENT ON COLUMN public.dave_api_keys.api_key IS 'The actual API key string (stored in plain text for external use)';
COMMENT ON COLUMN public.dave_api_keys.key_hash IS 'Hashed version of the API key for security verification';
COMMENT ON COLUMN public.dave_api_keys.permissions IS 'JSON object defining detailed permissions for this key';
COMMENT ON COLUMN public.dave_api_keys.scopes IS 'Array of API scopes this key can access';
COMMENT ON COLUMN public.dave_api_keys.rate_limit_per_hour IS 'Maximum API calls allowed per hour for this key';
COMMENT ON COLUMN public.dave_api_keys.ip_whitelist IS 'Array of allowed IP addresses (NULL = no restriction)';
CREATE TABLE public.device_recalls_link (
    link_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    device_id uuid,
    recall_id uuid,
    remediation_status character varying(20) DEFAULT 'Open'::character varying,
    remediation_notes text,
    assigned_to uuid,
    due_date date,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    remediation_date timestamp without time zone,
    CONSTRAINT device_recalls_link_remediation_status_check CHECK (((remediation_status)::text = ANY (ARRAY[('Open'::character varying)::text, ('In Progress'::character varying)::text, ('Resolved'::character varying)::text, ('Mitigated'::character varying)::text])))
);
CREATE TABLE public.device_vulnerabilities_link (
    link_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    device_id uuid,
    component_id uuid,
    cve_id character varying(20),
    discovered_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    remediation_status character varying(20) DEFAULT 'Open'::character varying,
    remediation_notes text,
    assigned_to uuid,
    due_date date,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    vendor_name character varying(200),
    vendor_contact character varying(200),
    vendor_ticket_id character varying(100),
    vendor_status character varying(50),
    patch_expected_date date,
    patch_applied_date date,
    risk_score integer,
    priority_tier integer,
    compensating_controls text,
    asset_id uuid,
    vulnerability_id uuid,
    CONSTRAINT device_vulnerabilities_link_priority_tier_check CHECK ((priority_tier = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT device_vulnerabilities_link_remediation_status_check CHECK (((remediation_status)::text = ANY (ARRAY[('Open'::character varying)::text, ('In Progress'::character varying)::text, ('Resolved'::character varying)::text, ('Mitigated'::character varying)::text, ('False Positive'::character varying)::text]))),
    CONSTRAINT device_vulnerabilities_link_vendor_status_check CHECK (((vendor_status)::text = ANY (ARRAY[('Not Contacted'::character varying)::text, ('Contacted'::character varying)::text, ('Patch Available'::character varying)::text, ('Patch Pending'::character varying)::text, ('No Patch Available'::character varying)::text, ('End of Life'::character varying)::text])))
);
COMMENT ON COLUMN public.device_vulnerabilities_link.asset_id IS 'UUID reference to asset/device associated with this vulnerability link';
COMMENT ON COLUMN public.device_vulnerabilities_link.vulnerability_id IS 'Reference to vulnerability by UUID - preferred over cve_id for non-CVE vulnerabilities';
CREATE TABLE public.scheduled_tasks (
    task_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    task_type character varying(50) NOT NULL,
    package_id uuid,
    cve_id character varying(20),
    action_id uuid,
    device_id uuid,
    assigned_to uuid NOT NULL,
    assigned_by uuid,
    scheduled_date timestamp without time zone NOT NULL,
    implementation_date timestamp without time zone,
    estimated_downtime integer NOT NULL,
    actual_downtime integer,
    status character varying(20) DEFAULT 'Scheduled'::character varying,
    task_description text,
    notes text,
    completion_notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp without time zone,
    completed_by uuid,
    department_notified boolean DEFAULT false,
    department_approval_status character varying(20) DEFAULT 'Pending'::character varying,
    department_approval_contact text,
    department_approval_notes text,
    department_approval_date timestamp without time zone,
    department_approval_by uuid,
    patch_id uuid,
    recall_id uuid,
    recall_priority character varying(20) DEFAULT 'Medium'::character varying,
    recall_classification character varying(50),
    remediation_type character varying(50) DEFAULT 'Inspection'::character varying,
    affected_serial_numbers text,
    vendor_contact_required boolean DEFAULT false,
    fda_notification_required boolean DEFAULT false,
    patient_safety_impact boolean DEFAULT false,
    original_fda_recall_number character varying(50),
    original_manufacturer_name character varying(100),
    original_product_description text,
    original_recall_date date,
    original_reason_for_recall text,
    original_product_code text,
    original_recall_status character varying(20),
    original_cve_id text,
    original_cve_description text,
    original_cve_severity character varying(20),
    original_cvss_v3_score numeric(3,1),
    original_cve_published_date date,
    original_cve_modified_date date,
    original_patch_name character varying(100),
    original_patch_type character varying(50),
    original_patch_vendor character varying(100),
    original_patch_version character varying(50),
    original_patch_description text,
    original_patch_release_date date,
    original_patch_requires_reboot boolean,
    original_action_type character varying(50),
    original_action_description text,
    original_action_vendor character varying(100),
    original_action_target_version character varying(50),
    original_action_patch_reference character varying(100),
    original_device_name character varying(200),
    original_brand_name character varying(100),
    original_model_number character varying(100),
    original_device_identifier character varying(100),
    original_k_number character varying(20),
    original_udi character varying(100),
    original_ip_address inet,
    original_hostname character varying(100),
    original_location character varying(200),
    original_department character varying(100),
    CONSTRAINT scheduled_tasks_department_approval_status_check CHECK (((department_approval_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Approved'::character varying)::text, ('Denied'::character varying)::text, ('Not Required'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_department_approval_status_check1 CHECK (((department_approval_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Approved'::character varying)::text, ('Denied'::character varying)::text, ('Not Required'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_department_approval_status_check2 CHECK (((department_approval_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Approved'::character varying)::text, ('Denied'::character varying)::text, ('Not Required'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_recall_priority_check CHECK (((recall_priority)::text = ANY (ARRAY[('Low'::character varying)::text, ('Medium'::character varying)::text, ('High'::character varying)::text, ('Critical'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_recall_priority_check1 CHECK (((recall_priority)::text = ANY (ARRAY[('Low'::character varying)::text, ('Medium'::character varying)::text, ('High'::character varying)::text, ('Critical'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_recall_priority_check2 CHECK (((recall_priority)::text = ANY (ARRAY[('Low'::character varying)::text, ('Medium'::character varying)::text, ('High'::character varying)::text, ('Critical'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_remediation_type_check CHECK (((remediation_type)::text = ANY (ARRAY[('Inspection'::character varying)::text, ('Repair'::character varying)::text, ('Replacement'::character varying)::text, ('Software Update'::character varying)::text, ('Configuration Change'::character varying)::text, ('Other'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_remediation_type_check1 CHECK (((remediation_type)::text = ANY (ARRAY[('Inspection'::character varying)::text, ('Repair'::character varying)::text, ('Replacement'::character varying)::text, ('Software Update'::character varying)::text, ('Configuration Change'::character varying)::text, ('Other'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_remediation_type_check2 CHECK (((remediation_type)::text = ANY (ARRAY[('Inspection'::character varying)::text, ('Repair'::character varying)::text, ('Replacement'::character varying)::text, ('Software Update'::character varying)::text, ('Configuration Change'::character varying)::text, ('Other'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_status_check CHECK (((status)::text = ANY (ARRAY[('Scheduled'::character varying)::text, ('In Progress'::character varying)::text, ('Completed'::character varying)::text, ('Cancelled'::character varying)::text, ('Failed'::character varying)::text, ('Consolidated'::character varying)::text]))),
    CONSTRAINT scheduled_tasks_task_type_check CHECK (((task_type)::text = ANY (ARRAY[('package_remediation'::character varying)::text, ('cve_remediation'::character varying)::text, ('patch_application'::character varying)::text, ('recall_maintenance'::character varying)::text])))
);
COMMENT ON TABLE public.scheduled_tasks IS 'Scheduled remediation tasks with device-specific assignments and downtime tracking';
COMMENT ON COLUMN public.scheduled_tasks.estimated_downtime IS 'Estimated downtime in minutes';
COMMENT ON COLUMN public.scheduled_tasks.actual_downtime IS 'Actual downtime in minutes (populated after completion)';
COMMENT ON COLUMN public.scheduled_tasks.status IS 'Task status: Scheduled, In Progress, Completed, Cancelled, Failed, or Consolidated (hidden from normal views)';
COMMENT ON COLUMN public.scheduled_tasks.department_notified IS 'Whether the department has been notified of the maintenance task';
COMMENT ON COLUMN public.scheduled_tasks.department_approval_status IS 'Approval status from department: Pending, Approved, Denied, Not Required';
COMMENT ON COLUMN public.scheduled_tasks.department_approval_contact IS 'Contact person who provided approval';
COMMENT ON COLUMN public.scheduled_tasks.department_approval_notes IS 'Notes about the approval decision';
COMMENT ON COLUMN public.scheduled_tasks.department_approval_date IS 'Date when approval was given';
COMMENT ON COLUMN public.scheduled_tasks.department_approval_by IS 'User who recorded the approval';
COMMENT ON COLUMN public.scheduled_tasks.recall_id IS 'Reference to the recall that requires maintenance';
COMMENT ON COLUMN public.scheduled_tasks.recall_priority IS 'Priority level for the recall maintenance task';
COMMENT ON COLUMN public.scheduled_tasks.recall_classification IS 'FDA recall classification (Class I, II, or III)';
COMMENT ON COLUMN public.scheduled_tasks.remediation_type IS 'Type of remediation required for the recall';
COMMENT ON COLUMN public.scheduled_tasks.affected_serial_numbers IS 'Serial numbers of affected devices (comma-separated)';
COMMENT ON COLUMN public.scheduled_tasks.vendor_contact_required IS 'Whether vendor contact is required for this task';
COMMENT ON COLUMN public.scheduled_tasks.fda_notification_required IS 'Whether FDA notification is required for this task';
COMMENT ON COLUMN public.scheduled_tasks.patient_safety_impact IS 'Whether this recall has patient safety implications';
COMMENT ON COLUMN public.scheduled_tasks.original_fda_recall_number IS 'Original FDA recall number from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_manufacturer_name IS 'Original manufacturer name from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_product_description IS 'Original product description from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_recall_date IS 'Original recall date from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_reason_for_recall IS 'Original reason for recall from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_product_code IS 'Original product code from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_recall_status IS 'Original recall status from the recall record';
COMMENT ON COLUMN public.scheduled_tasks.original_cve_id IS 'Original CVE ID from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_cve_description IS 'Original CVE description from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_cve_severity IS 'Original CVE severity from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_cvss_v3_score IS 'Original CVSS v3 score from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_cve_published_date IS 'Original CVE published date from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_cve_modified_date IS 'Original CVE modified date from the vulnerability record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_name IS 'Original patch name from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_type IS 'Original patch type from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_vendor IS 'Original patch vendor from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_version IS 'Original patch version from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_description IS 'Original patch description from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_release_date IS 'Original patch release date from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_patch_requires_reboot IS 'Original patch requires reboot flag from the patch record';
COMMENT ON COLUMN public.scheduled_tasks.original_action_type IS 'Original action type from the remediation action record';
COMMENT ON COLUMN public.scheduled_tasks.original_action_description IS 'Original action description from the remediation action record';
COMMENT ON COLUMN public.scheduled_tasks.original_action_vendor IS 'Original action vendor from the remediation action record';
COMMENT ON COLUMN public.scheduled_tasks.original_action_target_version IS 'Original action target version from the remediation action record';
COMMENT ON COLUMN public.scheduled_tasks.original_action_patch_reference IS 'Original action patch reference from the remediation action record';
COMMENT ON COLUMN public.scheduled_tasks.original_device_name IS 'Original device name from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_brand_name IS 'Original brand name from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_model_number IS 'Original model number from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_device_identifier IS 'Original device identifier from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_k_number IS 'Original K number from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_udi IS 'Original UDI from the medical device record';
COMMENT ON COLUMN public.scheduled_tasks.original_ip_address IS 'Original IP address from the asset record';
COMMENT ON COLUMN public.scheduled_tasks.original_hostname IS 'Original hostname from the asset record';
COMMENT ON COLUMN public.scheduled_tasks.original_location IS 'Original location from the asset record';
COMMENT ON COLUMN public.scheduled_tasks.original_department IS 'Original department from the asset record';
CREATE TABLE public.vulnerabilities (
    cve_id character varying(20),
    description text,
    cvss_v3_score numeric(3,1),
    cvss_v3_vector character varying(100),
    severity character varying(20),
    published_date date,
    last_modified_date date,
    nvd_data jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    cvss_v2_score numeric(3,1),
    cvss_v2_vector character varying(100),
    is_kev boolean DEFAULT false,
    kev_id uuid,
    kev_date_added date,
    kev_due_date date,
    kev_required_action text,
    priority character varying(20) DEFAULT 'Normal'::character varying,
    cvss_v4_score numeric(3,1),
    cvss_v4_vector character varying(200),
    epss_score numeric(5,4) DEFAULT NULL::numeric,
    epss_percentile numeric(5,4) DEFAULT NULL::numeric,
    epss_date date,
    epss_last_updated timestamp without time zone,
    patched_devices jsonb DEFAULT '[]'::jsonb,
    vulnerability_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    CONSTRAINT vulnerabilities_priority_check CHECK (((priority)::text = ANY (ARRAY[('Critical-KEV'::character varying)::text, ('High'::character varying)::text, ('Medium'::character varying)::text, ('Low'::character varying)::text, ('Normal'::character varying)::text]))),
    CONSTRAINT vulnerabilities_severity_check CHECK (((severity)::text = ANY (ARRAY[('Critical'::character varying)::text, ('High'::character varying)::text, ('Medium'::character varying)::text, ('Low'::character varying)::text, ('Info'::character varying)::text, ('Unknown'::character varying)::text])))
);
COMMENT ON COLUMN public.vulnerabilities.cve_id IS 'CVE identifier (optional, can be NULL for non-CVE vulnerabilities or custom threats)';
COMMENT ON COLUMN public.vulnerabilities.cvss_v3_score IS 'CVSS v3.x score (0.0-10.0). Use if v4 not available.';
COMMENT ON COLUMN public.vulnerabilities.cvss_v2_score IS 'CVSS v2.0 score (0.0-10.0). Legacy, use only if v3/v4 not available.';
COMMENT ON COLUMN public.vulnerabilities.is_kev IS 'TRUE if vulnerability is in CISA KEV catalog (actively exploited)';
COMMENT ON COLUMN public.vulnerabilities.priority IS 'Vulnerability priority: Critical-KEV for actively exploited vulnerabilities';
COMMENT ON COLUMN public.vulnerabilities.cvss_v4_score IS 'CVSS v4.0 score (0.0-10.0). Preferred when available.';
COMMENT ON COLUMN public.vulnerabilities.epss_score IS 'EPSS probability score (0.0000-1.0000) - likelihood of exploitation';
COMMENT ON COLUMN public.vulnerabilities.epss_percentile IS 'EPSS percentile ranking (0.0000-1.0000) - relative to all CVEs';
COMMENT ON COLUMN public.vulnerabilities.epss_date IS 'Date of EPSS score from FIRST.org API';
COMMENT ON COLUMN public.vulnerabilities.epss_last_updated IS 'Timestamp of last EPSS score update';
COMMENT ON COLUMN public.vulnerabilities.vulnerability_id IS 'Auto-generated UUID primary key for each vulnerability record';
CREATE VIEW public.downtime_calendar_view AS
 SELECT date(st.scheduled_date) AS calendar_date,
    count(*) AS total_tasks,
    count(
        CASE
            WHEN ((st.status)::text = 'Scheduled'::text) THEN 1
            ELSE NULL::integer
        END) AS scheduled_count,
    count(
        CASE
            WHEN ((st.status)::text = 'In Progress'::text) THEN 1
            ELSE NULL::integer
        END) AS in_progress_count,
    count(
        CASE
            WHEN ((st.status)::text = 'Completed'::text) THEN 1
            ELSE NULL::integer
        END) AS completed_count,
    count(
        CASE
            WHEN ((st.status)::text = 'Cancelled'::text) THEN 1
            ELSE NULL::integer
        END) AS cancelled_count,
    count(
        CASE
            WHEN ((st.status)::text = 'Failed'::text) THEN 1
            ELSE NULL::integer
        END) AS failed_count,
    sum(st.estimated_downtime) AS total_estimated_downtime,
    sum(st.actual_downtime) AS total_actual_downtime,
    count(DISTINCT st.device_id) AS affected_devices,
    count(DISTINCT st.assigned_to) AS assigned_users,
    count(DISTINCT a.location) AS affected_locations,
    count(DISTINCT a.department) AS affected_departments,
    count(
        CASE
            WHEN ((a.criticality)::text = 'Clinical-High'::text) THEN 1
            ELSE NULL::integer
        END) AS critical_devices_affected,
    count(
        CASE
            WHEN ((v.severity)::text = 'Critical'::text) THEN 1
            ELSE NULL::integer
        END) AS critical_cves,
    count(
        CASE
            WHEN ((v.severity)::text = 'High'::text) THEN 1
            ELSE NULL::integer
        END) AS high_cves
   FROM (((public.scheduled_tasks st
     LEFT JOIN public.medical_devices md ON ((st.device_id = md.device_id)))
     LEFT JOIN public.assets a ON ((md.asset_id = a.asset_id)))
     LEFT JOIN public.vulnerabilities v ON (((st.cve_id)::text = (v.cve_id)::text)))
  WHERE ((st.status)::text <> ALL (ARRAY[('Completed'::character varying)::text, ('Cancelled'::character varying)::text, ('Failed'::character varying)::text]))
  GROUP BY (date(st.scheduled_date))
  ORDER BY (date(st.scheduled_date));
CREATE TABLE public.epss_score_history (
    history_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    cve_id character varying(20) NOT NULL,
    epss_score numeric(5,4) NOT NULL,
    epss_percentile numeric(5,4) NOT NULL,
    recorded_date date NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.epss_score_history IS 'Historical EPSS scores for trend analysis and exploitation tracking';
COMMENT ON COLUMN public.epss_score_history.epss_score IS 'EPSS probability score at time of recording';
COMMENT ON COLUMN public.epss_score_history.epss_percentile IS 'EPSS percentile at time of recording';
COMMENT ON COLUMN public.epss_score_history.recorded_date IS 'Date when this EPSS score was recorded';
CREATE TABLE public.epss_sync_log (
    sync_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    sync_started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    sync_completed_at timestamp without time zone,
    sync_status character varying(20) DEFAULT 'Running'::character varying,
    total_cves_processed integer DEFAULT 0,
    cves_updated integer DEFAULT 0,
    cves_new integer DEFAULT 0,
    api_date date,
    api_total_cves integer,
    api_version character varying(50),
    error_message text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT epss_sync_log_sync_status_check CHECK (((sync_status)::text = ANY (ARRAY[('Success'::character varying)::text, ('Failed'::character varying)::text, ('Partial'::character varying)::text, ('Running'::character varying)::text])))
);
COMMENT ON TABLE public.epss_sync_log IS 'Log of EPSS synchronization operations from FIRST.org API';
COMMENT ON COLUMN public.epss_sync_log.sync_status IS 'Status of sync operation: Success, Failed, Partial, Running';
COMMENT ON COLUMN public.epss_sync_log.total_cves_processed IS 'Total CVEs processed from API';
COMMENT ON COLUMN public.epss_sync_log.cves_updated IS 'Number of existing CVEs updated with new EPSS scores';
COMMENT ON COLUMN public.epss_sync_log.cves_new IS 'Number of new CVEs added with EPSS scores';
CREATE TABLE public.failed_login_attempts (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    ip_address character varying(45) NOT NULL,
    user_agent text,
    attempt_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    reason character varying(255)
);
CREATE SEQUENCE public.failed_login_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.failed_login_attempts_id_seq OWNED BY public.failed_login_attempts.id;
CREATE TABLE public.ip_blocklist (
    id integer NOT NULL,
    ip_address character varying(45) NOT NULL,
    reason character varying(255) NOT NULL,
    blocked_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone,
    is_permanent boolean DEFAULT false,
    blocked_by integer
);
CREATE SEQUENCE public.ip_blocklist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.ip_blocklist_id_seq OWNED BY public.ip_blocklist.id;
CREATE TABLE public.ip_locations (
    id integer NOT NULL,
    ip_address inet NOT NULL,
    location_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
COMMENT ON TABLE public.ip_locations IS 'Cached GeoIP location data for IP addresses';
COMMENT ON COLUMN public.ip_locations.ip_address IS 'IP address (supports both IPv4 and IPv6)';
COMMENT ON COLUMN public.ip_locations.location_data IS 'JSON data containing country, region, city, coordinates, etc.';
COMMENT ON COLUMN public.ip_locations.created_at IS 'When this location data was first cached';
COMMENT ON COLUMN public.ip_locations.updated_at IS 'When this location data was last updated';
CREATE SEQUENCE public.ip_locations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.ip_locations_id_seq OWNED BY public.ip_locations.id;
CREATE VIEW public.kev_vulnerability_summary AS
 SELECT k.kev_id,
    k.cve_id,
    k.vulnerability_name,
    k.vendor_project,
    k.product,
    k.date_added,
    k.due_date,
    k.required_action,
    k.known_ransomware_campaign_use,
    count(DISTINCT dvl.link_id) AS affected_vulnerabilities,
    count(DISTINCT dvl.device_id) AS affected_devices,
    min(dvl.discovered_at) AS first_discovered,
    max(dvl.updated_at) AS last_updated
   FROM (public.cisa_kev_catalog k
     LEFT JOIN public.device_vulnerabilities_link dvl ON (((k.cve_id)::text = (dvl.cve_id)::text)))
  GROUP BY k.kev_id, k.cve_id, k.vulnerability_name, k.vendor_project, k.product, k.date_added, k.due_date, k.required_action, k.known_ransomware_campaign_use;
CREATE TABLE public.locations (
    location_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    parent_location_id uuid,
    location_name character varying(200) NOT NULL,
    location_type character varying(50) NOT NULL,
    location_code character varying(50),
    description text,
    criticality integer NOT NULL,
    ip_range_cidr cidr[],
    ip_range_start inet[],
    ip_range_end inet[],
    is_active boolean DEFAULT true,
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT locations_criticality_check CHECK (((criticality >= 1) AND (criticality <= 10))),
    CONSTRAINT locations_location_type_check CHECK (((location_type)::text = ANY (ARRAY[('Building'::character varying)::text, ('Floor'::character varying)::text, ('Department'::character varying)::text, ('Ward'::character varying)::text, ('Lab'::character varying)::text, ('Room'::character varying)::text, ('Other'::character varying)::text])))
);
CREATE VIEW public.location_hierarchy AS
 WITH RECURSIVE location_tree AS (
         SELECT locations.location_id,
            locations.parent_location_id,
            locations.location_name,
            locations.location_type,
            locations.location_code,
            locations.description,
            locations.criticality,
            locations.is_active,
            locations.created_at,
            locations.updated_at,
            0 AS level,
            (locations.location_name)::text AS hierarchy_path,
            ARRAY[locations.location_id] AS path_array
           FROM public.locations
          WHERE (locations.parent_location_id IS NULL)
        UNION ALL
         SELECT l.location_id,
            l.parent_location_id,
            l.location_name,
            l.location_type,
            l.location_code,
            l.description,
            l.criticality,
            l.is_active,
            l.created_at,
            l.updated_at,
            (lt.level + 1),
            ((lt.hierarchy_path || ' > '::text) || (l.location_name)::text),
            (lt.path_array || l.location_id)
           FROM (public.locations l
             JOIN location_tree lt ON ((l.parent_location_id = lt.location_id)))
        )
 SELECT location_id,
    parent_location_id,
    location_name,
    location_type,
    location_code,
    description,
    criticality,
    is_active,
    created_at,
    updated_at,
    level,
    hierarchy_path,
    path_array
   FROM location_tree
  ORDER BY path_array;
CREATE TABLE public.location_ip_ranges (
    range_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    location_id uuid NOT NULL,
    range_format character varying(20) NOT NULL,
    cidr_notation cidr,
    start_ip inet,
    end_ip inet,
    description text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_ip_range_format CHECK (((((range_format)::text = 'CIDR'::text) AND (cidr_notation IS NOT NULL) AND (start_ip IS NULL) AND (end_ip IS NULL)) OR (((range_format)::text = 'StartEnd'::text) AND (cidr_notation IS NULL) AND (start_ip IS NOT NULL) AND (end_ip IS NOT NULL)))),
    CONSTRAINT location_ip_ranges_range_format_check CHECK (((range_format)::text = ANY (ARRAY[('CIDR'::character varying)::text, ('StartEnd'::character varying)::text])))
);
CREATE TABLE public.mfa_sessions (
    user_id uuid NOT NULL,
    secret character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);
COMMENT ON TABLE public.mfa_sessions IS 'Temporary MFA secrets during setup process';
CREATE TABLE public.notifications (
    notification_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    title character varying(255) NOT NULL,
    message text NOT NULL,
    type character varying(50) NOT NULL,
    priority character varying(20) DEFAULT 'Medium'::character varying,
    is_read boolean DEFAULT false,
    related_entity_type character varying(50),
    related_entity_id uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    read_at timestamp without time zone,
    CONSTRAINT notifications_priority_check CHECK (((priority)::text = ANY (ARRAY[('Low'::character varying)::text, ('Medium'::character varying)::text, ('High'::character varying)::text, ('Critical'::character varying)::text])))
);
CREATE VIEW public.overdue_kev_vulnerabilities AS
 SELECT k.cve_id,
    k.vulnerability_name,
    k.vendor_project,
    k.product,
    k.due_date,
    k.required_action,
    count(DISTINCT dvl.device_id) AS affected_devices,
    (CURRENT_DATE - k.due_date) AS days_overdue
   FROM (public.cisa_kev_catalog k
     JOIN public.device_vulnerabilities_link dvl ON (((k.cve_id)::text = (dvl.cve_id)::text)))
  WHERE ((k.due_date < CURRENT_DATE) AND ((dvl.remediation_status)::text <> 'Resolved'::text))
  GROUP BY k.kev_id, k.cve_id, k.vulnerability_name, k.vendor_project, k.product, k.due_date, k.required_action
  ORDER BY (CURRENT_DATE - k.due_date) DESC;
CREATE TABLE public.patch_applications (
    application_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    patch_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    device_id uuid,
    applied_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    applied_by uuid NOT NULL,
    verification_status character varying(20) DEFAULT 'Pending'::character varying,
    verification_method character varying(50),
    verification_date timestamp without time zone,
    verified_by uuid,
    notes text,
    install_duration integer,
    issues_encountered text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT patch_applications_verification_method_check CHECK (((verification_method)::text = ANY (ARRAY[('Manual'::character varying)::text, ('SBOM Upload'::character varying)::text, ('Automatic'::character varying)::text, ('Version Check'::character varying)::text]))),
    CONSTRAINT patch_applications_verification_status_check CHECK (((verification_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Verified'::character varying)::text, ('Failed'::character varying)::text, ('Rolled Back'::character varying)::text])))
);
COMMENT ON TABLE public.patch_applications IS 'Tracks deployment of patches to specific assets with verification status';
CREATE TABLE public.patches (
    patch_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    patch_name character varying(255) NOT NULL,
    patch_type character varying(50) DEFAULT 'Software Update'::character varying,
    target_device_type character varying(255),
    target_package_id uuid,
    target_version character varying(100),
    cve_list jsonb,
    description text,
    release_date date,
    vendor character varying(255),
    kb_article character varying(100),
    download_url text,
    install_instructions text,
    prerequisites text,
    estimated_install_time integer,
    requires_reboot boolean DEFAULT false,
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    is_active boolean DEFAULT true,
    estimated_downtime integer DEFAULT 0,
    applied_devices jsonb DEFAULT '[]'::jsonb,
    CONSTRAINT patches_patch_type_check CHECK (((patch_type)::text = ANY (ARRAY[('Software Update'::character varying)::text, ('Firmware'::character varying)::text, ('Configuration'::character varying)::text, ('Security Patch'::character varying)::text, ('Hotfix'::character varying)::text])))
);
COMMENT ON TABLE public.patches IS 'Reusable patch definitions that can be applied to multiple assets';
COMMENT ON COLUMN public.patches.estimated_downtime IS 'Estimated downtime in minutes for patch installation';
CREATE TABLE public.recalls (
    recall_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    fda_recall_number character varying(50) NOT NULL,
    recall_date date NOT NULL,
    product_description text,
    reason_for_recall text,
    manufacturer_name character varying(100),
    product_code text,
    recall_classification character varying(20),
    recall_status character varying(20) DEFAULT 'Active'::character varying,
    fda_data jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT recalls_recall_status_check CHECK (((recall_status)::text = ANY (ARRAY[('Active'::character varying)::text, ('Resolved'::character varying)::text, ('Closed'::character varying)::text])))
);
CREATE VIEW public.recall_summary AS
 SELECT drl.link_id,
    md.device_id,
    a.hostname,
    a.ip_address,
    a.department,
    a.criticality,
    r.fda_recall_number,
    r.recall_date,
    r.reason_for_recall,
    r.recall_classification,
    drl.remediation_status,
    drl.due_date
   FROM (((public.device_recalls_link drl
     JOIN public.medical_devices md ON ((drl.device_id = md.device_id)))
     JOIN public.assets a ON ((md.asset_id = a.asset_id)))
     JOIN public.recalls r ON ((drl.recall_id = r.recall_id)));
CREATE TABLE public.risk_matrix_config (
    config_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    config_name character varying(100) NOT NULL,
    is_active boolean DEFAULT true,
    kev_weight integer DEFAULT 100,
    clinical_high_score integer DEFAULT 10,
    business_medium_score integer DEFAULT 5,
    non_essential_score integer DEFAULT 1,
    location_weight_multiplier numeric(3,2) DEFAULT 1.0,
    critical_severity_score integer DEFAULT 10,
    high_severity_score integer DEFAULT 7,
    medium_severity_score integer DEFAULT 4,
    low_severity_score integer DEFAULT 1,
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    epss_weight_enabled boolean DEFAULT true,
    epss_high_threshold numeric(5,4) DEFAULT 0.7000,
    epss_weight_score integer DEFAULT 20
);
COMMENT ON COLUMN public.risk_matrix_config.epss_weight_enabled IS 'Whether to include EPSS scores in risk calculations';
COMMENT ON COLUMN public.risk_matrix_config.epss_high_threshold IS 'EPSS score threshold for high exploitation risk (0.0000-1.0000)';
COMMENT ON COLUMN public.risk_matrix_config.epss_weight_score IS 'Points added to risk score for high EPSS vulnerabilities';
CREATE MATERIALIZED VIEW public.risk_priority_view AS
 SELECT dvl.link_id,
    dvl.device_id,
    dvl.cve_id,
    md.asset_id,
    a.hostname,
    a.ip_address,
    a.criticality AS asset_criticality,
    a.department,
    l.location_id,
    l.location_name,
    l.criticality AS location_criticality,
    v.severity,
    v.cvss_v3_score,
    v.is_kev,
    v.kev_due_date,
    v.description AS vulnerability_description,
    v.epss_score,
    v.epss_percentile,
    v.epss_date,
    v.epss_last_updated,
    dvl.remediation_status,
    dvl.due_date,
    dvl.vendor_status,
    dvl.vendor_name,
    dvl.vendor_ticket_id,
    dvl.patch_expected_date,
    dvl.assigned_to,
    u.username AS assigned_to_name,
    md.device_name,
    md.brand_name,
    md.manufacturer_name,
    (((((
        CASE
            WHEN (v.is_kev = true) THEN rmc.kev_weight
            ELSE 0
        END +
        CASE a.criticality
            WHEN 'Clinical-High'::text THEN rmc.clinical_high_score
            WHEN 'Business-Medium'::text THEN rmc.business_medium_score
            WHEN 'Non-Essential'::text THEN rmc.non_essential_score
            ELSE 0
        END))::numeric + COALESCE(((l.criticality)::numeric * rmc.location_weight_multiplier), (0)::numeric)) + (
        CASE v.severity
            WHEN 'Critical'::text THEN rmc.critical_severity_score
            WHEN 'High'::text THEN rmc.high_severity_score
            WHEN 'Medium'::text THEN rmc.medium_severity_score
            WHEN 'Low'::text THEN rmc.low_severity_score
            ELSE 0
        END)::numeric) + (
        CASE
            WHEN ((rmc.epss_weight_enabled = true) AND (v.epss_score >= rmc.epss_high_threshold)) THEN rmc.epss_weight_score
            ELSE 0
        END)::numeric) AS calculated_risk_score,
        CASE
            WHEN ((((((
            CASE
                WHEN (v.is_kev = true) THEN rmc.kev_weight
                ELSE 0
            END +
            CASE a.criticality
                WHEN 'Clinical-High'::text THEN rmc.clinical_high_score
                WHEN 'Business-Medium'::text THEN rmc.business_medium_score
                WHEN 'Non-Essential'::text THEN rmc.non_essential_score
                ELSE 0
            END))::numeric + COALESCE(((l.criticality)::numeric * rmc.location_weight_multiplier), (0)::numeric)) + (
            CASE v.severity
                WHEN 'Critical'::text THEN rmc.critical_severity_score
                WHEN 'High'::text THEN rmc.high_severity_score
                WHEN 'Medium'::text THEN rmc.medium_severity_score
                WHEN 'Low'::text THEN rmc.low_severity_score
                ELSE 0
            END)::numeric) + (
            CASE
                WHEN ((rmc.epss_weight_enabled = true) AND (v.epss_score >= rmc.epss_high_threshold)) THEN rmc.epss_weight_score
                ELSE 0
            END)::numeric) >= (800)::numeric) THEN 1
            WHEN ((((((
            CASE
                WHEN (v.is_kev = true) THEN rmc.kev_weight
                ELSE 0
            END +
            CASE a.criticality
                WHEN 'Clinical-High'::text THEN rmc.clinical_high_score
                WHEN 'Business-Medium'::text THEN rmc.business_medium_score
                WHEN 'Non-Essential'::text THEN rmc.non_essential_score
                ELSE 0
            END))::numeric + COALESCE(((l.criticality)::numeric * rmc.location_weight_multiplier), (0)::numeric)) + (
            CASE v.severity
                WHEN 'Critical'::text THEN rmc.critical_severity_score
                WHEN 'High'::text THEN rmc.high_severity_score
                WHEN 'Medium'::text THEN rmc.medium_severity_score
                WHEN 'Low'::text THEN rmc.low_severity_score
                ELSE 0
            END)::numeric) + (
            CASE
                WHEN ((rmc.epss_weight_enabled = true) AND (v.epss_score >= rmc.epss_high_threshold)) THEN rmc.epss_weight_score
                ELSE 0
            END)::numeric) >= (400)::numeric) THEN 2
            WHEN ((((((
            CASE
                WHEN (v.is_kev = true) THEN rmc.kev_weight
                ELSE 0
            END +
            CASE a.criticality
                WHEN 'Clinical-High'::text THEN rmc.clinical_high_score
                WHEN 'Business-Medium'::text THEN rmc.business_medium_score
                WHEN 'Non-Essential'::text THEN rmc.non_essential_score
                ELSE 0
            END))::numeric + COALESCE(((l.criticality)::numeric * rmc.location_weight_multiplier), (0)::numeric)) + (
            CASE v.severity
                WHEN 'Critical'::text THEN rmc.critical_severity_score
                WHEN 'High'::text THEN rmc.high_severity_score
                WHEN 'Medium'::text THEN rmc.medium_severity_score
                WHEN 'Low'::text THEN rmc.low_severity_score
                ELSE 0
            END)::numeric) + (
            CASE
                WHEN ((rmc.epss_weight_enabled = true) AND (v.epss_score >= rmc.epss_high_threshold)) THEN rmc.epss_weight_score
                ELSE 0
            END)::numeric) >= (200)::numeric) THEN 3
            ELSE 4
        END AS priority_tier,
        CASE
            WHEN (dvl.due_date IS NOT NULL) THEN (CURRENT_DATE - dvl.due_date)
            ELSE NULL::integer
        END AS days_overdue
   FROM ((((((public.device_vulnerabilities_link dvl
     JOIN public.medical_devices md ON ((dvl.device_id = md.device_id)))
     JOIN public.assets a ON ((md.asset_id = a.asset_id)))
     LEFT JOIN public.locations l ON ((a.location_id = l.location_id)))
     JOIN public.vulnerabilities v ON (((dvl.cve_id)::text = (v.cve_id)::text)))
     LEFT JOIN public.users u ON ((dvl.assigned_to = u.user_id)))
     CROSS JOIN ( SELECT risk_matrix_config.config_id,
            risk_matrix_config.config_name,
            risk_matrix_config.is_active,
            risk_matrix_config.kev_weight,
            risk_matrix_config.clinical_high_score,
            risk_matrix_config.business_medium_score,
            risk_matrix_config.non_essential_score,
            risk_matrix_config.location_weight_multiplier,
            risk_matrix_config.critical_severity_score,
            risk_matrix_config.high_severity_score,
            risk_matrix_config.medium_severity_score,
            risk_matrix_config.low_severity_score,
            risk_matrix_config.created_by,
            risk_matrix_config.created_at,
            risk_matrix_config.updated_at,
            risk_matrix_config.epss_weight_enabled,
            risk_matrix_config.epss_high_threshold,
            risk_matrix_config.epss_weight_score
           FROM public.risk_matrix_config
          WHERE (risk_matrix_config.is_active = true)
          ORDER BY risk_matrix_config.created_at DESC
         LIMIT 1) rmc)
  WITH NO DATA;
CREATE TABLE public.risks (
    asset_id uuid NOT NULL,
    device_class character varying(50),
    type character varying(100),
    type_display_name character varying(255),
    display_name character varying(255),
    risk_id character varying(255) NOT NULL,
    risk_type_display_name character varying(100),
    risk_group character varying(255),
    name character varying(255),
    risk_score numeric(10,2) DEFAULT 0,
    risk_score_level character varying(50),
    cvss numeric(10,2),
    epss numeric(10,5),
    availability_score character varying(50),
    confidentiality_score character varying(50),
    integrity_score character varying(50),
    impact_confidentiality character varying(50),
    impact_patient_safety character varying(50),
    impact_service_disruption character varying(50),
    nhs_published_date timestamp without time zone,
    nhs_severity character varying(50),
    nhs_threat_id character varying(100),
    description text,
    status_display_name character varying(100),
    category character varying(100),
    has_malware boolean DEFAULT false,
    tags_easy_to_weaponize boolean DEFAULT false,
    tags_exploit_code_maturity character varying(50),
    tags_exploited_in_the_wild boolean DEFAULT false,
    tags_lateral_movement boolean DEFAULT false,
    tags_malware jsonb DEFAULT '[]'::jsonb,
    site character varying(255),
    link jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    external_id character varying(255),
    CONSTRAINT risks_asset_id_check CHECK ((asset_id IS NOT NULL))
);
COMMENT ON TABLE public.risks IS 'Comprehensive risk tracking table including vulnerabilities, threats, and security assessments';
COMMENT ON COLUMN public.risks.asset_id IS 'UUID reference to the associated asset/device';
COMMENT ON COLUMN public.risks.device_class IS 'Device classification (e.g., IoMT, IT, OT)';
COMMENT ON COLUMN public.risks.type IS 'Device type code (e.g., IV_PUMP)';
COMMENT ON COLUMN public.risks.type_display_name IS 'Human-readable device type name';
COMMENT ON COLUMN public.risks.display_name IS 'Display name/identifier for the device';
COMMENT ON COLUMN public.risks.risk_id IS 'Risk identifier (e.g., CVE-ID)';
COMMENT ON COLUMN public.risks.risk_type_display_name IS 'Type of risk (e.g., Vulnerability)';
COMMENT ON COLUMN public.risks.risk_group IS 'Risk grouping/category';
COMMENT ON COLUMN public.risks.name IS 'Risk name/title';
COMMENT ON COLUMN public.risks.risk_score IS 'Calculated risk score';
COMMENT ON COLUMN public.risks.risk_score_level IS 'Risk level classification (e.g., Low, Medium, High, Critical)';
COMMENT ON COLUMN public.risks.cvss IS 'CVSS score for vulnerabilities';
COMMENT ON COLUMN public.risks.epss IS 'EPSS (Exploit Prediction Scoring System) score';
COMMENT ON COLUMN public.risks.availability_score IS 'CIA Triad - Availability impact score';
COMMENT ON COLUMN public.risks.confidentiality_score IS 'CIA Triad - Confidentiality impact score';
COMMENT ON COLUMN public.risks.integrity_score IS 'CIA Triad - Integrity impact score';
COMMENT ON COLUMN public.risks.impact_confidentiality IS 'Confidentiality impact level';
COMMENT ON COLUMN public.risks.impact_patient_safety IS 'Patient safety impact level';
COMMENT ON COLUMN public.risks.impact_service_disruption IS 'Service disruption impact level';
COMMENT ON COLUMN public.risks.nhs_published_date IS 'NHS threat intelligence publication date';
COMMENT ON COLUMN public.risks.nhs_severity IS 'NHS severity classification';
COMMENT ON COLUMN public.risks.nhs_threat_id IS 'NHS threat identifier';
COMMENT ON COLUMN public.risks.description IS 'Detailed risk description';
COMMENT ON COLUMN public.risks.status_display_name IS 'Current status of the risk';
COMMENT ON COLUMN public.risks.category IS 'Risk category';
COMMENT ON COLUMN public.risks.has_malware IS 'Flag indicating malware presence';
COMMENT ON COLUMN public.risks.tags_easy_to_weaponize IS 'Tag indicating if easily weaponizable';
COMMENT ON COLUMN public.risks.tags_exploit_code_maturity IS 'Exploit code maturity level';
COMMENT ON COLUMN public.risks.tags_exploited_in_the_wild IS 'Flag indicating active exploitation';
COMMENT ON COLUMN public.risks.tags_lateral_movement IS 'Flag indicating lateral movement capability';
COMMENT ON COLUMN public.risks.tags_malware IS 'JSON array of malware tags';
COMMENT ON COLUMN public.risks.site IS 'Site/location identifier';
COMMENT ON COLUMN public.risks.link IS 'JSON object containing related links';
COMMENT ON COLUMN public.risks.created_at IS 'Record creation timestamp';
COMMENT ON COLUMN public.risks.updated_at IS 'Record last update timestamp';
COMMENT ON COLUMN public.risks.id IS 'Auto-generated UUID primary key for each risk record (migrated from VARCHAR to UUID)';
COMMENT ON COLUMN public.risks.external_id IS 'External system risk identifier (e.g., Cynerio risk ID)';
CREATE TABLE public.sbom_evaluation_logs (
    log_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    queue_id uuid,
    sbom_id uuid,
    device_id uuid,
    evaluation_started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    evaluation_completed_at timestamp without time zone,
    evaluation_duration_seconds integer,
    components_evaluated integer DEFAULT 0,
    vulnerabilities_found integer DEFAULT 0,
    vulnerabilities_stored integer DEFAULT 0,
    nvd_api_calls_made integer DEFAULT 0,
    nvd_api_failures integer DEFAULT 0,
    status character varying(20),
    error_message text,
    evaluation_metadata jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT sbom_evaluation_logs_status_check CHECK (((status)::text = ANY (ARRAY[('Success'::character varying)::text, ('Failed'::character varying)::text, ('Partial'::character varying)::text])))
);
COMMENT ON TABLE public.sbom_evaluation_logs IS 'Detailed log of all SBOM evaluation attempts and results';
COMMENT ON COLUMN public.sbom_evaluation_logs.nvd_api_calls_made IS 'Number of NVD API calls made during evaluation';
CREATE TABLE public.sbom_evaluation_queue (
    queue_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    sbom_id uuid NOT NULL,
    device_id uuid NOT NULL,
    priority integer DEFAULT 5,
    status character varying(20) DEFAULT 'Queued'::character varying,
    queued_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    vulnerabilities_found integer DEFAULT 0,
    vulnerabilities_stored integer DEFAULT 0,
    components_evaluated integer DEFAULT 0,
    error_message text,
    retry_count integer DEFAULT 0,
    max_retries integer DEFAULT 3,
    queued_by uuid,
    evaluation_metadata jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT sbom_evaluation_queue_priority_check CHECK (((priority >= 1) AND (priority <= 10))),
    CONSTRAINT sbom_evaluation_queue_status_check CHECK (((status)::text = ANY (ARRAY[('Queued'::character varying)::text, ('Processing'::character varying)::text, ('Completed'::character varying)::text, ('Failed'::character varying)::text, ('Cancelled'::character varying)::text])))
);
COMMENT ON TABLE public.sbom_evaluation_queue IS 'Queue system for background SBOM vulnerability evaluation against NVD';
COMMENT ON COLUMN public.sbom_evaluation_queue.priority IS 'Priority 1 (highest) to 10 (lowest) for queue processing';
COMMENT ON COLUMN public.sbom_evaluation_queue.status IS 'Current status of the evaluation job';
CREATE TABLE public.sboms (
    sbom_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    device_id uuid,
    format character varying(20) NOT NULL,
    content jsonb NOT NULL,
    file_name character varying(255),
    file_size integer,
    uploaded_by uuid,
    uploaded_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    parsed_at timestamp without time zone,
    parsing_status character varying(20) DEFAULT 'Pending'::character varying,
    last_evaluated_at timestamp without time zone,
    evaluation_status character varying(20) DEFAULT 'Pending'::character varying,
    vulnerabilities_count integer DEFAULT 0,
    asset_id uuid,
    CONSTRAINT sboms_device_or_asset_check CHECK (((device_id IS NOT NULL) OR (asset_id IS NOT NULL))),
    CONSTRAINT sboms_evaluation_status_check CHECK (((evaluation_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Queued'::character varying)::text, ('Completed'::character varying)::text, ('Failed'::character varying)::text]))),
    CONSTRAINT sboms_format_check CHECK (((format)::text = ANY (ARRAY[('CycloneDX'::character varying)::text, ('SPDX'::character varying)::text, ('spdx-tag-value'::character varying)::text, ('JSON'::character varying)::text, ('XML'::character varying)::text]))),
    CONSTRAINT sboms_parsing_status_check CHECK (((parsing_status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Success'::character varying)::text, ('Failed'::character varying)::text, ('Partial'::character varying)::text])))
);
COMMENT ON COLUMN public.sboms.device_id IS 'Reference to medical_devices table for mapped devices (optional if asset_id is provided)';
COMMENT ON COLUMN public.sboms.asset_id IS 'Reference to assets table for unmapped devices (optional if device_id is provided)';
CREATE VIEW public.scheduled_recall_tasks_view AS
 SELECT st.task_id,
    st.task_type,
    st.recall_id,
    r.fda_recall_number,
    r.recall_date,
    r.product_description,
    r.manufacturer_name,
    r.recall_classification,
    r.recall_status,
    st.device_id,
    md.device_name,
    md.brand_name,
    md.model_number,
    md.k_number,
    a.hostname,
    a.asset_tag,
    a.location,
    a.department,
    l.location_name,
    st.assigned_to,
    u.username AS assigned_to_username,
    u.username AS assigned_to_name,
    u.email AS assigned_to_email,
    st.assigned_by,
    assigned_by_user.username AS assigned_by_username,
    assigned_by_user.username AS assigned_by_name,
    st.scheduled_date,
    st.implementation_date,
    st.estimated_downtime,
    st.actual_downtime,
    st.status,
    st.task_description,
    st.notes,
    st.completion_notes,
    st.recall_priority,
    st.remediation_type,
    st.affected_serial_numbers,
    st.vendor_contact_required,
    st.fda_notification_required,
    st.patient_safety_impact,
    st.created_at,
    st.updated_at,
    st.completed_at,
    (CURRENT_DATE - r.recall_date) AS days_since_recall,
    (
        CASE
            WHEN ((st.recall_priority)::text = 'Critical'::text) THEN 100
            WHEN ((st.recall_priority)::text = 'High'::text) THEN 80
            WHEN ((st.recall_priority)::text = 'Medium'::text) THEN 60
            WHEN ((st.recall_priority)::text = 'Low'::text) THEN 40
            ELSE 50
        END +
        CASE
            WHEN ((CURRENT_DATE - r.recall_date) > 30) THEN 20
            WHEN ((CURRENT_DATE - r.recall_date) > 14) THEN 10
            ELSE 0
        END) AS urgency_score
   FROM ((((((public.scheduled_tasks st
     JOIN public.recalls r ON ((st.recall_id = r.recall_id)))
     JOIN public.medical_devices md ON ((st.device_id = md.device_id)))
     JOIN public.assets a ON ((md.asset_id = a.asset_id)))
     LEFT JOIN public.locations l ON ((a.location_id = l.location_id)))
     LEFT JOIN public.users u ON ((st.assigned_to = u.user_id)))
     LEFT JOIN public.users assigned_by_user ON ((st.assigned_by = assigned_by_user.user_id)))
  WHERE ((st.task_type)::text = 'recall_maintenance'::text);
COMMENT ON VIEW public.scheduled_recall_tasks_view IS 'Comprehensive view of recall maintenance tasks with device and recall details';
CREATE TABLE public.schema_migrations (
    version character varying(255) NOT NULL,
    applied_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.security_audit_log (
    id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    user_id integer,
    username character varying(100),
    ip_address character varying(45),
    description text NOT NULL,
    metadata jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.security_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.security_audit_log_id_seq OWNED BY public.security_audit_log.id;
CREATE TABLE public.security_incidents (
    id integer NOT NULL,
    incident_type character varying(50) NOT NULL,
    severity character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    description text NOT NULL,
    actions_taken text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    resolved_at timestamp without time zone,
    created_by integer,
    resolved_by integer,
    CONSTRAINT security_incidents_severity_check CHECK (((severity)::text = ANY (ARRAY[('low'::character varying)::text, ('medium'::character varying)::text, ('high'::character varying)::text, ('critical'::character varying)::text]))),
    CONSTRAINT security_incidents_status_check CHECK (((status)::text = ANY (ARRAY[('open'::character varying)::text, ('investigating'::character varying)::text, ('resolved'::character varying)::text, ('closed'::character varying)::text])))
);
CREATE SEQUENCE public.security_incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.security_incidents_id_seq OWNED BY public.security_incidents.id;
CREATE VIEW public.security_metrics AS
 SELECT ( SELECT count(*) AS count
           FROM public.failed_login_attempts
          WHERE (failed_login_attempts.attempt_time >= (now() - '24:00:00'::interval))) AS failed_logins_24h,
    ( SELECT count(*) AS count
           FROM public.security_incidents
          WHERE ((security_incidents.status)::text = ANY (ARRAY[('open'::character varying)::text, ('investigating'::character varying)::text]))) AS active_incidents,
    ( SELECT count(*) AS count
           FROM public.ip_blocklist
          WHERE (((ip_blocklist.expires_at IS NULL) OR (ip_blocklist.expires_at > now())) AND (ip_blocklist.is_permanent = true))) AS blocked_ips_permanent,
    ( SELECT count(*) AS count
           FROM public.ip_blocklist
          WHERE ((ip_blocklist.expires_at > now()) AND (ip_blocklist.is_permanent = false))) AS blocked_ips_temporary,
    ( SELECT count(DISTINCT failed_login_attempts.ip_address) AS count
           FROM public.failed_login_attempts
          WHERE (failed_login_attempts.attempt_time >= (now() - '01:00:00'::interval))) AS unique_ips_last_hour;
CREATE TABLE public.security_settings (
    id integer NOT NULL,
    setting_key character varying(100) NOT NULL,
    setting_value text,
    category character varying(50) DEFAULT 'general'::character varying NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_by integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.security_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.security_settings_id_seq OWNED BY public.security_settings.id;
CREATE TABLE public.software_components (
    component_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    sbom_id uuid,
    name character varying(255) NOT NULL,
    version character varying(100),
    vendor character varying(100),
    license character varying(100),
    purl character varying(500),
    cpe character varying(500),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    package_id uuid,
    version_id uuid
);
CREATE TABLE public.software_package_risk_scores (
    risk_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    package_id uuid NOT NULL,
    version_id uuid NOT NULL,
    total_vulnerabilities integer DEFAULT 0,
    kev_count integer DEFAULT 0,
    critical_severity_count integer DEFAULT 0,
    high_severity_count integer DEFAULT 0,
    medium_severity_count integer DEFAULT 0,
    low_severity_count integer DEFAULT 0,
    affected_assets_count integer DEFAULT 0,
    tier1_assets_count integer DEFAULT 0,
    tier2_assets_count integer DEFAULT 0,
    tier3_assets_count integer DEFAULT 0,
    highest_risk_score integer DEFAULT 0,
    aggregate_risk_score integer DEFAULT 0,
    oldest_vulnerability_date timestamp without time zone,
    has_available_patch boolean DEFAULT false,
    remediation_priority character varying(20) DEFAULT 'Medium'::character varying,
    calculated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.software_package_risk_scores IS 'Aggregated risk scores for software packages considering all affected assets';
CREATE TABLE public.software_package_versions (
    version_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    package_id uuid NOT NULL,
    version character varying(100) NOT NULL,
    is_vulnerable boolean DEFAULT false,
    vulnerability_count integer DEFAULT 0,
    affected_asset_count integer DEFAULT 0,
    highest_severity character varying(20),
    first_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    remediated_devices jsonb DEFAULT '[]'::jsonb
);
COMMENT ON TABLE public.software_package_versions IS 'All versions of software packages found in the environment with vulnerability status';
CREATE TABLE public.software_packages (
    package_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    vendor character varying(255),
    latest_safe_version character varying(100),
    cpe_product character varying(255),
    description text,
    package_type character varying(50) DEFAULT 'Software'::character varying,
    first_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    remediated_devices jsonb DEFAULT '[]'::jsonb
);
COMMENT ON TABLE public.software_packages IS 'Unique software packages across all assets, deduplicated from software_components';
CREATE MATERIALIZED VIEW public.software_package_risk_priority_view AS
 SELECT sprs.risk_id,
    sprs.package_id,
    sprs.version_id,
    sp.name AS package_name,
    sp.vendor,
    spv.version,
    sp.latest_safe_version,
    sprs.total_vulnerabilities,
    sprs.kev_count,
    sprs.critical_severity_count,
    sprs.high_severity_count,
    sprs.medium_severity_count,
    sprs.low_severity_count,
    sprs.affected_assets_count,
    sprs.tier1_assets_count,
    sprs.tier2_assets_count,
    sprs.tier3_assets_count,
    sprs.highest_risk_score,
    sprs.aggregate_risk_score,
    sprs.oldest_vulnerability_date,
    sprs.has_available_patch,
    sprs.remediation_priority,
    ( SELECT a.hostname
           FROM (((public.assets a
             JOIN public.medical_devices md ON ((a.asset_id = md.asset_id)))
             JOIN public.device_vulnerabilities_link dvl ON ((md.device_id = dvl.device_id)))
             JOIN public.software_components sc ON ((dvl.component_id = sc.component_id)))
          WHERE (((sc.name)::text = (sp.name)::text) AND ((sc.version)::text = (spv.version)::text) AND ((dvl.remediation_status)::text = 'Open'::text))
          ORDER BY
                CASE a.criticality
                    WHEN 'Clinical-High'::text THEN 1
                    WHEN 'Business-Medium'::text THEN 2
                    WHEN 'Non-Essential'::text THEN 3
                    ELSE NULL::integer
                END, a.location_id DESC
         LIMIT 1) AS top_priority_hostname,
    ( SELECT l.location_name
           FROM ((((public.assets a
             JOIN public.medical_devices md ON ((a.asset_id = md.asset_id)))
             JOIN public.device_vulnerabilities_link dvl ON ((md.device_id = dvl.device_id)))
             JOIN public.software_components sc ON ((dvl.component_id = sc.component_id)))
             LEFT JOIN public.locations l ON ((a.location_id = l.location_id)))
          WHERE (((sc.name)::text = (sp.name)::text) AND ((sc.version)::text = (spv.version)::text) AND ((dvl.remediation_status)::text = 'Open'::text))
          ORDER BY
                CASE a.criticality
                    WHEN 'Clinical-High'::text THEN 1
                    WHEN 'Business-Medium'::text THEN 2
                    WHEN 'Non-Essential'::text THEN 3
                    ELSE NULL::integer
                END, a.location_id DESC
         LIMIT 1) AS top_priority_location,
    ( SELECT a.department
           FROM (((public.assets a
             JOIN public.medical_devices md ON ((a.asset_id = md.asset_id)))
             JOIN public.device_vulnerabilities_link dvl ON ((md.device_id = dvl.device_id)))
             JOIN public.software_components sc ON ((dvl.component_id = sc.component_id)))
          WHERE (((sc.name)::text = (sp.name)::text) AND ((sc.version)::text = (spv.version)::text) AND ((dvl.remediation_status)::text = 'Open'::text))
          ORDER BY
                CASE a.criticality
                    WHEN 'Clinical-High'::text THEN 1
                    WHEN 'Business-Medium'::text THEN 2
                    WHEN 'Non-Essential'::text THEN 3
                    ELSE NULL::integer
                END, a.location_id DESC
         LIMIT 1) AS top_priority_department,
    ( SELECT count(*) AS count
           FROM public.patches p
          WHERE ((p.target_package_id = sp.package_id) AND (p.is_active = true))) AS available_patch_count,
    (date_part('day'::text, (CURRENT_TIMESTAMP - (sprs.oldest_vulnerability_date)::timestamp with time zone)))::integer AS days_since_discovery,
    sprs.calculated_at
   FROM ((public.software_package_risk_scores sprs
     JOIN public.software_packages sp ON ((sprs.package_id = sp.package_id)))
     JOIN public.software_package_versions spv ON ((sprs.version_id = spv.version_id)))
  WHERE (sprs.total_vulnerabilities > 0)
  ORDER BY sprs.kev_count DESC, sprs.tier1_assets_count DESC, sprs.aggregate_risk_score DESC, sprs.critical_severity_count DESC
  WITH NO DATA;
COMMENT ON MATERIALIZED VIEW public.software_package_risk_priority_view IS 'Prioritized view of vulnerable software packages for remediation planning';
CREATE TABLE public.software_package_vulnerabilities (
    spv_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    package_id uuid NOT NULL,
    version_id uuid,
    cve_id character varying(20) NOT NULL,
    affects_version_range character varying(255),
    discovered_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.software_package_vulnerabilities IS 'Maps software packages and versions to CVE vulnerabilities';
CREATE TABLE public.system_logs (
    id integer NOT NULL,
    log_level character varying(20) NOT NULL,
    message text NOT NULL,
    context jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE SEQUENCE public.system_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.system_logs_id_seq OWNED BY public.system_logs.id;
CREATE TABLE public.task_consolidation_mapping (
    consolidated_task_id uuid NOT NULL,
    original_task_id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.threats (
    threat_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    threat_name character varying(255) NOT NULL,
    threat_type character varying(50) DEFAULT 'CVE'::character varying NOT NULL,
    description text,
    severity character varying(20) DEFAULT 'Medium'::character varying,
    cwe_id character varying(20),
    cve_id character varying(20),
    created_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT threats_type_check CHECK (((threat_type)::text = ANY (ARRAY[('CVE'::character varying)::text, ('Zero-Day'::character varying)::text, ('Novel'::character varying)::text, ('Configuration'::character varying)::text, ('CWE'::character varying)::text, ('Custom'::character varying)::text])))
);
CREATE TABLE public.tier_change_audit (
    id integer NOT NULL,
    link_id uuid NOT NULL,
    cve_id character varying(20) NOT NULL,
    old_tier integer,
    new_tier integer,
    change_reason character varying(100),
    changed_by character varying(100),
    changed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    risk_score integer,
    is_kev boolean
);
CREATE SEQUENCE public.tier_change_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.tier_change_audit_id_seq OWNED BY public.tier_change_audit.id;
CREATE TABLE public.user_sessions (
    session_id character varying(128) NOT NULL,
    user_id uuid,
    ip_address inet NOT NULL,
    user_agent text,
    login_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_activity timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    is_active boolean DEFAULT true,
    terminated_at timestamp without time zone,
    terminated_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE public.vulnerability_overrides (
    cve_id character varying(20) NOT NULL,
    override_status character varying(50) NOT NULL,
    note text NOT NULL,
    accepted_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerability_overrides_override_status_check CHECK (((override_status)::text = 'Risk Accepted'::text))
);
CREATE TABLE public.vulnerability_overrides_device (
    cve_id character varying(20) NOT NULL,
    device_id uuid NOT NULL,
    override_status character varying(50) NOT NULL,
    note text NOT NULL,
    accepted_by uuid,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerability_overrides_device_override_status_check CHECK (((override_status)::text = 'Risk Accepted'::text))
);
CREATE TABLE public.vulnerability_scans (
    scan_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid,
    device_id uuid,
    scan_type character varying(20) DEFAULT 'full'::character varying,
    include_sbom boolean DEFAULT false,
    status character varying(20) DEFAULT 'Pending'::character varying,
    requested_by uuid,
    requested_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    scan_results jsonb,
    error_message text,
    vulnerabilities_found integer DEFAULT 0,
    vulnerabilities_stored integer DEFAULT 0,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerability_scans_scan_type_check CHECK (((scan_type)::text = ANY (ARRAY[('full'::character varying)::text, ('quick'::character varying)::text, ('deep'::character varying)::text, ('sbom'::character varying)::text]))),
    CONSTRAINT vulnerability_scans_status_check CHECK (((status)::text = ANY (ARRAY[('Pending'::character varying)::text, ('Running'::character varying)::text, ('Completed'::character varying)::text, ('Failed'::character varying)::text, ('Cancelled'::character varying)::text])))
);
CREATE VIEW public.vulnerability_summary AS
 SELECT dvl.link_id,
    md.device_id,
    a.hostname,
    a.ip_address,
    a.department,
    a.criticality,
    v.cve_id,
    v.severity,
    v.cvss_v3_score,
    sc.name AS component_name,
    sc.version AS component_version,
    dvl.remediation_status,
    dvl.due_date
   FROM ((((public.device_vulnerabilities_link dvl
     JOIN public.medical_devices md ON ((dvl.device_id = md.device_id)))
     JOIN public.assets a ON ((md.asset_id = a.asset_id)))
     JOIN public.vulnerabilities v ON (((dvl.cve_id)::text = (v.cve_id)::text)))
     JOIN public.software_components sc ON ((dvl.component_id = sc.component_id)));
ALTER TABLE ONLY public.failed_login_attempts ALTER COLUMN id SET DEFAULT nextval('public.failed_login_attempts_id_seq'::regclass);
ALTER TABLE ONLY public.ip_blocklist ALTER COLUMN id SET DEFAULT nextval('public.ip_blocklist_id_seq'::regclass);
ALTER TABLE ONLY public.ip_locations ALTER COLUMN id SET DEFAULT nextval('public.ip_locations_id_seq'::regclass);
ALTER TABLE ONLY public.security_audit_log ALTER COLUMN id SET DEFAULT nextval('public.security_audit_log_id_seq'::regclass);
ALTER TABLE ONLY public.security_incidents ALTER COLUMN id SET DEFAULT nextval('public.security_incidents_id_seq'::regclass);
ALTER TABLE ONLY public.security_settings ALTER COLUMN id SET DEFAULT nextval('public.security_settings_id_seq'::regclass);
ALTER TABLE ONLY public.system_logs ALTER COLUMN id SET DEFAULT nextval('public.system_logs_id_seq'::regclass);
ALTER TABLE ONLY public.tier_change_audit ALTER COLUMN id SET DEFAULT nextval('public.tier_change_audit_id_seq'::regclass);
ALTER TABLE ONLY public.action_device_links
    ADD CONSTRAINT action_device_links_action_id_device_id_key UNIQUE (action_id, device_id);
ALTER TABLE ONLY public.action_device_links
    ADD CONSTRAINT action_device_links_pkey PRIMARY KEY (link_id);
ALTER TABLE ONLY public.action_risk_scores
    ADD CONSTRAINT action_risk_scores_action_id_key UNIQUE (action_id);
ALTER TABLE ONLY public.action_risk_scores
    ADD CONSTRAINT action_risk_scores_pkey PRIMARY KEY (score_id);
ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_api_key_key UNIQUE (api_key);
ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (key_id);
ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (asset_id);
ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (log_id);
ALTER TABLE ONLY public.cisa_kev_catalog
    ADD CONSTRAINT cisa_kev_catalog_cve_id_key UNIQUE (cve_id);
ALTER TABLE ONLY public.cisa_kev_catalog
    ADD CONSTRAINT cisa_kev_catalog_pkey PRIMARY KEY (kev_id);
ALTER TABLE ONLY public.cisa_kev_sync_log
    ADD CONSTRAINT cisa_kev_sync_log_pkey PRIMARY KEY (sync_id);
ALTER TABLE ONLY public.compensating_controls_checklist
    ADD CONSTRAINT compensating_controls_checklist_pkey PRIMARY KEY (control_id);
ALTER TABLE ONLY public.cwe_reference
    ADD CONSTRAINT cwe_reference_pkey PRIMARY KEY (cwe_id);
ALTER TABLE ONLY public.dave_api_key_usage
    ADD CONSTRAINT dave_api_key_usage_pkey PRIMARY KEY (usage_id);
ALTER TABLE ONLY public.dave_api_keys
    ADD CONSTRAINT dave_api_keys_api_key_key UNIQUE (api_key);
ALTER TABLE ONLY public.dave_api_keys
    ADD CONSTRAINT dave_api_keys_pkey PRIMARY KEY (key_id);
ALTER TABLE ONLY public.device_recalls_link
    ADD CONSTRAINT device_recalls_link_device_id_recall_id_key UNIQUE (device_id, recall_id);
ALTER TABLE ONLY public.device_recalls_link
    ADD CONSTRAINT device_recalls_link_pkey PRIMARY KEY (link_id);
ALTER TABLE ONLY public.device_vulnerabilities_link
    ADD CONSTRAINT device_vulnerabilities_link_pkey PRIMARY KEY (link_id);
ALTER TABLE ONLY public.epss_score_history
    ADD CONSTRAINT epss_score_history_pkey PRIMARY KEY (history_id);
ALTER TABLE ONLY public.epss_sync_log
    ADD CONSTRAINT epss_sync_log_pkey PRIMARY KEY (sync_id);
ALTER TABLE ONLY public.failed_login_attempts
    ADD CONSTRAINT failed_login_attempts_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.ip_blocklist
    ADD CONSTRAINT ip_blocklist_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.ip_locations
    ADD CONSTRAINT ip_locations_ip_address_key UNIQUE (ip_address);
ALTER TABLE ONLY public.ip_locations
    ADD CONSTRAINT ip_locations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.location_ip_ranges
    ADD CONSTRAINT location_ip_ranges_pkey PRIMARY KEY (range_id);
ALTER TABLE ONLY public.locations
    ADD CONSTRAINT locations_location_code_key UNIQUE (location_code);
ALTER TABLE ONLY public.locations
    ADD CONSTRAINT locations_pkey PRIMARY KEY (location_id);
ALTER TABLE ONLY public.medical_devices
    ADD CONSTRAINT medical_devices_pkey PRIMARY KEY (device_id);
ALTER TABLE ONLY public.mfa_sessions
    ADD CONSTRAINT mfa_sessions_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (notification_id);
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_pkey PRIMARY KEY (application_id);
ALTER TABLE ONLY public.patches
    ADD CONSTRAINT patches_pkey PRIMARY KEY (patch_id);
ALTER TABLE ONLY public.recalls
    ADD CONSTRAINT recalls_fda_recall_number_key UNIQUE (fda_recall_number);
ALTER TABLE ONLY public.recalls
    ADD CONSTRAINT recalls_pkey PRIMARY KEY (recall_id);
ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_pkey PRIMARY KEY (action_id);
ALTER TABLE ONLY public.risk_matrix_config
    ADD CONSTRAINT risk_matrix_config_pkey PRIMARY KEY (config_id);
ALTER TABLE ONLY public.risks
    ADD CONSTRAINT risks_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.sbom_evaluation_logs
    ADD CONSTRAINT sbom_evaluation_logs_pkey PRIMARY KEY (log_id);
ALTER TABLE ONLY public.sbom_evaluation_queue
    ADD CONSTRAINT sbom_evaluation_queue_pkey PRIMARY KEY (queue_id);
ALTER TABLE ONLY public.sbom_evaluation_queue
    ADD CONSTRAINT sbom_evaluation_queue_sbom_id_status_key UNIQUE (sbom_id, status);
ALTER TABLE ONLY public.sboms
    ADD CONSTRAINT sboms_pkey PRIMARY KEY (sbom_id);
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_pkey PRIMARY KEY (task_id);
ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);
ALTER TABLE ONLY public.security_audit_log
    ADD CONSTRAINT security_audit_log_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.security_incidents
    ADD CONSTRAINT security_incidents_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.security_settings
    ADD CONSTRAINT security_settings_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.security_settings
    ADD CONSTRAINT security_settings_setting_key_key UNIQUE (setting_key);
ALTER TABLE ONLY public.software_components
    ADD CONSTRAINT software_components_pkey PRIMARY KEY (component_id);
ALTER TABLE ONLY public.software_package_risk_scores
    ADD CONSTRAINT software_package_risk_scores_package_id_version_id_key UNIQUE (package_id, version_id);
ALTER TABLE ONLY public.software_package_risk_scores
    ADD CONSTRAINT software_package_risk_scores_pkey PRIMARY KEY (risk_id);
ALTER TABLE ONLY public.software_package_versions
    ADD CONSTRAINT software_package_versions_package_id_version_key UNIQUE (package_id, version);
ALTER TABLE ONLY public.software_package_versions
    ADD CONSTRAINT software_package_versions_pkey PRIMARY KEY (version_id);
ALTER TABLE ONLY public.software_package_vulnerabilities
    ADD CONSTRAINT software_package_vulnerabiliti_package_id_version_id_cve_id_key UNIQUE (package_id, version_id, cve_id);
ALTER TABLE ONLY public.software_package_vulnerabilities
    ADD CONSTRAINT software_package_vulnerabilities_pkey PRIMARY KEY (spv_id);
ALTER TABLE ONLY public.software_packages
    ADD CONSTRAINT software_packages_name_vendor_key UNIQUE (name, vendor);
ALTER TABLE ONLY public.software_packages
    ADD CONSTRAINT software_packages_pkey PRIMARY KEY (package_id);
ALTER TABLE ONLY public.system_logs
    ADD CONSTRAINT system_logs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.task_consolidation_mapping
    ADD CONSTRAINT task_consolidation_mapping_pkey PRIMARY KEY (consolidated_task_id, original_task_id);
ALTER TABLE ONLY public.threats
    ADD CONSTRAINT threats_pkey PRIMARY KEY (threat_id);
ALTER TABLE ONLY public.tier_change_audit
    ADD CONSTRAINT tier_change_audit_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (session_id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (vulnerability_id);
ALTER TABLE ONLY public.vulnerability_overrides_device
    ADD CONSTRAINT vulnerability_overrides_device_pkey PRIMARY KEY (cve_id, device_id);
ALTER TABLE ONLY public.vulnerability_overrides
    ADD CONSTRAINT vulnerability_overrides_pkey PRIMARY KEY (cve_id);
ALTER TABLE ONLY public.vulnerability_scans
    ADD CONSTRAINT vulnerability_scans_pkey PRIMARY KEY (scan_id);
CREATE INDEX idx_action_device_links_action_id ON public.action_device_links USING btree (action_id);
CREATE INDEX idx_action_device_links_device_id ON public.action_device_links USING btree (device_id);
CREATE INDEX idx_action_device_links_device_risk ON public.action_device_links USING btree (device_risk_score DESC);
CREATE INDEX idx_action_device_links_patch_status ON public.action_device_links USING btree (patch_status);
CREATE UNIQUE INDEX idx_action_priority_view_action_id ON public.action_priority_view USING btree (action_id);
CREATE INDEX idx_action_priority_view_assigned ON public.action_priority_view USING btree (assigned_to);
CREATE INDEX idx_action_priority_view_due_date ON public.action_priority_view USING btree (due_date);
CREATE INDEX idx_action_priority_view_efficiency ON public.action_priority_view USING btree (efficiency_score DESC);
CREATE INDEX idx_action_priority_view_kev ON public.action_priority_view USING btree (is_kev);
CREATE INDEX idx_action_priority_view_status ON public.action_priority_view USING btree (status);
CREATE INDEX idx_action_priority_view_tier ON public.action_priority_view USING btree (priority_tier);
CREATE INDEX idx_action_priority_view_urgency ON public.action_priority_view USING btree (urgency_score DESC);
CREATE INDEX idx_action_risk_scores_action_id ON public.action_risk_scores USING btree (action_id);
CREATE INDEX idx_action_risk_scores_efficiency ON public.action_risk_scores USING btree (efficiency_score DESC);
CREATE INDEX idx_action_risk_scores_kev_count ON public.action_risk_scores USING btree (kev_count DESC);
CREATE INDEX idx_action_risk_scores_urgency ON public.action_risk_scores USING btree (urgency_score DESC);
CREATE INDEX idx_assets_asset_type ON public.assets USING btree (asset_type);
CREATE INDEX idx_assets_criticality ON public.assets USING btree (criticality);
CREATE INDEX idx_assets_department ON public.assets USING btree (department);
CREATE INDEX idx_assets_ip ON public.assets USING btree (ip_address);
CREATE INDEX idx_assets_ip_address ON public.assets USING btree (ip_address);
CREATE INDEX idx_assets_location ON public.assets USING btree (location_id);
CREATE INDEX idx_assets_location_method ON public.assets USING btree (location_assignment_method);
CREATE INDEX idx_assets_mac_address ON public.assets USING btree (mac_address);
CREATE INDEX idx_assets_source ON public.assets USING btree (source);
CREATE INDEX idx_assets_status ON public.assets USING btree (status);
CREATE INDEX idx_audit_log_cleanup ON public.security_audit_log USING btree (created_at);
CREATE INDEX idx_audit_log_created_at ON public.security_audit_log USING btree (created_at);
CREATE INDEX idx_audit_log_event_time ON public.security_audit_log USING btree (event_type, created_at);
CREATE INDEX idx_audit_log_event_type ON public.security_audit_log USING btree (event_type);
CREATE INDEX idx_audit_log_ip ON public.security_audit_log USING btree (ip_address);
CREATE INDEX idx_audit_log_user_id ON public.security_audit_log USING btree (user_id);
CREATE INDEX idx_audit_log_username ON public.security_audit_log USING btree (username);
CREATE INDEX idx_audit_logs_action ON public.audit_logs USING btree (action);
CREATE INDEX idx_audit_logs_timestamp ON public.audit_logs USING btree ("timestamp");
CREATE INDEX idx_audit_logs_user_id ON public.audit_logs USING btree (user_id);
CREATE INDEX idx_blocklist_active ON public.ip_blocklist USING btree (ip_address, expires_at, is_permanent);
CREATE INDEX idx_blocklist_expires ON public.ip_blocklist USING btree (expires_at);
CREATE INDEX idx_blocklist_ip ON public.ip_blocklist USING btree (ip_address);
CREATE INDEX idx_blocklist_permanent ON public.ip_blocklist USING btree (is_permanent);
CREATE INDEX idx_compensating_controls_link ON public.compensating_controls_checklist USING btree (link_id);
CREATE INDEX idx_dave_api_key_usage_created_at ON public.dave_api_key_usage USING btree (created_at);
CREATE INDEX idx_dave_api_key_usage_endpoint ON public.dave_api_key_usage USING btree (endpoint);
CREATE INDEX idx_dave_api_key_usage_key_id ON public.dave_api_key_usage USING btree (key_id);
CREATE INDEX idx_dave_api_keys_api_key ON public.dave_api_keys USING btree (api_key);
CREATE INDEX idx_dave_api_keys_expires_at ON public.dave_api_keys USING btree (expires_at);
CREATE INDEX idx_dave_api_keys_is_active ON public.dave_api_keys USING btree (is_active);
CREATE INDEX idx_dave_api_keys_key_hash ON public.dave_api_keys USING btree (key_hash);
CREATE INDEX idx_dave_api_keys_user_id ON public.dave_api_keys USING btree (user_id);
CREATE INDEX idx_device_vulnerabilities_cve_id ON public.device_vulnerabilities_link USING btree (cve_id);
CREATE INDEX idx_device_vulnerabilities_device_id ON public.device_vulnerabilities_link USING btree (device_id);
CREATE INDEX idx_device_vulnerabilities_link_asset_id ON public.device_vulnerabilities_link USING btree (asset_id);
CREATE INDEX idx_device_vulnerabilities_status ON public.device_vulnerabilities_link USING btree (remediation_status);
CREATE UNIQUE INDEX idx_dvl_device_component_cve_unique ON public.device_vulnerabilities_link USING btree (device_id, component_id, cve_id) WHERE (cve_id IS NOT NULL);
CREATE UNIQUE INDEX idx_dvl_device_component_vuln_unique ON public.device_vulnerabilities_link USING btree (device_id, component_id, vulnerability_id) WHERE (vulnerability_id IS NOT NULL);
CREATE INDEX idx_dvl_due_date ON public.device_vulnerabilities_link USING btree (due_date);
CREATE INDEX idx_dvl_priority_tier ON public.device_vulnerabilities_link USING btree (priority_tier);
CREATE INDEX idx_dvl_risk_score ON public.device_vulnerabilities_link USING btree (risk_score);
CREATE INDEX idx_dvl_vendor_status ON public.device_vulnerabilities_link USING btree (vendor_status);
CREATE INDEX idx_dvl_vulnerability_id ON public.device_vulnerabilities_link USING btree (vulnerability_id);
CREATE INDEX idx_epss_history_cve_date ON public.epss_score_history USING btree (cve_id, recorded_date DESC);
CREATE INDEX idx_epss_history_date ON public.epss_score_history USING btree (recorded_date DESC);
CREATE INDEX idx_epss_history_score ON public.epss_score_history USING btree (epss_score DESC);
CREATE INDEX idx_epss_sync_log_date ON public.epss_sync_log USING btree (sync_started_at DESC);
CREATE INDEX idx_epss_sync_log_status ON public.epss_sync_log USING btree (sync_status);
CREATE INDEX idx_eval_logs_created ON public.sbom_evaluation_logs USING btree (created_at DESC);
CREATE INDEX idx_eval_logs_device ON public.sbom_evaluation_logs USING btree (device_id);
CREATE INDEX idx_eval_logs_queue ON public.sbom_evaluation_logs USING btree (queue_id);
CREATE INDEX idx_eval_logs_sbom ON public.sbom_evaluation_logs USING btree (sbom_id);
CREATE INDEX idx_failed_logins_cleanup ON public.failed_login_attempts USING btree (attempt_time);
CREATE INDEX idx_failed_logins_ip ON public.failed_login_attempts USING btree (ip_address);
CREATE INDEX idx_failed_logins_ip_time ON public.failed_login_attempts USING btree (ip_address, attempt_time);
CREATE INDEX idx_failed_logins_time ON public.failed_login_attempts USING btree (attempt_time);
CREATE INDEX idx_failed_logins_username ON public.failed_login_attempts USING btree (username);
CREATE INDEX idx_failed_logins_username_time ON public.failed_login_attempts USING btree (username, attempt_time);
CREATE INDEX idx_incidents_created_at ON public.security_incidents USING btree (created_at);
CREATE INDEX idx_incidents_severity ON public.security_incidents USING btree (severity);
CREATE INDEX idx_incidents_status ON public.security_incidents USING btree (status);
CREATE INDEX idx_incidents_status_severity ON public.security_incidents USING btree (status, severity);
CREATE INDEX idx_incidents_status_time ON public.security_incidents USING btree (status, created_at);
CREATE INDEX idx_incidents_type ON public.security_incidents USING btree (incident_type);
CREATE INDEX idx_ip_locations_created_at ON public.ip_locations USING btree (created_at);
CREATE INDEX idx_ip_locations_ip_address ON public.ip_locations USING btree (ip_address);
CREATE INDEX idx_kev_cve_id ON public.cisa_kev_catalog USING btree (cve_id);
CREATE INDEX idx_kev_date_added ON public.cisa_kev_catalog USING btree (date_added DESC);
CREATE INDEX idx_kev_ransomware ON public.cisa_kev_catalog USING btree (known_ransomware_campaign_use) WHERE (known_ransomware_campaign_use = true);
CREATE INDEX idx_kev_sync_log_date ON public.cisa_kev_sync_log USING btree (sync_started_at DESC);
CREATE INDEX idx_kev_vendor_product ON public.cisa_kev_catalog USING btree (vendor_project, product);
CREATE INDEX idx_location_ip_ranges_cidr ON public.location_ip_ranges USING gist (cidr_notation inet_ops);
CREATE INDEX idx_location_ip_ranges_end ON public.location_ip_ranges USING btree (end_ip);
CREATE INDEX idx_location_ip_ranges_location ON public.location_ip_ranges USING btree (location_id);
CREATE INDEX idx_location_ip_ranges_start ON public.location_ip_ranges USING btree (start_ip);
CREATE INDEX idx_locations_active ON public.locations USING btree (is_active);
CREATE INDEX idx_locations_code ON public.locations USING btree (location_code);
CREATE INDEX idx_locations_criticality ON public.locations USING btree (criticality);
CREATE INDEX idx_locations_parent ON public.locations USING btree (parent_location_id);
CREATE INDEX idx_locations_type ON public.locations USING btree (location_type);
CREATE INDEX idx_medical_devices_applicant ON public.medical_devices USING btree (applicant);
CREATE INDEX idx_medical_devices_asset_id ON public.medical_devices USING btree (asset_id);
CREATE INDEX idx_medical_devices_brand ON public.medical_devices USING btree (brand_name);
CREATE INDEX idx_medical_devices_commercial_status ON public.medical_devices USING btree (commercial_status);
CREATE INDEX idx_medical_devices_decision_date ON public.medical_devices USING btree (decision_date);
CREATE INDEX idx_medical_devices_fda_class ON public.medical_devices USING btree (fda_class);
CREATE INDEX idx_medical_devices_implantable ON public.medical_devices USING btree (is_implantable);
CREATE INDEX idx_medical_devices_k_number ON public.medical_devices USING btree (k_number);
CREATE INDEX idx_medical_devices_manufacturer ON public.medical_devices USING btree (manufacturer_name);
CREATE INDEX idx_medical_devices_raw_510k_data ON public.medical_devices USING gin (raw_510k_data);
CREATE INDEX idx_mfa_sessions_created_at ON public.mfa_sessions USING btree (created_at);
CREATE INDEX idx_notifications_is_read ON public.notifications USING btree (is_read);
CREATE INDEX idx_notifications_type ON public.notifications USING btree (type);
CREATE INDEX idx_notifications_user_id ON public.notifications USING btree (user_id);
CREATE INDEX idx_package_versions_is_vulnerable ON public.software_package_versions USING btree (is_vulnerable);
CREATE INDEX idx_package_versions_package_id ON public.software_package_versions USING btree (package_id);
CREATE INDEX idx_package_versions_severity ON public.software_package_versions USING btree (highest_severity);
CREATE INDEX idx_patch_apps_applied_at ON public.patch_applications USING btree (applied_at);
CREATE INDEX idx_patch_apps_asset_id ON public.patch_applications USING btree (asset_id);
CREATE INDEX idx_patch_apps_device_id ON public.patch_applications USING btree (device_id);
CREATE INDEX idx_patch_apps_patch_id ON public.patch_applications USING btree (patch_id);
CREATE INDEX idx_patch_apps_verification_status ON public.patch_applications USING btree (verification_status);
CREATE INDEX idx_patches_cve_list ON public.patches USING gin (cve_list);
CREATE INDEX idx_patches_device_type ON public.patches USING btree (target_device_type);
CREATE INDEX idx_patches_is_active ON public.patches USING btree (is_active);
CREATE INDEX idx_patches_name ON public.patches USING btree (patch_name);
CREATE INDEX idx_patches_package_id ON public.patches USING btree (target_package_id);
CREATE INDEX idx_pkg_risk_aggregate_score ON public.software_package_risk_scores USING btree (aggregate_risk_score DESC);
CREATE INDEX idx_pkg_risk_kev_count ON public.software_package_risk_scores USING btree (kev_count DESC);
CREATE INDEX idx_pkg_risk_package_id ON public.software_package_risk_scores USING btree (package_id);
CREATE INDEX idx_pkg_risk_tier1_count ON public.software_package_risk_scores USING btree (tier1_assets_count DESC);
CREATE INDEX idx_pkg_risk_version_id ON public.software_package_risk_scores USING btree (version_id);
CREATE INDEX idx_recalls_date ON public.recalls USING btree (recall_date);
CREATE INDEX idx_recalls_manufacturer ON public.recalls USING btree (manufacturer_name);
CREATE INDEX idx_recalls_status ON public.recalls USING btree (recall_status);
CREATE INDEX idx_remediation_actions_assigned_to ON public.remediation_actions USING btree (assigned_to);
CREATE INDEX idx_remediation_actions_cve_id ON public.remediation_actions USING btree (cve_id);
CREATE INDEX idx_remediation_actions_due_date ON public.remediation_actions USING btree (due_date);
CREATE INDEX idx_remediation_actions_status ON public.remediation_actions USING btree (status);
CREATE INDEX idx_remediation_actions_type ON public.remediation_actions USING btree (action_type);
CREATE INDEX idx_risk_priority_view_epss ON public.risk_priority_view USING btree (epss_score DESC) WHERE (epss_score IS NOT NULL);
CREATE INDEX idx_risk_priority_view_kev ON public.risk_priority_view USING btree (is_kev) WHERE (is_kev = true);
CREATE UNIQUE INDEX idx_risk_priority_view_link_id ON public.risk_priority_view USING btree (link_id);
CREATE INDEX idx_risk_priority_view_overdue ON public.risk_priority_view USING btree (days_overdue DESC) WHERE (days_overdue > 0);
CREATE INDEX idx_risk_priority_view_score ON public.risk_priority_view USING btree (calculated_risk_score DESC);
CREATE INDEX idx_risk_priority_view_tier ON public.risk_priority_view USING btree (priority_tier);
CREATE INDEX idx_risks_asset_id ON public.risks USING btree (asset_id);
CREATE INDEX idx_risks_asset_status ON public.risks USING btree (asset_id, status_display_name);
CREATE INDEX idx_risks_created_at ON public.risks USING btree (created_at DESC);
CREATE INDEX idx_risks_device_class ON public.risks USING btree (device_class);
CREATE INDEX idx_risks_exploited ON public.risks USING btree (tags_exploited_in_the_wild) WHERE (tags_exploited_in_the_wild = true);
CREATE INDEX idx_risks_external_id ON public.risks USING btree (external_id);
CREATE INDEX idx_risks_id ON public.risks USING btree (id);
CREATE INDEX idx_risks_name ON public.risks USING btree (name);
CREATE INDEX idx_risks_nhs_threat_id ON public.risks USING btree (nhs_threat_id);
CREATE INDEX idx_risks_risk_id ON public.risks USING btree (risk_id);
CREATE INDEX idx_risks_risk_score ON public.risks USING btree (risk_score DESC);
CREATE INDEX idx_risks_risk_score_level ON public.risks USING btree (risk_score_level);
CREATE INDEX idx_risks_site ON public.risks USING btree (site);
CREATE INDEX idx_risks_site_score ON public.risks USING btree (site, risk_score DESC);
CREATE INDEX idx_risks_status ON public.risks USING btree (status_display_name);
CREATE INDEX idx_sbom_queue_device ON public.sbom_evaluation_queue USING btree (device_id);
CREATE INDEX idx_sbom_queue_priority ON public.sbom_evaluation_queue USING btree (priority DESC, queued_at);
CREATE INDEX idx_sbom_queue_queued_at ON public.sbom_evaluation_queue USING btree (queued_at);
CREATE INDEX idx_sbom_queue_status ON public.sbom_evaluation_queue USING btree (status);
CREATE INDEX idx_sboms_asset_id ON public.sboms USING btree (asset_id);
CREATE INDEX idx_sboms_device_id ON public.sboms USING btree (device_id);
CREATE INDEX idx_sboms_format ON public.sboms USING btree (format);
CREATE INDEX idx_sboms_parsing_status ON public.sboms USING btree (parsing_status);
CREATE INDEX idx_scheduled_tasks_action_id ON public.scheduled_tasks USING btree (action_id);
CREATE INDEX idx_scheduled_tasks_approval_date ON public.scheduled_tasks USING btree (department_approval_date);
CREATE INDEX idx_scheduled_tasks_approval_status ON public.scheduled_tasks USING btree (department_approval_status);
CREATE INDEX idx_scheduled_tasks_assigned_to ON public.scheduled_tasks USING btree (assigned_to);
CREATE INDEX idx_scheduled_tasks_created_at ON public.scheduled_tasks USING btree (created_at);
CREATE INDEX idx_scheduled_tasks_cve_id ON public.scheduled_tasks USING btree (cve_id);
CREATE INDEX idx_scheduled_tasks_department_notified ON public.scheduled_tasks USING btree (department_notified);
CREATE INDEX idx_scheduled_tasks_device_date ON public.scheduled_tasks USING btree (device_id, scheduled_date);
CREATE INDEX idx_scheduled_tasks_device_id ON public.scheduled_tasks USING btree (device_id);
CREATE INDEX idx_scheduled_tasks_implementation_date ON public.scheduled_tasks USING btree (implementation_date);
CREATE INDEX idx_scheduled_tasks_original_cve_id ON public.scheduled_tasks USING btree (original_cve_id);
CREATE INDEX idx_scheduled_tasks_original_device_name ON public.scheduled_tasks USING btree (original_device_name);
CREATE INDEX idx_scheduled_tasks_original_fda_recall_number ON public.scheduled_tasks USING btree (original_fda_recall_number);
CREATE INDEX idx_scheduled_tasks_original_patch_name ON public.scheduled_tasks USING btree (original_patch_name);
CREATE INDEX idx_scheduled_tasks_package_id ON public.scheduled_tasks USING btree (package_id);
CREATE INDEX idx_scheduled_tasks_patient_safety ON public.scheduled_tasks USING btree (patient_safety_impact) WHERE (patient_safety_impact = true);
CREATE INDEX idx_scheduled_tasks_recall_id ON public.scheduled_tasks USING btree (recall_id);
CREATE INDEX idx_scheduled_tasks_recall_priority ON public.scheduled_tasks USING btree (recall_priority);
CREATE INDEX idx_scheduled_tasks_recall_type ON public.scheduled_tasks USING btree (task_type) WHERE ((task_type)::text = 'recall_maintenance'::text);
CREATE INDEX idx_scheduled_tasks_remediation_type ON public.scheduled_tasks USING btree (remediation_type);
CREATE INDEX idx_scheduled_tasks_scheduled_date ON public.scheduled_tasks USING btree (scheduled_date);
CREATE INDEX idx_scheduled_tasks_status ON public.scheduled_tasks USING btree (status);
CREATE INDEX idx_scheduled_tasks_task_type ON public.scheduled_tasks USING btree (task_type);
CREATE INDEX idx_security_settings_category ON public.security_settings USING btree (category);
CREATE INDEX idx_security_settings_key ON public.security_settings USING btree (setting_key);
CREATE INDEX idx_software_components_name ON public.software_components USING btree (name);
CREATE INDEX idx_software_components_package_id ON public.software_components USING btree (package_id);
CREATE INDEX idx_software_components_sbom_id ON public.software_components USING btree (sbom_id);
CREATE INDEX idx_software_components_vendor ON public.software_components USING btree (vendor);
CREATE INDEX idx_software_components_version_id ON public.software_components USING btree (version_id);
CREATE INDEX idx_software_packages_cpe ON public.software_packages USING btree (cpe_product);
CREATE INDEX idx_software_packages_name ON public.software_packages USING btree (name);
CREATE INDEX idx_software_packages_vendor ON public.software_packages USING btree (vendor);
CREATE INDEX idx_spkgrisk_view_kev ON public.software_package_risk_priority_view USING btree (kev_count DESC);
CREATE INDEX idx_spkgrisk_view_package_id ON public.software_package_risk_priority_view USING btree (package_id);
CREATE UNIQUE INDEX idx_spkgrisk_view_risk_id ON public.software_package_risk_priority_view USING btree (risk_id);
CREATE INDEX idx_spkgrisk_view_tier1 ON public.software_package_risk_priority_view USING btree (tier1_assets_count DESC);
CREATE INDEX idx_spv_cve_id ON public.software_package_vulnerabilities USING btree (cve_id);
CREATE INDEX idx_spv_package_id ON public.software_package_vulnerabilities USING btree (package_id);
CREATE INDEX idx_spv_version_id ON public.software_package_vulnerabilities USING btree (version_id);
CREATE INDEX idx_user_sessions_active ON public.user_sessions USING btree (is_active);
CREATE INDEX idx_user_sessions_last_activity ON public.user_sessions USING btree (last_activity);
CREATE INDEX idx_user_sessions_user_id ON public.user_sessions USING btree (user_id);
CREATE INDEX idx_vuln_epss_date ON public.vulnerabilities USING btree (epss_date DESC) WHERE (epss_date IS NOT NULL);
CREATE INDEX idx_vuln_epss_percentile ON public.vulnerabilities USING btree (epss_percentile DESC) WHERE (epss_percentile IS NOT NULL);
CREATE INDEX idx_vuln_epss_score ON public.vulnerabilities USING btree (epss_score DESC) WHERE (epss_score IS NOT NULL);
CREATE INDEX idx_vuln_epss_updated ON public.vulnerabilities USING btree (epss_last_updated DESC) WHERE (epss_last_updated IS NOT NULL);
CREATE INDEX idx_vuln_is_kev ON public.vulnerabilities USING btree (is_kev) WHERE (is_kev = true);
CREATE INDEX idx_vuln_kev_due_date ON public.vulnerabilities USING btree (kev_due_date) WHERE (kev_due_date IS NOT NULL);
CREATE UNIQUE INDEX idx_vulnerabilities_cve_id_unique ON public.vulnerabilities USING btree (cve_id) WHERE (cve_id IS NOT NULL);
CREATE INDEX idx_vulnerabilities_cvss_score ON public.vulnerabilities USING btree (cvss_v3_score);
CREATE INDEX idx_vulnerabilities_cvss_v4_score ON public.vulnerabilities USING btree (cvss_v4_score);
CREATE INDEX idx_vulnerabilities_severity ON public.vulnerabilities USING btree (severity);
CREATE INDEX idx_vulnerabilities_uuid ON public.vulnerabilities USING btree (vulnerability_id);
CREATE INDEX idx_vulnerability_scans_asset_id ON public.vulnerability_scans USING btree (asset_id);
CREATE INDEX idx_vulnerability_scans_device_id ON public.vulnerability_scans USING btree (device_id);
CREATE INDEX idx_vulnerability_scans_requested_at ON public.vulnerability_scans USING btree (requested_at);
CREATE INDEX idx_vulnerability_scans_requested_by ON public.vulnerability_scans USING btree (requested_by);
CREATE INDEX idx_vulnerability_scans_status ON public.vulnerability_scans USING btree (status);
CREATE TRIGGER assets_criticality_update_trigger AFTER UPDATE OF criticality ON public.assets FOR EACH ROW WHEN (((old.criticality)::text IS DISTINCT FROM (new.criticality)::text)) EXECUTE FUNCTION public.trigger_recalculate_device_risk_scores();
CREATE TRIGGER kev_vulnerability_update AFTER INSERT OR UPDATE ON public.cisa_kev_catalog FOR EACH ROW EXECUTE FUNCTION public.update_vulnerability_kev_status();
CREATE TRIGGER locations_criticality_update_trigger AFTER UPDATE OF criticality ON public.locations FOR EACH ROW WHEN ((old.criticality IS DISTINCT FROM new.criticality)) EXECUTE FUNCTION public.trigger_recalculate_location_risk_scores();
CREATE TRIGGER preserve_completed_tasks_before_device_delete BEFORE DELETE ON public.medical_devices FOR EACH ROW EXECUTE FUNCTION public.preserve_completed_tasks_on_device_delete();
COMMENT ON TRIGGER preserve_completed_tasks_before_device_delete ON public.medical_devices IS 'Trigger to preserve completed scheduled tasks when a medical device is deleted. Sets device_id to NULL for completed tasks before the device deletion occurs.';
CREATE TRIGGER sbom_evaluation_status_update AFTER UPDATE ON public.sbom_evaluation_queue FOR EACH ROW WHEN (((new.status)::text = ANY (ARRAY[('Completed'::character varying)::text, ('Failed'::character varying)::text]))) EXECUTE FUNCTION public.update_sbom_evaluation_status();
CREATE TRIGGER trigger_asset_actions AFTER UPDATE ON public.assets FOR EACH ROW WHEN ((((old.criticality)::text IS DISTINCT FROM (new.criticality)::text) OR (old.location_id IS DISTINCT FROM new.location_id))) EXECUTE FUNCTION public.trigger_recalculate_asset_actions();
CREATE TRIGGER trigger_location_actions AFTER UPDATE ON public.locations FOR EACH ROW WHEN ((old.criticality IS DISTINCT FROM new.criticality)) EXECUTE FUNCTION public.trigger_recalculate_location_actions();
CREATE TRIGGER trigger_risk_matrix_actions AFTER INSERT OR UPDATE ON public.risk_matrix_config FOR EACH ROW WHEN ((new.is_active = true)) EXECUTE FUNCTION public.trigger_recalculate_all_actions();
CREATE TRIGGER trigger_risks_updated_at BEFORE UPDATE ON public.risks FOR EACH ROW EXECUTE FUNCTION public.update_risks_updated_at();
CREATE TRIGGER trigger_update_risk_priority BEFORE INSERT OR UPDATE ON public.device_vulnerabilities_link FOR EACH ROW EXECUTE FUNCTION public.update_risk_priority();
CREATE TRIGGER trigger_vulnerability_actions AFTER INSERT OR DELETE OR UPDATE ON public.vulnerabilities FOR EACH ROW EXECUTE FUNCTION public.trigger_recalculate_vulnerability_actions();
CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_device_recalls_updated_at BEFORE UPDATE ON public.device_recalls_link FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_device_vulnerabilities_updated_at BEFORE UPDATE ON public.device_vulnerabilities_link FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_location_ip_ranges_updated_at BEFORE UPDATE ON public.location_ip_ranges FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_locations_updated_at BEFORE UPDATE ON public.locations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_medical_devices_updated_at BEFORE UPDATE ON public.medical_devices FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_recalls_updated_at BEFORE UPDATE ON public.recalls FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_scheduled_tasks_updated_at_trigger BEFORE UPDATE ON public.scheduled_tasks FOR EACH ROW EXECUTE FUNCTION public.update_scheduled_tasks_updated_at();
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON public.vulnerabilities FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_vulnerability_scans_updated_at BEFORE UPDATE ON public.vulnerability_scans FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
ALTER TABLE ONLY public.action_device_links
    ADD CONSTRAINT action_device_links_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.remediation_actions(action_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.action_device_links
    ADD CONSTRAINT action_device_links_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.action_device_links
    ADD CONSTRAINT action_device_links_patched_by_fkey FOREIGN KEY (patched_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.action_risk_scores
    ADD CONSTRAINT action_risk_scores_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.remediation_actions(action_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.compensating_controls_checklist
    ADD CONSTRAINT compensating_controls_checklist_link_id_fkey FOREIGN KEY (link_id) REFERENCES public.device_vulnerabilities_link(link_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.compensating_controls_checklist
    ADD CONSTRAINT compensating_controls_checklist_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.dave_api_key_usage
    ADD CONSTRAINT dave_api_key_usage_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.dave_api_keys(key_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.dave_api_keys
    ADD CONSTRAINT dave_api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.dave_api_keys
    ADD CONSTRAINT dave_api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_recalls_link
    ADD CONSTRAINT device_recalls_link_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.device_recalls_link
    ADD CONSTRAINT device_recalls_link_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_recalls_link
    ADD CONSTRAINT device_recalls_link_recall_id_fkey FOREIGN KEY (recall_id) REFERENCES public.recalls(recall_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_vulnerabilities_link
    ADD CONSTRAINT device_vulnerabilities_link_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.device_vulnerabilities_link
    ADD CONSTRAINT device_vulnerabilities_link_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.software_components(component_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_vulnerabilities_link
    ADD CONSTRAINT device_vulnerabilities_link_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.device_vulnerabilities_link
    ADD CONSTRAINT device_vulnerabilities_link_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(vulnerability_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.location_ip_ranges
    ADD CONSTRAINT location_ip_ranges_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.locations
    ADD CONSTRAINT locations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.locations
    ADD CONSTRAINT locations_parent_location_id_fkey FOREIGN KEY (parent_location_id) REFERENCES public.locations(location_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.medical_devices
    ADD CONSTRAINT medical_devices_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.medical_devices
    ADD CONSTRAINT medical_devices_mapped_by_fkey FOREIGN KEY (mapped_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.mfa_sessions
    ADD CONSTRAINT mfa_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_applied_by_fkey FOREIGN KEY (applied_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_patch_id_fkey FOREIGN KEY (patch_id) REFERENCES public.patches(patch_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.patch_applications
    ADD CONSTRAINT patch_applications_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.patches
    ADD CONSTRAINT patches_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.patches
    ADD CONSTRAINT patches_target_package_id_fkey FOREIGN KEY (target_package_id) REFERENCES public.software_packages(package_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_threat_id_fkey FOREIGN KEY (threat_id) REFERENCES public.threats(threat_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.risk_matrix_config
    ADD CONSTRAINT risk_matrix_config_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.sbom_evaluation_logs
    ADD CONSTRAINT sbom_evaluation_logs_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sbom_evaluation_logs
    ADD CONSTRAINT sbom_evaluation_logs_queue_id_fkey FOREIGN KEY (queue_id) REFERENCES public.sbom_evaluation_queue(queue_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sbom_evaluation_logs
    ADD CONSTRAINT sbom_evaluation_logs_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES public.sboms(sbom_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sbom_evaluation_queue
    ADD CONSTRAINT sbom_evaluation_queue_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sbom_evaluation_queue
    ADD CONSTRAINT sbom_evaluation_queue_queued_by_fkey FOREIGN KEY (queued_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.sbom_evaluation_queue
    ADD CONSTRAINT sbom_evaluation_queue_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES public.sboms(sbom_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sboms
    ADD CONSTRAINT sboms_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sboms
    ADD CONSTRAINT sboms_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sboms
    ADD CONSTRAINT sboms_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.remediation_actions(action_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_department_approval_by_fkey FOREIGN KEY (department_approval_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_department_approval_by_fkey1 FOREIGN KEY (department_approval_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_department_approval_by_fkey2 FOREIGN KEY (department_approval_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.software_packages(package_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_patch_id_fkey FOREIGN KEY (patch_id) REFERENCES public.patches(patch_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_recall_id_fkey FOREIGN KEY (recall_id) REFERENCES public.recalls(recall_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_recall_id_fkey1 FOREIGN KEY (recall_id) REFERENCES public.recalls(recall_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_recall_id_fkey2 FOREIGN KEY (recall_id) REFERENCES public.recalls(recall_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_components
    ADD CONSTRAINT software_components_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.software_packages(package_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.software_components
    ADD CONSTRAINT software_components_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES public.sboms(sbom_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_components
    ADD CONSTRAINT software_components_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.software_package_versions(version_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.software_package_risk_scores
    ADD CONSTRAINT software_package_risk_scores_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.software_packages(package_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_package_risk_scores
    ADD CONSTRAINT software_package_risk_scores_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.software_package_versions(version_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_package_versions
    ADD CONSTRAINT software_package_versions_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.software_packages(package_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_package_vulnerabilities
    ADD CONSTRAINT software_package_vulnerabilities_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.software_packages(package_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.software_package_vulnerabilities
    ADD CONSTRAINT software_package_vulnerabilities_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.software_package_versions(version_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.task_consolidation_mapping
    ADD CONSTRAINT task_consolidation_mapping_consolidated_task_id_fkey FOREIGN KEY (consolidated_task_id) REFERENCES public.scheduled_tasks(task_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.task_consolidation_mapping
    ADD CONSTRAINT task_consolidation_mapping_original_task_id_fkey FOREIGN KEY (original_task_id) REFERENCES public.scheduled_tasks(task_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.threats
    ADD CONSTRAINT threats_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.threats
    ADD CONSTRAINT threats_cwe_id_fkey FOREIGN KEY (cwe_id) REFERENCES public.cwe_reference(cwe_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_terminated_by_fkey FOREIGN KEY (terminated_by) REFERENCES public.users(user_id);
ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_kev_id_fkey FOREIGN KEY (kev_id) REFERENCES public.cisa_kev_catalog(kev_id);
ALTER TABLE ONLY public.vulnerability_overrides
    ADD CONSTRAINT vulnerability_overrides_accepted_by_fkey FOREIGN KEY (accepted_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.vulnerability_overrides_device
    ADD CONSTRAINT vulnerability_overrides_device_accepted_by_fkey FOREIGN KEY (accepted_by) REFERENCES public.users(user_id) ON DELETE SET NULL;
ALTER TABLE ONLY public.vulnerability_overrides_device
    ADD CONSTRAINT vulnerability_overrides_device_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.vulnerability_scans
    ADD CONSTRAINT vulnerability_scans_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(asset_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.vulnerability_scans
    ADD CONSTRAINT vulnerability_scans_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.medical_devices(device_id) ON DELETE CASCADE;
ALTER TABLE ONLY public.vulnerability_scans
    ADD CONSTRAINT vulnerability_scans_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.users(user_id);
\unrestrict 7n2HHSFEePEEgKGTLQhc4IHni2VDzecQhQdxCmL05Ur3RFw0HINscoKu1eiGZwn

-- ====================================================================================
-- Migration Tracking Table
-- ====================================================================================
-- This table tracks which migrations have been applied
-- For fresh installs using this consolidated schema, all migrations are considered applied

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Mark all migrations as applied (since they're included in this consolidated schema)
-- This prevents the migration script from trying to re-apply them

-- Insert migration tracking records for all included migrations:
