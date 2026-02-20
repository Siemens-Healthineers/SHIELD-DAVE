#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

This service continuously monitors the sbom_evaluation_queue table and processes
SBOMs in the background with proper rate limiting for NVD API requests.

Features:
- Automatic queue processing
- NVD API rate limiting (50 requests per 30 seconds without API key, 100 with key)
- Comprehensive logging
- Error handling and retries
- Graceful shutdown
"""

import os
import sys
import time
import json
import logging
import signal
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/sbom_evaluation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('sbom_evaluation_service')

@dataclass
class RateLimiter:
    """Rate limiter for NVD API requests"""
    requests_per_window: int = 50  # Default without API key
    window_seconds: int = 30
    request_times: List[datetime] = None
    
    def __post_init__(self):
        if self.request_times is None:
            self.request_times = []
    
    def wait_if_needed(self):
        """Wait if we've hit the rate limit"""
        now = datetime.now()
        
        # Remove old requests outside the time window
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.request_times = [t for t in self.request_times if t > cutoff]
        
        # If we're at the limit, wait
        if len(self.request_times) >= self.requests_per_window:
            sleep_time = (self.request_times[0] - cutoff).total_seconds() + 1
            if sleep_time > 0:
                logger.info(f"Rate limit reached, waiting {sleep_time:.1f} seconds")
                time.sleep(sleep_time)
                return self.wait_if_needed()
        
        # Record this request
        self.request_times.append(now)
    
    def set_api_key_rate(self):
        """Adjust rate limit when API key is available"""
        self.requests_per_window = 100
        logger.info("Using API key rate limit: 100 requests per 30 seconds")


class SBOMEvaluationService:
    """Background service for SBOM evaluation"""
    
    def __init__(self):
        self.running = True
        self.db_config = self._load_db_config()
        self.nvd_api_key = self._load_nvd_api_key()
        self.rate_limiter = RateLimiter()
        self.last_kev_sync = None
        
        if self.nvd_api_key:
            self.rate_limiter.set_api_key_rate()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def _load_db_config(self) -> Dict[str, str]:
        """Load database configuration"""
        config_file = '/var/www/html/config/database.php'
        
        # Parse PHP config file
        config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                # Simple parsing - extract values between quotes
                if "'host'" in content:
                    config['host'] = content.split("'host' => '")[1].split("'")[0]
                if "'database'" in content:
                    config['database'] = content.split("'database' => '")[1].split("'")[0]
                if "'username'" in content:
                    config['user'] = content.split("'username' => '")[1].split("'")[0]
                if "'password'" in content:
                    config['password'] = content.split("'password' => '")[1].split("'")[0]
        except Exception as e:
            logger.warning(f"Could not load database config, using defaults: {e}")
        
        return config
    
    def _load_nvd_api_key(self) -> Optional[str]:
        """Load NVD API key if available"""
        api_key_file = '/var/www/html/config/nvd_api_key.txt'
        
        if os.path.exists(api_key_file):
            try:
                with open(api_key_file, 'r') as f:
                    api_key = f.read().strip()
                    if api_key:
                        logger.info("NVD API key loaded successfully")
                        return api_key
            except Exception as e:
                logger.warning(f"Could not load NVD API key: {e}")
        
        logger.warning("No NVD API key found, using rate limit of 50 requests per 30 seconds")
        return None
    
    def get_db_connection(self):
        """Create database connection"""
        return psycopg2.connect(**self.db_config)
    
    def get_next_queue_item(self, conn) -> Optional[Dict]:
        """Get next item from queue"""
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get highest priority pending item
        cursor.execute("""
            UPDATE sbom_evaluation_queue
            SET status = 'Processing',
                started_at = CURRENT_TIMESTAMP
            WHERE queue_id = (
                SELECT queue_id
                FROM sbom_evaluation_queue
                WHERE status = 'Queued'
                  AND retry_count < max_retries
                ORDER BY priority ASC, queued_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
        """)
        
        result = cursor.fetchone()
        conn.commit()
        cursor.close()
        
        return dict(result) if result else None
    
    def get_sbom_data(self, conn, sbom_id: str) -> Optional[Dict]:
        """Get SBOM data from database"""
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("""
            SELECT sbom_id, device_id, content
            FROM sboms
            WHERE sbom_id = %s
        """, (sbom_id,))
        
        result = cursor.fetchone()
        cursor.close()
        
        return dict(result) if result else None
    
    def search_nvd_for_cpe(self, cpe_name: str) -> List[Dict]:
        """Search NVD for vulnerabilities for a given CPE"""
        self.rate_limiter.wait_if_needed()
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'cpeName': cpe_name,
            'resultsPerPage': 100
        }
        
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('vulnerabilities', [])
            elif response.status_code == 404:
                # No vulnerabilities found for this CPE
                return []
            else:
                logger.warning(f"NVD API returned status {response.status_code} for {cpe_name}")
                return []
                
        except Exception as e:
            logger.error(f"Error querying NVD for {cpe_name}: {e}")
            return []
    
    def check_kev_status(self, conn, cve_id: str) -> Optional[Dict]:
        """Check if CVE is in CISA KEV catalog"""
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("""
                SELECT kev_id, date_added, due_date, required_action, 
                       known_ransomware_campaign_use
                FROM cisa_kev_catalog
                WHERE cve_id = %s
            """, (cve_id,))
            
            result = cursor.fetchone()
            cursor.close()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.debug(f"Error checking KEV status for {cve_id}: {e}")
            cursor.close()
            return None
    
    def store_vulnerability(self, conn, vuln_data: Dict, component_id: str, device_id: str) -> bool:
        """Store vulnerability in database"""
        cursor = conn.cursor()
        
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            # Extract metrics
            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            cvss_data = cvss_v3.get('cvssData', {})
            
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description available')
            
            # Check if CVE is in CISA KEV catalog
            kev_data = self.check_kev_status(conn, cve_id)
            is_kev = kev_data is not None
            priority = 'Critical-KEV' if is_kev else 'Normal'
            
            if is_kev:
                logger.warning(f"🚨 KEV ALERT: {cve_id} is in CISA KEV catalog - actively exploited!")
            
            # Store vulnerability in vulnerabilities table (CVE catalog)
            cursor.execute("""
                INSERT INTO vulnerabilities (
                    cve_id, description, cvss_v3_score, severity,
                    published_date, last_modified_date, nvd_data,
                    is_kev, kev_id, kev_date_added, kev_due_date, kev_required_action, priority
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE
                SET description = EXCLUDED.description,
                    cvss_v3_score = EXCLUDED.cvss_v3_score,
                    severity = EXCLUDED.severity,
                    last_modified_date = EXCLUDED.last_modified_date,
                    nvd_data = EXCLUDED.nvd_data,
                    is_kev = EXCLUDED.is_kev,
                    kev_id = EXCLUDED.kev_id,
                    kev_date_added = EXCLUDED.kev_date_added,
                    kev_due_date = EXCLUDED.kev_due_date,
                    kev_required_action = EXCLUDED.kev_required_action,
                    priority = EXCLUDED.priority,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                cve_id,
                description,
                cvss_score,
                cvss_severity,
                cve.get('published'),
                cve.get('lastModified'),
                json.dumps(vuln_data),
                is_kev,
                kev_data['kev_id'] if kev_data else None,
                kev_data['date_added'] if kev_data else None,
                kev_data['due_date'] if kev_data else None,
                kev_data['required_action'] if kev_data else None,
                priority
            ))
            
            # Link vulnerability to device and component
            cursor.execute("""
                INSERT INTO device_vulnerabilities_link (
                    device_id, component_id, cve_id, remediation_status
                )
                VALUES (%s, %s, %s, 'Open')
                ON CONFLICT (device_id, component_id, cve_id) DO NOTHING
            """, (
                device_id,
                component_id,
                cve_id
            ))
            
            conn.commit()
            cursor.close()
            return True
            
        except Exception as e:
            logger.error(f"Error storing vulnerability {cve_id}: {e}")
            conn.rollback()
            cursor.close()
            return False
    
    def evaluate_sbom(self, conn, queue_item: Dict) -> Tuple[bool, Dict]:
        """Evaluate SBOM against NVD"""
        sbom_id = queue_item['sbom_id']
        device_id = queue_item['device_id']
        
        logger.info(f"Starting evaluation for SBOM {sbom_id}, Device {device_id}")
        
        evaluation_start = datetime.now()
        stats = {
            'components_evaluated': 0,
            'vulnerabilities_found': 0,
            'vulnerabilities_stored': 0,
            'api_calls': 0,
            'api_failures': 0
        }
        
        try:
            # Get SBOM data
            sbom_data = self.get_sbom_data(conn, sbom_id)
            if not sbom_data:
                logger.error(f"SBOM {sbom_id} not found in database")
                return False, stats
            
            sbom_json = sbom_data['content']
            
            # Parse SBOM components
            components = sbom_json.get('components', [])
            logger.info(f"Found {len(components)} components in SBOM")
            
            for component in components:
                stats['components_evaluated'] += 1
                
                component_name = component.get('name', 'Unknown')
                component_version = component.get('version', '')
                
                # Get CPE if available
                cpe = component.get('cpe')
                if not cpe:
                    # Try to construct CPE from purl
                    purl = component.get('purl', '')
                    if purl:
                        # Simple purl to CPE conversion (simplified)
                        logger.debug(f"Component {component_name} has no CPE, has purl: {purl}")
                    continue
                
                logger.info(f"Evaluating component: {component_name} (CPE: {cpe})")
                
                # Search NVD
                stats['api_calls'] += 1
                vulnerabilities = self.search_nvd_for_cpe(cpe)
                
                if vulnerabilities:
                    logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {component_name}")
                    stats['vulnerabilities_found'] += len(vulnerabilities)
                    
                    # Store each vulnerability
                    for vuln in vulnerabilities:
                        if self.store_vulnerability(conn, vuln, component.get('bom-ref', ''), device_id):
                            stats['vulnerabilities_stored'] += 1
            
            evaluation_end = datetime.now()
            duration = int((evaluation_end - evaluation_start).total_seconds())
            
            logger.info(f"Evaluation completed for SBOM {sbom_id}: {stats['vulnerabilities_found']} vulnerabilities found")
            
            # Log the evaluation
            self._log_evaluation(conn, queue_item['queue_id'], sbom_id, device_id, 
                               evaluation_start, evaluation_end, duration, 'Success', stats)
            
            return True, stats
            
        except Exception as e:
            logger.error(f"Error evaluating SBOM {sbom_id}: {e}", exc_info=True)
            evaluation_end = datetime.now()
            duration = int((evaluation_end - evaluation_start).total_seconds())
            
            self._log_evaluation(conn, queue_item['queue_id'], sbom_id, device_id,
                               evaluation_start, evaluation_end, duration, 'Failed', stats, str(e))
            
            return False, stats
    
    def _log_evaluation(self, conn, queue_id: str, sbom_id: str, device_id: str,
                       start_time: datetime, end_time: datetime, duration: int,
                       status: str, stats: Dict, error_message: str = None):
        """Log evaluation details"""
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO sbom_evaluation_logs (
                    queue_id, sbom_id, device_id,
                    evaluation_started_at, evaluation_completed_at, evaluation_duration_seconds,
                    components_evaluated, vulnerabilities_found, vulnerabilities_stored,
                    nvd_api_calls_made, nvd_api_failures,
                    status, error_message,
                    evaluation_metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                queue_id, sbom_id, device_id,
                start_time, end_time, duration,
                stats['components_evaluated'], stats['vulnerabilities_found'], 
                stats['vulnerabilities_stored'],
                stats['api_calls'], stats['api_failures'],
                status, error_message,
                json.dumps(stats)
            ))
            
            conn.commit()
            cursor.close()
            
            logger.info(f"Logged evaluation for SBOM {sbom_id}: {status}")
            
        except Exception as e:
            logger.error(f"Error logging evaluation: {e}")
            conn.rollback()
            cursor.close()
    
    def update_queue_item(self, conn, queue_id: str, status: str, stats: Dict = None, error_message: str = None):
        """Update queue item status"""
        cursor = conn.cursor()
        
        try:
            if status == 'Completed':
                cursor.execute("""
                    UPDATE sbom_evaluation_queue
                    SET status = %s,
                        completed_at = CURRENT_TIMESTAMP,
                        vulnerabilities_found = %s,
                        vulnerabilities_stored = %s,
                        components_evaluated = %s
                    WHERE queue_id = %s
                """, (status, stats.get('vulnerabilities_found', 0), 
                      stats.get('vulnerabilities_stored', 0),
                      stats.get('components_evaluated', 0), queue_id))
            elif status == 'Failed':
                cursor.execute("""
                    UPDATE sbom_evaluation_queue
                    SET status = %s,
                        completed_at = CURRENT_TIMESTAMP,
                        error_message = %s,
                        retry_count = retry_count + 1
                    WHERE queue_id = %s
                """, (status, error_message, queue_id))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error updating queue item: {e}")
            conn.rollback()
            cursor.close()
    
    def sync_kev_catalog(self):
        """Sync CISA KEV catalog - runs every 24 hours"""
        now = datetime.now()
        
        # Check if we need to sync (every 24 hours)
        if self.last_kev_sync:
            time_since_sync = (now - self.last_kev_sync).total_seconds()
            if time_since_sync < 86400:  # 24 hours in seconds
                return
        
        logger.info("Starting CISA KEV catalog sync...")
        
        try:
            # Call KEV sync service
            import subprocess
            result = subprocess.run(
                ['python3', '/var/www/html/services/kev_sync_service.py'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("KEV catalog sync completed successfully")
                self.last_kev_sync = now
            else:
                logger.error(f"KEV catalog sync failed: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Error running KEV sync: {e}")
    
    def process_queue(self):
        """Main processing loop"""
        logger.info("SBOM Evaluation Service started")
        
        # Perform initial KEV sync on startup
        logger.info("Performing initial KEV catalog sync...")
        self.sync_kev_catalog()
        
        while self.running:
            try:
                # Sync KEV catalog every 24 hours
                self.sync_kev_catalog()
                
                conn = self.get_db_connection()
                
                # Get next queue item
                queue_item = self.get_next_queue_item(conn)
                
                if queue_item:
                    logger.info(f"Processing queue item {queue_item['queue_id']}")
                    
                    # Evaluate SBOM
                    success, stats = self.evaluate_sbom(conn, queue_item)
                    
                    # Update queue status
                    if success:
                        self.update_queue_item(conn, queue_item['queue_id'], 'Completed', stats)
                    else:
                        self.update_queue_item(conn, queue_item['queue_id'], 'Failed', 
                                             error_message="Evaluation failed, see logs for details")
                    
                    conn.close()
                else:
                    # No items in queue, wait before checking again
                    conn.close()
                    logger.debug("No items in queue, waiting 30 seconds...")
                    time.sleep(30)
                    
            except Exception as e:
                logger.error(f"Error in main processing loop: {e}", exc_info=True)
                time.sleep(60)  # Wait longer on error
        
        logger.info("SBOM Evaluation Service stopped")


def main():
    """Main entry point"""
    try:
        service = SBOMEvaluationService()
        service.process_queue()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

