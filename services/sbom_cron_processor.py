#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

This script processes SBOM evaluation queue items and exits.
Designed to be run via cron every few minutes.
"""

import os
import sys
import json
import logging
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/sbom_cron.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('sbom_cron_processor')

class SBOMCronProcessor:
    """Cron-based SBOM processor"""
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
        self.nvd_api_key = self._load_nvd_api_key()
        self.rate_limiter = RateLimiter()
    
    def _load_nvd_api_key(self) -> Optional[str]:
        """Load NVD API key from file"""
        try:
            key_file = '/var/www/html/config/nvd_api_key.txt'
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    return f.read().strip()
        except Exception as e:
            logger.warning(f"Could not load NVD API key: {e}")
        return None
    
    def get_db_connection(self):
        """Get database connection"""
        return psycopg2.connect(**self.db_config)
    
    def get_next_queue_item(self, conn) -> Optional[Dict]:
        """Get next queued SBOM for processing"""
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("""
            SELECT queue_id, sbom_id, device_id, priority
            FROM sbom_evaluation_queue
            WHERE status = 'Queued'
            ORDER BY priority DESC, queued_at ASC
            LIMIT 1
        """)
        
        return cursor.fetchone()
    
    def update_queue_item(self, conn, queue_id: str, status: str, stats: Dict = None, error_message: str = None):
        """Update queue item status"""
        cursor = conn.cursor()
        
        if status == 'Processing':
            cursor.execute("""
                UPDATE sbom_evaluation_queue 
                SET status = %s, started_at = CURRENT_TIMESTAMP
                WHERE queue_id = %s
            """, (status, queue_id))
        elif status == 'Completed':
            cursor.execute("""
                UPDATE sbom_evaluation_queue 
                SET status = %s, completed_at = CURRENT_TIMESTAMP,
                    vulnerabilities_found = %s, vulnerabilities_stored = %s,
                    components_evaluated = %s
                WHERE queue_id = %s
            """, (status, stats.get('vulnerabilities_found', 0),
                  stats.get('vulnerabilities_stored', 0),
                  stats.get('components_evaluated', 0), queue_id))
        elif status == 'Failed':
            cursor.execute("""
                UPDATE sbom_evaluation_queue 
                SET status = %s, completed_at = CURRENT_TIMESTAMP,
                    error_message = %s, retry_count = retry_count + 1
                WHERE queue_id = %s
            """, (status, error_message, queue_id))
        
        conn.commit()
    
    def get_sbom_data(self, conn, sbom_id: str) -> Optional[Dict]:
        """Get SBOM data from database"""
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("""
            SELECT sbom_id, device_id, content
            FROM sboms
            WHERE sbom_id = %s
        """, (sbom_id,))
        
        result = cursor.fetchone()
        return dict(result) if result else None
    
    def search_nvd_for_cpe(self, cpe: str) -> List[Dict]:
        """Search NVD for vulnerabilities by CPE"""
        if not cpe:
            return []
        
        try:
            # Rate limiting
            self.rate_limiter.wait_if_needed()
            
            # NVD API call
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'cpeName': cpe,
                'resultsPerPage': 2000
            }
            
            if self.nvd_api_key:
                params['apiKey'] = self.nvd_api_key
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                vuln_data = {
                    'cve_id': cve.get('id', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                    'severity': self._extract_severity(cve),
                    'cvss_v3_score': self._extract_cvss_score(cve),
                    'published_date': cve.get('published', ''),
                    'last_modified_date': cve.get('lastModified', ''),
                    'nvd_data': vuln
                }
                vulnerabilities.append(vuln_data)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching NVD for CPE {cpe}: {e}")
            return []
    
    def _extract_severity(self, cve_data: Dict) -> str:
        """Extract severity from CVE data"""
        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            return cvss_v3[0].get('cvssData', {}).get('baseSeverity', 'Unknown')
        return 'Unknown'
    
    def _extract_cvss_score(self, cve_data: Dict) -> float:
        """Extract CVSS score from CVE data"""
        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            return float(cvss_v3[0].get('cvssData', {}).get('baseScore', 0))
        return 0.0
    
    def store_vulnerability(self, conn, vuln_data: Dict, component_id: str, device_id: str) -> bool:
        """Store vulnerability in database"""
        try:
            cursor = conn.cursor()
            
            # Insert vulnerability if not exists
            cursor.execute("""
                INSERT INTO vulnerabilities (cve_id, description, cvss_v3_score, severity, published_date, last_modified_date, nvd_data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    cvss_v3_score = EXCLUDED.cvss_v3_score,
                    severity = EXCLUDED.severity,
                    published_date = EXCLUDED.published_date,
                    last_modified_date = EXCLUDED.last_modified_date,
                    nvd_data = EXCLUDED.nvd_data,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                vuln_data['cve_id'],
                vuln_data['description'],
                vuln_data['cvss_v3_score'],
                vuln_data['severity'],
                vuln_data['published_date'],
                vuln_data['last_modified_date'],
                json.dumps(vuln_data['nvd_data'])
            ))
            
            # Link to device if not already linked
            cursor.execute("""
                INSERT INTO device_vulnerabilities_link (device_id, component_id, cve_id, discovered_at)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (device_id, component_id, cve_id) DO NOTHING
            """, (device_id, component_id, vuln_data['cve_id']))
            
            conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
            conn.rollback()
            return False
    
    def evaluate_sbom(self, conn, queue_item: Dict) -> Tuple[bool, Dict]:
        """Evaluate SBOM for vulnerabilities"""
        sbom_id = queue_item['sbom_id']
        device_id = queue_item['device_id']
        
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
            
            logger.info(f"Evaluation completed for SBOM {sbom_id}: {stats['vulnerabilities_found']} vulnerabilities found")
            return True, stats
            
        except Exception as e:
            logger.error(f"Error evaluating SBOM {sbom_id}: {e}", exc_info=True)
            return False, stats
    
    def process_queue(self):
        """Process one queue item and exit"""
        logger.info("SBOM Cron Processor started")
        
        try:
            conn = self.get_db_connection()
            
            # Get next queue item
            queue_item = self.get_next_queue_item(conn)
            
            if queue_item:
                logger.info(f"Processing queue item {queue_item['queue_id']}")
                
                # Update status to processing
                self.update_queue_item(conn, queue_item['queue_id'], 'Processing')
                
                # Evaluate SBOM
                success, stats = self.evaluate_sbom(conn, queue_item)
                
                # Update queue status
                if success:
                    self.update_queue_item(conn, queue_item['queue_id'], 'Completed', stats)
                    logger.info(f"Successfully processed queue item {queue_item['queue_id']}")
                else:
                    self.update_queue_item(conn, queue_item['queue_id'], 'Failed', 
                                         error_message="Evaluation failed, see logs for details")
                    logger.error(f"Failed to process queue item {queue_item['queue_id']}")
                
                conn.close()
            else:
                logger.info("No items in queue")
                conn.close()
                
        except Exception as e:
            logger.error(f"Error in cron processor: {e}", exc_info=True)

class RateLimiter:
    """Simple rate limiter for NVD API"""
    
    def __init__(self):
        self.last_request = 0
        self.min_interval = 0.6  # 1 request per 0.6 seconds (100 per minute)
    
    def wait_if_needed(self):
        """Wait if needed to respect rate limits"""
        now = time.time()
        time_since_last = now - self.last_request
        
        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request = time.time()

def main():
    """Main entry point"""
    processor = SBOMCronProcessor()
    processor.process_queue()

if __name__ == "__main__":
    main()
