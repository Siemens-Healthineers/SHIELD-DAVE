#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/


This service downloads and synchronizes the CISA KEV catalog with the local database.
It can be run as a cron job or manually to update the KEV data.

CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import os
import sys
import json
import logging
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime
from typing import Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/kev_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('kev_sync_service')

# CISA KEV Catalog URL
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVSyncService:
    """Service to sync CISA KEV catalog"""
    
    def __init__(self):
        self.db_config = self._load_db_config()
        self.stats = {
            'total_kev_entries': 0,
            'new_entries': 0,
            'updated_entries': 0,
            'vulnerabilities_matched': 0
        }
    
    def _load_db_config(self) -> Dict[str, str]:
        """Load database configuration"""
        config_file = '/var/www/html/config/database.php'
        
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
    
    def get_db_connection(self):
        """Create database connection"""
        return psycopg2.connect(**self.db_config)
    
    def download_kev_catalog(self) -> Optional[Dict]:
        """Download CISA KEV catalog"""
        logger.info(f"Downloading KEV catalog from {KEV_CATALOG_URL}")
        
        try:
            response = requests.get(KEV_CATALOG_URL, timeout=30)
            response.raise_for_status()
            
            catalog = response.json()
            logger.info(f"Successfully downloaded KEV catalog with {catalog.get('count', 0)} entries")
            return catalog
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download KEV catalog: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse KEV catalog JSON: {e}")
            return None
    
    def sync_kev_entry(self, conn, entry: Dict, catalog_version: str) -> str:
        """Sync a single KEV entry to database"""
        cursor = conn.cursor()
        
        try:
            cve_id = entry.get('cveID')
            
            # Check if entry exists
            cursor.execute("SELECT kev_id FROM cisa_kev_catalog WHERE cve_id = %s", (cve_id,))
            existing = cursor.fetchone()
            
            # Parse dates
            date_added = entry.get('dateAdded')
            due_date = entry.get('dueDate')
            
            # Parse known ransomware use
            ransomware_use = entry.get('knownRansomwareCampaignUse', 'Unknown').lower() == 'known'
            
            # Parse CWEs if available
            cwes = []
            if entry.get('cwes'):
                if isinstance(entry['cwes'], list):
                    cwes = entry['cwes']
                elif isinstance(entry['cwes'], str):
                    cwes = [cwe.strip() for cwe in entry['cwes'].split(',')]
            
            if existing:
                # Update existing entry
                cursor.execute("""
                    UPDATE cisa_kev_catalog
                    SET vendor_project = %s,
                        product = %s,
                        vulnerability_name = %s,
                        date_added = %s,
                        short_description = %s,
                        required_action = %s,
                        due_date = %s,
                        known_ransomware_campaign_use = %s,
                        notes = %s,
                        cwes = %s,
                        catalog_version = %s,
                        last_synced_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE cve_id = %s
                    RETURNING kev_id
                """, (
                    entry.get('vendorProject'),
                    entry.get('product'),
                    entry.get('vulnerabilityName'),
                    date_added,
                    entry.get('shortDescription'),
                    entry.get('requiredAction'),
                    due_date,
                    ransomware_use,
                    entry.get('notes'),
                    cwes,
                    catalog_version,
                    cve_id
                ))
                
                self.stats['updated_entries'] += 1
                action = 'updated'
            else:
                # Insert new entry
                cursor.execute("""
                    INSERT INTO cisa_kev_catalog (
                        cve_id, vendor_project, product, vulnerability_name,
                        date_added, short_description, required_action, due_date,
                        known_ransomware_campaign_use, notes, cwes,
                        catalog_version, last_synced_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING kev_id
                """, (
                    cve_id,
                    entry.get('vendorProject'),
                    entry.get('product'),
                    entry.get('vulnerabilityName'),
                    date_added,
                    entry.get('shortDescription'),
                    entry.get('requiredAction'),
                    due_date,
                    ransomware_use,
                    entry.get('notes'),
                    cwes,
                    catalog_version
                ))
                
                self.stats['new_entries'] += 1
                action = 'added'
            
            result = cursor.fetchone()
            conn.commit()
            cursor.close()
            
            logger.debug(f"KEV entry {action}: {cve_id}")
            return action
            
        except Exception as e:
            logger.error(f"Error syncing KEV entry {entry.get('cveID')}: {e}")
            conn.rollback()
            cursor.close()
            return 'error'
    
    def match_vulnerabilities(self, conn) -> int:
        """Match existing vulnerabilities with KEV catalog"""
        cursor = conn.cursor()
        
        try:
            # Update vulnerabilities that match KEV entries
            cursor.execute("""
                UPDATE vulnerabilities v
                SET is_kev = TRUE,
                    kev_id = k.kev_id,
                    kev_date_added = k.date_added,
                    kev_due_date = k.due_date,
                    kev_required_action = k.required_action,
                    priority = 'Critical-KEV',
                    updated_at = CURRENT_TIMESTAMP
                FROM cisa_kev_catalog k
                WHERE v.cve_id = k.cve_id
                  AND v.is_kev = FALSE
            """)
            
            matched = cursor.rowcount
            conn.commit()
            cursor.close()
            
            logger.info(f"Matched {matched} existing vulnerabilities with KEV catalog")
            return matched
            
        except Exception as e:
            logger.error(f"Error matching vulnerabilities: {e}")
            conn.rollback()
            cursor.close()
            return 0
    
    def log_sync(self, conn, sync_start: datetime, status: str, catalog_data: Dict, error_message: str = None):
        """Log sync operation"""
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO cisa_kev_sync_log (
                    sync_started_at, sync_completed_at, sync_status,
                    total_kev_entries, new_entries, updated_entries, vulnerabilities_matched,
                    catalog_version, catalog_title, catalog_count, error_message
                )
                VALUES (%s, CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                sync_start,
                status,
                self.stats['total_kev_entries'],
                self.stats['new_entries'],
                self.stats['updated_entries'],
                self.stats['vulnerabilities_matched'],
                catalog_data.get('catalogVersion'),
                catalog_data.get('title'),
                catalog_data.get('count'),
                error_message
            ))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error logging sync: {e}")
            conn.rollback()
            cursor.close()
    
    def sync(self) -> bool:
        """Main sync operation"""
        sync_start = datetime.now()
        logger.info("Starting CISA KEV catalog sync")
        
        try:
            # Download catalog
            catalog = self.download_kev_catalog()
            if not catalog:
                logger.error("Failed to download KEV catalog")
                return False
            
            # Connect to database
            conn = self.get_db_connection()
            
            # Get catalog info
            catalog_version = catalog.get('catalogVersion')
            vulnerabilities = catalog.get('vulnerabilities', [])
            self.stats['total_kev_entries'] = len(vulnerabilities)
            
            logger.info(f"Processing {self.stats['total_kev_entries']} KEV entries from catalog version {catalog_version}")
            
            # Sync each entry
            for i, entry in enumerate(vulnerabilities, 1):
                if i % 100 == 0:
                    logger.info(f"Processed {i}/{self.stats['total_kev_entries']} entries")
                
                self.sync_kev_entry(conn, entry, catalog_version)
            
            # Match existing vulnerabilities
            self.stats['vulnerabilities_matched'] = self.match_vulnerabilities(conn)
            
            # Log sync operation
            self.log_sync(conn, sync_start, 'Success', catalog)
            
            conn.close()
            
            sync_duration = (datetime.now() - sync_start).total_seconds()
            
            logger.info(f"KEV sync completed successfully in {sync_duration:.1f} seconds")
            logger.info(f"Statistics: {self.stats['total_kev_entries']} total, "
                       f"{self.stats['new_entries']} new, "
                       f"{self.stats['updated_entries']} updated, "
                       f"{self.stats['vulnerabilities_matched']} vulnerabilities matched")
            
            return True
            
        except Exception as e:
            logger.error(f"KEV sync failed: {e}", exc_info=True)
            
            try:
                conn = self.get_db_connection()
                self.log_sync(conn, sync_start, 'Failed', catalog or {}, str(e))
                conn.close()
            except:
                pass
            
            return False


def main():
    """Main entry point"""
    try:
        service = KEVSyncService()
        success = service.sync()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

