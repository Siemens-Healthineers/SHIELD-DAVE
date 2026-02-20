#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

This service downloads and synchronizes EPSS scores from the FIRST.org API with
the local database. It can be run as a cron job or manually to update EPSS data.

FIRST.org EPSS API: https://www.first.org/epss/api
"""

import os
import sys
import json
import logging
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime, date
from typing import Dict, List, Optional, Tuple
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/epss_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('epss_sync_service')

# FIRST.org EPSS API configuration
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"
EPSS_API_PAGE_SIZE = 1000  # Maximum per page
EPSS_API_DELAY = 0.1  # Delay between requests to be respectful

class EPSSSyncService:
    """Service to sync EPSS data from FIRST.org API"""
    
    def __init__(self):
        """Initialize the EPSS sync service"""
        self.db_config = self._get_db_config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': '-EPSS-Sync/1.0 (https://github.com/your-org/dave)',
            'Accept': 'application/json'
        })
        
    def _get_db_config(self) -> Dict:
        """Get database configuration from environment or config file"""
        return {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
    
    def _get_db_connection(self):
        """Get database connection"""
        try:
            conn = psycopg2.connect(**self.db_config)
            conn.autocommit = False
            return conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    def fetch_epss_data(self, offset: int = 0, limit: int = EPSS_API_PAGE_SIZE) -> Tuple[Dict, bool]:
        """
        Fetch EPSS data from FIRST.org API
        
        Args:
            offset: Starting position for pagination
            limit: Number of records to fetch
            
        Returns:
            Tuple of (response_data, has_more_pages)
        """
        try:
            params = {
                'envelope': 'true',
                'pretty': 'false',
                'offset': offset,
                'limit': limit
            }
            
            logger.info(f"Fetching EPSS data: offset={offset}, limit={limit}")
            response = self.session.get(EPSS_API_BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Check if there are more pages
            total_count = data.get('total', 0)
            current_count = offset + len(data.get('data', []))
            has_more = current_count < total_count
            
            logger.info(f"Fetched {len(data.get('data', []))} records, total: {total_count}, has_more: {has_more}")
            
            return data, has_more
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching EPSS data: {e}")
            raise
    
    def sync_epss_scores(self, conn, epss_data: List[Dict]) -> Dict:
        """
        Sync EPSS scores to the database
        
        Args:
            conn: Database connection
            epss_data: List of EPSS records from API
            
        Returns:
            Dictionary with sync statistics
        """
        cursor = conn.cursor()
        stats = {
            'total_processed': 0,
            'cves_updated': 0,
            'cves_new': 0,
            'errors': 0
        }
        
        try:
            for record in epss_data:
                stats['total_processed'] += 1
                
                try:
                    cve_id = record.get('cve')
                    epss_score = record.get('epss')
                    percentile = record.get('percentile')
                    
                    if not cve_id or epss_score is None or percentile is None:
                        logger.warning(f"Skipping invalid record: {record}")
                        stats['errors'] += 1
                        continue
                    
                    # Convert to float and validate EPSS score range (0.0 to 1.0)
                    try:
                        epss_score = float(epss_score)
                        percentile = float(percentile)
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid EPSS data types for {cve_id}: score={epss_score}, percentile={percentile}")
                        stats['errors'] += 1
                        continue
                    
                    if not (0.0 <= epss_score <= 1.0):
                        logger.warning(f"Invalid EPSS score for {cve_id}: {epss_score}")
                        stats['errors'] += 1
                        continue
                    
                    # Validate percentile range (0.0 to 1.0)
                    if not (0.0 <= percentile <= 1.0):
                        logger.warning(f"Invalid percentile for {cve_id}: {percentile}")
                        stats['errors'] += 1
                        continue
                    
                    # Update or insert EPSS data
                    cursor.execute("""
                        UPDATE vulnerabilities 
                        SET epss_score = %s,
                            epss_percentile = %s,
                            epss_date = CURRENT_DATE,
                            epss_last_updated = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE cve_id = %s
                    """, (epss_score, percentile, cve_id))
                    
                    if cursor.rowcount > 0:
                        stats['cves_updated'] += 1
                        logger.debug(f"Updated EPSS for {cve_id}: score={epss_score}, percentile={percentile}")
                    else:
                        # CVE doesn't exist in our database yet
                        logger.debug(f"CVE {cve_id} not found in vulnerabilities table")
                        stats['cves_new'] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing CVE {record.get('cve', 'unknown')}: {e}")
                    stats['errors'] += 1
                    continue
            
            conn.commit()
            cursor.close()
            
            logger.info(f"EPSS sync completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error in sync_epss_scores: {e}")
            conn.rollback()
            cursor.close()
            raise
    
    def archive_historical_scores(self, conn) -> int:
        """
        Archive current EPSS scores to history table
        
        Args:
            conn: Database connection
            
        Returns:
            Number of records archived
        """
        cursor = conn.cursor()
        
        try:
            # Archive current EPSS scores for today
            cursor.execute("""
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
                ON CONFLICT DO NOTHING
            """)
            
            archived_count = cursor.rowcount
            conn.commit()
            cursor.close()
            
            logger.info(f"Archived {archived_count} EPSS historical scores")
            return archived_count
            
        except Exception as e:
            logger.error(f"Error archiving historical scores: {e}")
            conn.rollback()
            cursor.close()
            raise
    
    def log_sync(self, conn, sync_start: datetime, status: str, stats: Dict, 
                 api_data: Dict, error_message: str = None):
        """
        Log sync operation to database
        
        Args:
            conn: Database connection
            sync_start: When sync started
            status: Sync status (Success, Failed, Partial)
            stats: Sync statistics
            api_data: API response metadata
            error_message: Error message if failed
        """
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO epss_sync_log (
                    sync_started_at, sync_completed_at, sync_status,
                    total_cves_processed, cves_updated, cves_new,
                    api_date, api_total_cves, api_version, error_message
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                sync_start,
                datetime.now(),
                status,
                stats.get('total_processed', 0),
                stats.get('cves_updated', 0),
                stats.get('cves_new', 0),
                date.today(),
                api_data.get('total', 0),
                api_data.get('version', 'unknown'),
                error_message
            ))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error logging sync: {e}")
            conn.rollback()
            cursor.close()
            raise
    
    def run_sync(self) -> bool:
        """
        Run the complete EPSS sync process
        
        Returns:
            True if successful, False otherwise
        """
        sync_start = datetime.now()
        conn = None
        total_stats = {
            'total_processed': 0,
            'cves_updated': 0,
            'cves_new': 0,
            'errors': 0
        }
        
        try:
            logger.info("Starting EPSS sync process")
            conn = self._get_db_connection()
            
            # Fetch all EPSS data with pagination
            offset = 0
            api_data = None
            
            while True:
                try:
                    data, has_more = self.fetch_epss_data(offset, EPSS_API_PAGE_SIZE)
                    
                    if api_data is None:
                        api_data = data  # Store metadata from first request
                    
                    # Sync this batch
                    batch_stats = self.sync_epss_scores(conn, data.get('data', []))
                    
                    # Accumulate statistics
                    for key in total_stats:
                        total_stats[key] += batch_stats[key]
                    
                    if not has_more:
                        break
                    
                    offset += EPSS_API_PAGE_SIZE
                    
                    # Be respectful to the API
                    time.sleep(EPSS_API_DELAY)
                    
                except Exception as e:
                    logger.error(f"Error processing batch at offset {offset}: {e}")
                    # Continue with next batch
                    offset += EPSS_API_PAGE_SIZE
                    if offset > 100000:  # Safety limit
                        logger.error("Reached safety limit, stopping sync")
                        break
                    continue
            
            # Archive historical scores
            try:
                archived_count = self.archive_historical_scores(conn)
                logger.info(f"Archived {archived_count} historical EPSS scores")
            except Exception as e:
                logger.error(f"Error archiving historical scores: {e}")
                # Don't fail the entire sync for this
            
            # Determine sync status
            if total_stats['errors'] == 0:
                status = 'Success'
            elif total_stats['cves_updated'] > 0:
                status = 'Partial'
            else:
                status = 'Failed'
            
            # Log sync operation
            self.log_sync(conn, sync_start, status, total_stats, api_data or {})
            
            logger.info(f"EPSS sync completed successfully: {total_stats}")
            return True
            
        except Exception as e:
            logger.error(f"EPSS sync failed: {e}")
            
            # Log failed sync
            if conn:
                try:
                    self.log_sync(conn, sync_start, 'Failed', total_stats, 
                                 api_data or {}, str(e))
                except:
                    pass  # Don't fail on logging errors
            
            return False
            
        finally:
            if conn:
                conn.close()

def main():
    """Main entry point for the EPSS sync service"""
    try:
        service = EPSSSyncService()
        success = service.run_sync()
        
        if success:
            logger.info("EPSS sync completed successfully")
            sys.exit(0)
        else:
            logger.error("EPSS sync failed")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Fatal error in EPSS sync: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
