#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
Recall Monitor Service for Device Assessment and Vulnerability Exposure ()
Monitors FDA recalls and matches them against organizational devices
"""

import sys
import os
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import psycopg2
from psycopg2.extras import RealDictCursor

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import our FDA integration
from python.services.fda_integration import FDAIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'logs', 'recall_monitor.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RecallMonitor:
    """FDA recall monitoring service"""
    
    def __init__(self):
        self.fda = FDAIntegration()
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
    
    def check_new_recalls(self, days_back: int = 7) -> Dict:
        """Check for new FDA recalls and match against organizational devices"""
        try:
            logger.info(f"Checking for new recalls in the last {days_back} days")
            
            # Get recent recalls from FDA
            recalls = self.fda.search_recalls(days_back)
            
            if not recalls:
                logger.info("No new recalls found")
                return {
                    'success': True,
                    'new_recalls': 0,
                    'matched_devices': 0,
                    'alerts_created': 0
                }
            
            logger.info(f"Found {len(recalls)} new recalls")
            
            # Process each recall
            matched_devices = 0
            alerts_created = 0
            
            for recall in recalls:
                try:
                    # Store recall in database
                    recall_id = self._store_recall(recall)
                    
                    if recall_id:
                        # Find matching devices
                        device_matches = self._find_matching_devices(recall)
                        
                        if device_matches:
                            # Create device-recall links
                            for device_id in device_matches:
                                self._create_device_recall_link(recall_id, device_id)
                                matched_devices += 1
                            
                            # Create alerts for affected users
                            alert_count = self._create_recall_alerts(recall_id, device_matches)
                            alerts_created += alert_count
                            
                            logger.info(f"Recall {recall['fda_recall_number']} matched {len(device_matches)} devices")
                
                except Exception as e:
                    logger.error(f"Error processing recall {recall.get('fda_recall_number', 'unknown')}: {e}")
                    continue
            
            logger.info(f"Recall check completed: {len(recalls)} recalls, {matched_devices} devices matched, {alerts_created} alerts created")
            
            return {
                'success': True,
                'new_recalls': len(recalls),
                'matched_devices': matched_devices,
                'alerts_created': alerts_created
            }
            
        except Exception as e:
            logger.error(f"Error checking recalls: {e}")
            return {
                'success': False,
                'error': str(e),
                'new_recalls': 0,
                'matched_devices': 0,
                'alerts_created': 0
            }
    
    def _store_recall(self, recall_data: Dict) -> Optional[str]:
        """Store recall in database"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Check if recall already exists
            cursor.execute("SELECT recall_id FROM recalls WHERE fda_recall_number = %s", 
                         [recall_data['fda_recall_number']])
            
            if cursor.fetchone():
                logger.info(f"Recall {recall_data['fda_recall_number']} already exists")
                cursor.close()
                conn.close()
                return None
            
            # Insert new recall
            sql = """
                INSERT INTO recalls (
                    fda_recall_number, recall_date, product_description, 
                    reason_for_recall, manufacturer_name, product_code, 
                    recall_classification, recall_status, fda_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING recall_id
            """
            
            cursor.execute(sql, [
                recall_data['fda_recall_number'],
                recall_data['recall_date'],
                recall_data['product_description'],
                recall_data['reason_for_recall'],
                recall_data['manufacturer_name'],
                recall_data['product_code'],
                recall_data['recall_classification'],
                'Active',
                json.dumps(recall_data['raw_data'])
            ])
            
            recall_id = cursor.fetchone()[0]
            conn.commit()
            
            cursor.close()
            conn.close()
            
            logger.info(f"Stored recall {recall_data['fda_recall_number']} with ID {recall_id}")
            return recall_id
            
        except Exception as e:
            logger.error(f"Error storing recall: {e}")
            return None
    
    def _find_matching_devices(self, recall: Dict) -> List[str]:
        """Find devices that match the recall criteria"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Build matching criteria
            manufacturer = recall.get('manufacturer_name', '').lower()
            product_code = recall.get('product_code', '')
            
            # Search for matching devices
            sql = """
                SELECT DISTINCT md.device_id, md.brand_name, md.model_number, md.manufacturer_name
                FROM medical_devices md
                WHERE LOWER(md.manufacturer_name) LIKE %s
                OR LOWER(md.brand_name) LIKE %s
            """
            
            manufacturer_pattern = f'%{manufacturer}%'
            cursor.execute(sql, [manufacturer_pattern, manufacturer_pattern])
            devices = cursor.fetchall()
            
            # Additional filtering based on product description
            matching_devices = []
            product_desc = recall.get('product_description', '').lower()
            
            for device in devices:
                device_name = f"{device['brand_name']} {device['model_number']}".lower()
                
                # Check if device name appears in product description
                if any(keyword in product_desc for keyword in device_name.split()):
                    matching_devices.append(device['device_id'])
                elif manufacturer in device_name:
                    matching_devices.append(device['device_id'])
            
            cursor.close()
            conn.close()
            
            logger.info(f"Found {len(matching_devices)} matching devices for recall {recall['fda_recall_number']}")
            return matching_devices
            
        except Exception as e:
            logger.error(f"Error finding matching devices: {e}")
            return []
    
    def _create_device_recall_link(self, recall_id: str, device_id: str) -> bool:
        """Create link between device and recall"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Check if link already exists
            cursor.execute("""
                SELECT link_id FROM device_recalls_link 
                WHERE device_id = %s AND recall_id = %s
            """, [device_id, recall_id])
            
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return False
            
            # Create new link
            cursor.execute("""
                INSERT INTO device_recalls_link (device_id, recall_id, remediation_status)
                VALUES (%s, %s, 'Open')
            """, [device_id, recall_id])
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating device-recall link: {e}")
            return False
    
    def _create_recall_alerts(self, recall_id: str, device_ids: List[str]) -> int:
        """Create alerts for users about recall"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Get recall information
            cursor.execute("SELECT * FROM recalls WHERE recall_id = %s", [recall_id])
            recall = cursor.fetchone()
            
            if not recall:
                return 0
            
            # Get users who should be notified (Clinical Engineers and Admins)
            cursor.execute("""
                SELECT user_id FROM users 
                WHERE role IN ('Admin', 'Clinical Engineer') AND is_active = TRUE
            """)
            users = cursor.fetchall()
            
            alerts_created = 0
            
            for user in users:
                for device_id in device_ids:
                    # Create notification
                    cursor.execute("""
                        INSERT INTO notifications (
                            user_id, title, message, type, priority, 
                            related_entity_type, related_entity_id
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, [
                        user[0],
                        f"FDA Recall Alert: {recall[1]}",  # fda_recall_number
                        f"Device affected by FDA recall. Reason: {recall[4]}",  # reason_for_recall
                        'recall',
                        'High',
                        'recall',
                        recall_id
                    ])
                    
                    alerts_created += 1
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Created {alerts_created} recall alerts")
            return alerts_created
            
        except Exception as e:
            logger.error(f"Error creating recall alerts: {e}")
            return 0
    
    def get_recall_summary(self) -> Dict:
        """Get recall summary statistics"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Total active recalls
            cursor.execute("SELECT COUNT(*) FROM recalls WHERE recall_status = 'Active'")
            active_recalls = cursor.fetchone()[0]
            
            # Recalls affecting devices
            cursor.execute("""
                SELECT COUNT(DISTINCT r.recall_id) 
                FROM recalls r
                JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                WHERE r.recall_status = 'Active'
            """)
            affecting_recalls = cursor.fetchone()[0]
            
            # Total affected devices
            cursor.execute("""
                SELECT COUNT(DISTINCT drl.device_id) 
                FROM device_recalls_link drl
                JOIN recalls r ON drl.recall_id = r.recall_id
                WHERE r.recall_status = 'Active'
            """)
            affected_devices = cursor.fetchone()[0]
            
            # Open remediation items
            cursor.execute("""
                SELECT COUNT(*) FROM device_recalls_link 
                WHERE remediation_status = 'Open'
            """)
            open_remediations = cursor.fetchone()[0]
            
            # Recent recalls (last 30 days)
            cursor.execute("""
                SELECT COUNT(*) FROM recalls 
                WHERE recall_date > CURRENT_DATE - INTERVAL '30 days'
            """)
            recent_recalls = cursor.fetchone()[0]
            
            cursor.close()
            conn.close()
            
            return {
                'active_recalls': active_recalls,
                'affecting_recalls': affecting_recalls,
                'affected_devices': affected_devices,
                'open_remediations': open_remediations,
                'recent_recalls': recent_recalls
            }
            
        except Exception as e:
            logger.error(f"Error getting recall summary: {e}")
            return {}
    
    def update_remediation_status(self, link_id: str, status: str, notes: str = None) -> bool:
        """Update remediation status for a device-recall link"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            sql = """
                UPDATE device_recalls_link 
                SET remediation_status = %s, remediation_notes = %s, updated_at = CURRENT_TIMESTAMP
                WHERE link_id = %s
            """
            
            cursor.execute(sql, [status, notes, link_id])
            conn.commit()
            
            cursor.close()
            conn.close()
            
            logger.info(f"Updated remediation status for link {link_id} to {status}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating remediation status: {e}")
            return False

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor FDA recalls')
    parser.add_argument('--days', type=int, default=7, help='Number of days to look back for recalls')
    parser.add_argument('--summary', action='store_true', help='Show recall summary statistics')
    
    args = parser.parse_args()
    
    monitor = RecallMonitor()
    
    if args.summary:
        summary = monitor.get_recall_summary()
        print(json.dumps(summary, indent=2))
    else:
        results = monitor.check_new_recalls(args.days)
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
