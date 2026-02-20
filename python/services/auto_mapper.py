#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
Auto Mapping Service for Device Assessment and Vulnerability Exposure ()
Automatically maps assets to FDA device records using manufacturer information
"""

import sys
import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional
import psycopg2
from psycopg2.extras import RealDictCursor

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import our FDA integration
from python.services.fda_integration import FDAIntegration
from python.services.oui_lookup import OUILookup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/auto_mapper.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AutoMapper:
    """Automatic device mapping service"""
    
    def __init__(self):
        self.fda = FDAIntegration()
        self.oui = OUILookup()
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
        self.min_confidence = 0.7  # Minimum confidence for auto-mapping
    
    def get_unmapped_assets(self) -> List[Dict]:
        """Get assets that need mapping"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            sql = """
                SELECT a.asset_id, a.hostname, a.manufacturer, a.model, a.mac_address, a.asset_type
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                WHERE md.device_id IS NULL
                AND a.status = 'Active'
                AND a.manufacturer IS NOT NULL
                AND a.manufacturer != ''
                ORDER BY a.last_seen DESC
            """
            
            cursor.execute(sql)
            assets = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return [dict(asset) for asset in assets]
            
        except Exception as e:
            logger.error(f"Error getting unmapped assets: {e}")
            return []
    
    def map_asset(self, asset: Dict, user_id: str = None) -> Dict:
        """Map a single asset to FDA device record"""
        try:
            manufacturer = asset['manufacturer']
            model = asset['model'] or ''
            
            logger.info(f"Mapping asset {asset['asset_id']}: {manufacturer} {model}")
            
            # Search FDA database
            devices = self.fda.search_devices(manufacturer, model)
            
            if not devices:
                return {
                    'asset_id': asset['asset_id'],
                    'success': False,
                    'reason': 'No FDA devices found',
                    'confidence': 0.0
                }
            
            # Find best match
            best_device = max(devices, key=lambda x: x.get('confidence_score', 0))
            confidence = best_device.get('confidence_score', 0)
            
            if confidence < self.min_confidence:
                return {
                    'asset_id': asset['asset_id'],
                    'success': False,
                    'reason': f'Confidence too low: {confidence:.2f}',
                    'confidence': confidence
                }
            
            # Insert mapping
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            sql = """
                INSERT INTO medical_devices (
                    asset_id, device_identifier, brand_name, model_number,
                    manufacturer_name, device_description, gmdn_term,
                    is_implantable, fda_class, udi, mapping_confidence,
                    mapping_method, mapped_by, mapped_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'automatic', %s, CURRENT_TIMESTAMP
                )
            """
            
            cursor.execute(sql, [
                asset['asset_id'],
                best_device.get('device_identifier', ''),
                best_device.get('brand_name', ''),
                best_device.get('model_number', ''),
                best_device.get('manufacturer_name', ''),
                best_device.get('device_description', ''),
                best_device.get('gmdn_term', ''),
                best_device.get('is_implantable', False),
                best_device.get('fda_class', ''),
                best_device.get('udi', ''),
                confidence,
                user_id or 'system'
            ])
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Successfully mapped asset {asset['asset_id']} with confidence {confidence:.2f}")
            
            return {
                'asset_id': asset['asset_id'],
                'success': True,
                'device': best_device,
                'confidence': confidence
            }
            
        except Exception as e:
            logger.error(f"Error mapping asset {asset['asset_id']}: {e}")
            return {
                'asset_id': asset['asset_id'],
                'success': False,
                'reason': str(e),
                'confidence': 0.0
            }
    
    def auto_map_all(self, user_id: str = None, max_assets: int = None) -> Dict:
        """Auto-map all unmapped assets"""
        try:
            logger.info("Starting auto-mapping process")
            
            # Get unmapped assets
            assets = self.get_unmapped_assets()
            
            if max_assets:
                assets = assets[:max_assets]
            
            logger.info(f"Found {len(assets)} unmapped assets")
            
            results = {
                'total': len(assets),
                'mapped': 0,
                'failed': 0,
                'errors': [],
                'mappings': []
            }
            
            for asset in assets:
                try:
                    result = self.map_asset(asset, user_id)
                    results['mappings'].append(result)
                    
                    if result['success']:
                        results['mapped'] += 1
                    else:
                        results['failed'] += 1
                        results['errors'].append({
                            'asset_id': asset['asset_id'],
                            'reason': result['reason']
                        })
                        
                except Exception as e:
                    logger.error(f"Error processing asset {asset['asset_id']}: {e}")
                    results['failed'] += 1
                    results['errors'].append({
                        'asset_id': asset['asset_id'],
                        'reason': str(e)
                    })
            
            logger.info(f"Auto-mapping completed: {results['mapped']} mapped, {results['failed']} failed")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in auto-mapping process: {e}")
            return {
                'total': 0,
                'mapped': 0,
                'failed': 0,
                'errors': [{'reason': str(e)}],
                'mappings': []
            }
    
    def get_mapping_stats(self) -> Dict:
        """Get mapping statistics"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Total assets
            cursor.execute("SELECT COUNT(*) FROM assets WHERE status = 'Active'")
            total_assets = cursor.fetchone()[0]
            
            # Mapped assets
            cursor.execute("""
                SELECT COUNT(*) FROM assets a
                JOIN medical_devices md ON a.asset_id = md.asset_id
                WHERE a.status = 'Active'
            """)
            mapped_assets = cursor.fetchone()[0]
            
            # Unmapped assets
            cursor.execute("""
                SELECT COUNT(*) FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                WHERE md.device_id IS NULL AND a.status = 'Active'
            """)
            unmapped_assets = cursor.fetchone()[0]
            
            # Average confidence
            cursor.execute("SELECT AVG(mapping_confidence) FROM medical_devices")
            avg_confidence = cursor.fetchone()[0] or 0.0
            
            cursor.close()
            conn.close()
            
            return {
                'total_assets': total_assets,
                'mapped_assets': mapped_assets,
                'unmapped_assets': unmapped_assets,
                'mapping_percentage': round((mapped_assets / total_assets * 100) if total_assets > 0 else 0, 1),
                'average_confidence': round(avg_confidence, 2)
            }
            
        except Exception as e:
            logger.error(f"Error getting mapping stats: {e}")
            return {}

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Auto-map assets to FDA devices')
    parser.add_argument('--max-assets', type=int, help='Maximum number of assets to process')
    parser.add_argument('--user-id', type=str, help='User ID for mapping attribution')
    parser.add_argument('--stats', action='store_true', help='Show mapping statistics')
    
    args = parser.parse_args()
    
    mapper = AutoMapper()
    
    if args.stats:
        stats = mapper.get_mapping_stats()
        print(json.dumps(stats, indent=2))
    else:
        results = mapper.auto_map_all(args.user_id, args.max_assets)
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
