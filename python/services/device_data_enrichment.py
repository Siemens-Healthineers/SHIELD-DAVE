#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
Device Data Enrichment Service for Device Assessment and Vulnerability Exposure ()
Fetches comprehensive device data using 510k numbers from multiple FDA sources
"""

import json
import logging
from typing import Dict, List, Optional
from fda_integration import FDAIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DeviceDataEnrichment:
    """Comprehensive device data enrichment service"""
    
    def __init__(self):
        self.fda = FDAIntegration()
    
    def enrich_device_data(self, k_number: str) -> Dict:
        """Fetch comprehensive device data using 510k number"""
        try:
            logger.info(f"Enriching device data for K number: {k_number}")
            
            enriched_data = {
                'k_number': k_number,
                '510k_data': None,
                'recalls': [],
                'adverse_events': [],
                'device_problems': [],
                'enrichment_timestamp': None,
                'data_sources': []
            }
            
            # 1. Get 510k details
            logger.info(f"Fetching 510k details for {k_number}")
            k510k_data = self.fda.search_510k(k_number)
            if k510k_data and len(k510k_data) > 0:
                enriched_data['510k_data'] = k510k_data[0]
                enriched_data['data_sources'].append('510k_database')
            
            # 2. Get recalls
            logger.info(f"Fetching recalls for {k_number}")
            recalls = self.fda.search_recalls_by_k_number(k_number)
            enriched_data['recalls'] = recalls
            if recalls:
                enriched_data['data_sources'].append('recalls_database')
            
            # 3. Get adverse events
            logger.info(f"Fetching adverse events for {k_number}")
            adverse_events = self.fda.search_adverse_events_by_k_number(k_number)
            enriched_data['adverse_events'] = adverse_events
            if adverse_events:
                enriched_data['data_sources'].append('adverse_events_database')
            
            # 4. Get device problems
            logger.info(f"Fetching device problems for {k_number}")
            device_problems = self.fda.search_device_problems_by_k_number(k_number)
            enriched_data['device_problems'] = device_problems
            if device_problems:
                enriched_data['data_sources'].append('device_problems_database')
            
            # 5. Add enrichment timestamp
            from datetime import datetime
            enriched_data['enrichment_timestamp'] = datetime.now().isoformat()
            
            # 6. Calculate summary statistics
            enriched_data['summary'] = self._calculate_summary_stats(enriched_data)
            
            logger.info(f"Device enrichment completed for {k_number}")
            return enriched_data
            
        except Exception as e:
            logger.error(f"Error enriching device data for {k_number}: {e}")
            return {
                'k_number': k_number,
                'error': str(e),
                'enrichment_timestamp': None
            }
    
    def _calculate_summary_stats(self, enriched_data: Dict) -> Dict:
        """Calculate summary statistics for enriched data"""
        try:
            summary = {
                'total_recalls': len(enriched_data.get('recalls', [])),
                'total_adverse_events': len(enriched_data.get('adverse_events', [])),
                'total_device_problems': len(enriched_data.get('device_problems', [])),
                'data_sources_count': len(enriched_data.get('data_sources', [])),
                'has_510k_data': enriched_data.get('510k_data') is not None,
                'has_safety_issues': False,
                'risk_level': 'low'
            }
            
            # Determine if there are safety issues
            if summary['total_recalls'] > 0 or summary['total_adverse_events'] > 0 or summary['total_device_problems'] > 0:
                summary['has_safety_issues'] = True
                summary['risk_level'] = 'high'
            elif summary['total_adverse_events'] > 0 or summary['total_device_problems'] > 0:
                summary['risk_level'] = 'medium'
            
            return summary
            
        except Exception as e:
            logger.error(f"Error calculating summary stats: {e}")
            return {
                'error': str(e)
            }
    
    def get_device_safety_summary(self, k_number: str) -> Dict:
        """Get a focused safety summary for a device"""
        try:
            enriched_data = self.enrich_device_data(k_number)
            
            safety_summary = {
                'k_number': k_number,
                'device_name': enriched_data.get('510k_data', {}).get('device_name', 'Unknown'),
                'manufacturer': enriched_data.get('510k_data', {}).get('applicant', 'Unknown'),
                'safety_issues': {
                    'recalls': len(enriched_data.get('recalls', [])),
                    'adverse_events': len(enriched_data.get('adverse_events', [])),
                    'device_problems': len(enriched_data.get('device_problems', []))
                },
                'risk_assessment': enriched_data.get('summary', {}).get('risk_level', 'unknown'),
                'last_updated': enriched_data.get('enrichment_timestamp')
            }
            
            return safety_summary
            
        except Exception as e:
            logger.error(f"Error getting safety summary for {k_number}: {e}")
            return {
                'k_number': k_number,
                'error': str(e)
            }

def main():
    """Main function for command-line interface"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 device_data_enrichment.py <command> <k_number>")
        print("Commands:")
        print("  enrich_device_data <k_number>")
        print("  get_safety_summary <k_number>")
        sys.exit(1)
    
    command = sys.argv[1]
    k_number = sys.argv[2]
    
    enrichment = DeviceDataEnrichment()
    
    try:
        if command == "enrich_device_data":
            result = enrichment.enrich_device_data(k_number)
            print(json.dumps(result, indent=2))
            
        elif command == "get_safety_summary":
            result = enrichment.get_device_safety_summary(k_number)
            print(json.dumps(result, indent=2))
            
        else:
            print(f"Error: Unknown command '{command}'")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
