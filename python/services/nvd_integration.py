#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
NVD Integration Service for Device Assessment and Vulnerability Exposure ()
Handles vulnerability scanning via National Vulnerability Database (NVD) API
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import os
import sys

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/nvd_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NVDIntegration:
    """NVD CVE API integration service"""
    
    def __init__(self, api_key: str = None):
        # Try to get API key from various sources
        if api_key:
            self.api_key = api_key
        else:
            # First try environment variable
            self.api_key = os.getenv('NVD_API_KEY', '')
            
            # If not found, try to read from config file
            if not self.api_key:
                try:
                    config_file = '/var/www/html/config/nvd_api_key.txt'
                    if os.path.exists(config_file):
                        with open(config_file, 'r') as f:
                            self.api_key = f.read().strip()
                except Exception as e:
                    logger.warning(f"Could not read NVD API key from config file: {e}")
        
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        # Rate limits: 50 requests/minute with API key, 5 requests/minute without
        self.rate_limit = 50 if self.api_key else 5
        self.request_count = 0
        self.last_reset = datetime.now()
        
        if self.api_key:
            logger.info("NVD API key loaded successfully - rate limit: 50 requests/minute")
        else:
            logger.warning("No NVD API key found - using unauthenticated requests (limited to 5 requests per minute)")
        
    def _make_request(self, params: Dict = None) -> Optional[Dict]:
        """Make API request with rate limiting"""
        try:
            # Check rate limit
            if self.request_count >= self.rate_limit:
                time_since_reset = datetime.now() - self.last_reset
                if time_since_reset.total_seconds() < 60:  # 1 minute
                    wait_time = 60 - time_since_reset.total_seconds()
                    logger.warning(f"Rate limit reached. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    self.request_count = 0
                    self.last_reset = datetime.now()
            
            # Prepare request
            headers = {'User-Agent': '/1.0'}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            # Make request
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            self.request_count += 1
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:  # Rate limited
                logger.warning("Rate limited by NVD API. Waiting 60 seconds...")
                time.sleep(60)
                return self._make_request(params)
            else:
                logger.error(f"NVD API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def search_vulnerabilities(self, cpe_name: str = None, keyword: str = None, 
                             severity: str = None, limit: int = 50) -> List[Dict]:
        """Search for vulnerabilities by CPE name or keyword"""
        try:
            params = {
                'resultsPerPage': min(limit, 2000),  # NVD API limit
                'startIndex': 0
            }
            
            # Build search criteria
            if cpe_name:
                params['cpeName'] = cpe_name
            elif keyword:
                params['keywordSearch'] = keyword
            
            if severity:
                params['cvssV3Severity'] = severity.upper()
            
            logger.info(f"Searching NVD for: {params}")
            response = self._make_request(params)
            
            if response and 'vulnerabilities' in response:
                vulnerabilities = []
                for vuln in response['vulnerabilities']:
                    vuln_info = self._parse_vulnerability_data(vuln)
                    if vuln_info:
                        vulnerabilities.append(vuln_info)
                
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
                return vulnerabilities
            else:
                logger.warning("No vulnerabilities found or API error")
                return []
                
        except Exception as e:
            logger.error(f"Error searching vulnerabilities: {e}")
            return []
    
    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Get specific vulnerability by CVE ID"""
        try:
            params = {
                'cveId': cve_id
            }
            
            response = self._make_request(params)
            
            if response and 'vulnerabilities' in response and len(response['vulnerabilities']) > 0:
                return self._parse_vulnerability_data(response['vulnerabilities'][0])
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error getting vulnerability {cve_id}: {e}")
            return None
    
    def _parse_vulnerability_data(self, vuln_data: Dict) -> Optional[Dict]:
        """Parse NVD vulnerability data into standardized format"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS scores
            metrics = cve.get('metrics', {})
            cvss_v3 = None
            cvss_v2 = None
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_v3 = {
                    'score': cvss_data.get('baseScore', 0.0),
                    'vector': cvss_data.get('vectorString', ''),
                    'severity': self._calculate_severity(cvss_data.get('baseScore', 0.0))
                }
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_v3 = {
                    'score': cvss_data.get('baseScore', 0.0),
                    'vector': cvss_data.get('vectorString', ''),
                    'severity': self._calculate_severity(cvss_data.get('baseScore', 0.0))
                }
            
            if 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_v2 = {
                    'score': cvss_data.get('baseScore', 0.0),
                    'vector': cvss_data.get('vectorString', ''),
                    'severity': self._calculate_severity_v2(cvss_data.get('baseScore', 0.0))
                }
            
            # Extract CPE matches
            cpe_matches = []
            configurations = cve.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches.extend(node.get('cpeMatch', []))
            
            # Extract references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references if ref.get('url')]
            
            # Extract published and modified dates
            published = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            # Determine the best available CVSS data
            best_cvss_score = 0.0
            best_cvss_vector = ''
            best_severity = 'Unknown'
            
            if cvss_v3:
                best_cvss_score = cvss_v3['score']
                best_cvss_vector = cvss_v3['vector']
                best_severity = cvss_v3['severity']
            elif cvss_v2:
                best_cvss_score = cvss_v2['score']
                best_cvss_vector = cvss_v2['vector']
                best_severity = cvss_v2['severity']
            
            vulnerability = {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3_score': cvss_v3['score'] if cvss_v3 else 0.0,
                'cvss_v3_vector': cvss_v3['vector'] if cvss_v3 else '',
                'cvss_v2_score': cvss_v2['score'] if cvss_v2 else 0.0,
                'cvss_v2_vector': cvss_v2['vector'] if cvss_v2 else '',
                'severity': best_severity,
                'published_date': published,
                'last_modified_date': last_modified,
                'cpe_matches': cpe_matches,
                'references': ref_urls,
                'raw_data': vuln_data
            }
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability data: {e}")
            return None
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate severity based on CVSS v3 score"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score >= 0.1:
            return 'Low'
        else:
            return 'Info'
    
    def _calculate_severity_v2(self, score: float) -> str:
        """Calculate severity based on CVSS v2 score"""
        if score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score >= 0.1:
            return 'Low'
        else:
            return 'Info'
    
    def search_by_software_component(self, name: str, version: str = None) -> List[Dict]:
        """Search vulnerabilities for a specific software component"""
        try:
            # Clean the name for CPE format
            clean_name = name.lower().replace(' ', '_').replace('-', '_')
            
            # Handle special cases
            if 'microsoft' in clean_name or '.net' in clean_name:
                vendor = 'microsoft'
                if '.net' in clean_name:
                    clean_name = clean_name.replace('.net', 'net_framework').replace('_framework_framework', '_framework')
            elif 'adobe' in clean_name:
                vendor = 'adobe'
            elif 'apache' in clean_name:
                vendor = 'apache'
            else:
                vendor = '*'
            
            # Build CPE name for software component
            cpe_name = f"cpe:2.3:a:{vendor}:{clean_name}:{version or '*'}:*:*:*:*:*:*:*"
            
            vulnerabilities = self.search_vulnerabilities(cpe_name=cpe_name, limit=100)
            
            # If no vulnerabilities found with CPE, try keyword search
            if not vulnerabilities:
                logger.info(f"No vulnerabilities found with CPE, trying keyword search for: {name}")
                vulnerabilities = self.search_vulnerabilities(keyword=name, limit=100)
            
            # For now, return all vulnerabilities found (CPE or keyword search)
            # TODO: Implement more sophisticated filtering based on version matching
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching by software component: {e}")
            return []
    
    def get_recent_vulnerabilities(self, days: int = 7) -> List[Dict]:
        """Get recently published vulnerabilities"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 1000
            }
            
            logger.info(f"Searching for vulnerabilities from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            response = self._make_request(params)
            
            if response and 'vulnerabilities' in response:
                vulnerabilities = []
                for vuln in response['vulnerabilities']:
                    vuln_info = self._parse_vulnerability_data(vuln)
                    if vuln_info:
                        vulnerabilities.append(vuln_info)
                
                logger.info(f"Found {len(vulnerabilities)} recent vulnerabilities")
                return vulnerabilities
            else:
                logger.warning("No recent vulnerabilities found")
                return []
                
        except Exception as e:
            logger.error(f"Error getting recent vulnerabilities: {e}")
            return []

def main():
    """Main function for testing"""
    nvd = NVDIntegration()
    
    # Test vulnerability search
    print("Testing NVD vulnerability search...")
    vulns = nvd.search_vulnerabilities(keyword="Apache", severity="High", limit=10)
    for vuln in vulns:
        print(f"Found: {vuln['cve_id']} - {vuln['severity']} (Score: {vuln['cvss_v3_score']})")
    
    # Test software component search
    print("\nTesting software component search...")
    vulns = nvd.search_by_software_component("Apache", "2.4.41")
    for vuln in vulns:
        print(f"Found: {vuln['cve_id']} - {vuln['severity']}")
    
    # Test recent vulnerabilities
    print("\nTesting recent vulnerabilities...")
    vulns = nvd.get_recent_vulnerabilities(7)
    print(f"Found {len(vulns)} recent vulnerabilities")

if __name__ == "__main__":
    main()
