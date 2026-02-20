#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
FDA Integration Service for Device Assessment and Vulnerability Exposure ()
Handles openFDA API integration for device mapping and recall monitoring
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
        logging.FileHandler('/var/www/html/logs/fda_integration.log')
    ]
)
logger = logging.getLogger(__name__)

class FDAIntegration:
    """FDA API integration service"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('OPENFDA_API_KEY', '')
        self.base_url = 'https://api.fda.gov'
        self.rate_limit = 1000  # requests per hour
        self.request_count = 0
        self.last_reset = datetime.now()
        
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make API request with rate limiting"""
        try:
            # Check rate limit
            if self.request_count >= self.rate_limit:
                time_since_reset = datetime.now() - self.last_reset
                if time_since_reset.total_seconds() < 3600:  # 1 hour
                    wait_time = 3600 - time_since_reset.total_seconds()
                    logger.warning(f"Rate limit reached. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    self.request_count = 0
                    self.last_reset = datetime.now()
            
            # Prepare request
            url = f"{self.base_url}{endpoint}"
            headers = {'User-Agent': '/1.0'}
            if self.api_key:
                params = params or {}
                params['api_key'] = self.api_key
            
            # Make request
            response = requests.get(url, params=params, headers=headers, timeout=30)
            self.request_count += 1
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:  # Rate limited
                logger.warning("Rate limited by FDA API. Waiting 60 seconds...")
                time.sleep(60)
                return self._make_request(endpoint, params)
            elif response.status_code == 404:
                # 404 is a normal response when no results are found
                logger.info("No results found for search query")
                return {"results": []}
            else:
                logger.error(f"FDA API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def _matches_manufacturer(self, device_manufacturer: str, search_manufacturer: str) -> bool:
        """Check if device manufacturer matches search manufacturer"""
        if not device_manufacturer or not search_manufacturer:
            return False
        
        # Convert to lowercase for comparison
        device_lower = device_manufacturer.lower()
        search_lower = search_manufacturer.lower()
        
        # For "Siemens" searches, be more lenient since we're searching for all Siemens companies
        if search_lower == "siemens":
            # Accept any manufacturer that contains "siemens"
            if "siemens" in device_lower:
                return True
        
        # Check for exact match
        if device_lower == search_lower:
            return True
        
        # Check if search term is contained in device manufacturer
        if search_lower in device_lower:
            return True
        
        # Check if device manufacturer is contained in search term
        if device_lower in search_lower:
            return True
        
        # Check for common variations
        search_words = search_lower.split()
        device_words = device_lower.split()
        
        # If search has multiple words, check if all are in device
        if len(search_words) > 1:
            match = all(word in device_lower for word in search_words)
            if match:
                return True
        
        # If device has multiple words, check if search word is in any of them
        if len(device_words) > 1:
            match = any(search_lower in word for word in device_words)
            if match:
                return True
        
        # More lenient matching - check if any word from search appears in device
        for search_word in search_words:
            if search_word in device_lower:
                return True
        
        # Check if any word from device appears in search
        for device_word in device_words:
            if device_word in search_lower:
                return True
        
        return False
    
    def _matches_brand_name(self, device_info: Dict, search_brand: str) -> bool:
        """Check if device brand name matches search brand name"""
        if not search_brand:
            return True  # If no brand specified, match all
        
        search_lower = search_brand.lower()
        
        # Check brand_name field first
        brand_name = device_info.get('brand_name', '')
        if brand_name:
            brand_lower = brand_name.lower()
            if search_lower in brand_lower or brand_lower in search_lower:
                return True
        
        # Check model_number field
        model_number = device_info.get('model_number', '')
        if model_number:
            model_lower = model_number.lower()
            if search_lower in model_lower or model_lower in search_lower:
                return True
        
        # Check catalog_number field
        catalog_number = device_info.get('catalog_number', '')
        if catalog_number:
            catalog_lower = catalog_number.lower()
            if search_lower in catalog_lower or catalog_lower in search_lower:
                return True
        
        # Check device_description for brand mentions
        description = device_info.get('device_description', '')
        if description:
            desc_lower = description.lower()
            if search_lower in desc_lower:
                return True
        
        return False
    
    def search_devices(self, manufacturer: str, model: str = None, limit: int = 100) -> List[Dict]:
        """Search for devices in FDA database with pagination support"""
        try:
            # If searching for just "Siemens", use broader search to get all Siemens companies
            if manufacturer.lower() == "siemens":
                # Use broader search for Siemens to get all companies
                query_parts = ["company_name:Siemens"]
            else:
                # Build more precise search query - use exact phrase matching
                # Wrap manufacturer in quotes for exact phrase search
                query_parts = [f'company_name:"{manufacturer}"']
            
            if model:
                # Try multiple model fields
                model_queries = [
                    f"version_or_model_number:{model}",
                    f"catalog_number:{model}",
                    f"brand_name:{model}"
                ]
                query_parts.append(f"({' OR '.join(model_queries)})")
            
            query = " AND ".join(query_parts)
            
            devices = []
            skip = 0
            page_size = 100  # FDA API max is 100 per request
            max_pages = (limit + page_size - 1) // page_size  # Calculate max pages needed
            
            logger.info(f"Searching FDA for: {query} (target limit={limit}, max_pages={max_pages})")
            
            for page in range(max_pages):
                params = {
                    'search': query,
                    'limit': page_size,
                    'skip': skip
                }
                
                logger.info(f"Fetching page {page + 1} (skip={skip}, limit={page_size})")
                response = self._make_request('/device/udi.json', params)
                
                if not response or 'results' not in response:
                    logger.warning("No more results or API error")
                    break
                
                # Check if we got any results
                if not response['results']:
                    logger.info("No more results available")
                    break
                
                # Process results
                page_devices = []
                for device in response['results']:
                    device_info = self._parse_device_data(device)
                    if device_info:
                        # Filter results to match manufacturer more closely
                        if self._matches_manufacturer(device_info.get('manufacturer_name', ''), manufacturer):
                            # If brand name/model is specified, also filter by that
                            if model:
                                if self._matches_brand_name(device_info, model):
                                    page_devices.append(device_info)
                            else:
                                page_devices.append(device_info)
                
                # Add devices from this page
                devices.extend(page_devices)
                logger.info(f"Page {page + 1}: Found {len(page_devices)} matching devices (total so far: {len(devices)})")
                
                # Check if we've reached our limit
                if len(devices) >= limit:
                    devices = devices[:limit]  # Trim to exact limit
                    logger.info(f"Reached target limit of {limit} devices")
                    break
                
                # Move to next page
                skip += page_size
                
                # If we got fewer results than requested, we've reached the end
                if len(response['results']) < page_size:
                    logger.info("Reached end of available results")
                    break
            
            logger.info(f"Search complete: Found {len(devices)} devices total")
            return devices
                
        except Exception as e:
            logger.error(f"Error searching devices: {e}")
            return []
    
    def _parse_device_data(self, device_data: Dict) -> Optional[Dict]:
        """Parse FDA device data into standardized format"""
        try:
            # Extract basic device information
            device_info = {
                # Basic Device Information
                'device_identifier': device_data.get('public_device_record_key', ''),
                'brand_name': device_data.get('brand_name', ''),
                'model_number': device_data.get('version_or_model_number', ''),
                'manufacturer_name': device_data.get('company_name', ''),
                'device_description': device_data.get('device_description', ''),
                'catalog_number': device_data.get('catalog_number', ''),
                
                # Regulatory Information
                'gmdn_term': self._extract_gmdn_term(device_data),
                'gmdn_code': self._extract_gmdn_code(device_data),
                'gmdn_definition': self._extract_gmdn_definition(device_data),
                'is_implantable': self._extract_implantable_status(device_data),
                'fda_class': self._extract_fda_class(device_data),
                'fda_class_name': self._extract_fda_class_name(device_data),
                'regulation_number': self._extract_regulation_number(device_data),
                'medical_specialty': self._extract_medical_specialty(device_data),
                
                # Device Identifiers
                'udi': self._extract_primary_udi(device_data),
                'primary_udi': self._extract_primary_udi(device_data),
                'package_udi': self._extract_package_udi(device_data),
                'issuing_agency': self._extract_issuing_agency(device_data),
                
                # Commercial Status
                'commercial_status': device_data.get('commercial_distribution_status', ''),
                'record_status': device_data.get('record_status', ''),
                'is_single_use': device_data.get('is_single_use', 'false') == 'true',
                'is_kit': device_data.get('is_kit', 'false') == 'true',
                'is_combination_product': device_data.get('is_combination_product', 'false') == 'true',
                'is_otc': device_data.get('is_otc', 'false') == 'true',
                'is_rx': device_data.get('is_rx', 'false') == 'true',
                
                # Sterilization Information
                'is_sterile': self._extract_sterilization_info(device_data, 'is_sterile'),
                'sterilization_methods': self._extract_sterilization_info(device_data, 'sterilization_methods'),
                'is_sterilization_prior_use': self._extract_sterilization_info(device_data, 'is_sterilization_prior_use'),
                
                # Regulatory Compliance
                'is_pm_exempt': device_data.get('is_pm_exempt', 'false') == 'true',
                'is_direct_marking_exempt': device_data.get('is_direct_marking_exempt', 'false') == 'true',
                'has_serial_number': device_data.get('has_serial_number', 'false') == 'true',
                'has_lot_batch_number': device_data.get('has_lot_or_batch_number', 'false') == 'true',
                'has_expiration_date': device_data.get('has_expiration_date', 'false') == 'true',
                'has_manufacturing_date': device_data.get('has_manufacturing_date', 'false') == 'true',
                
                # MRI Safety
                'mri_safety': device_data.get('mri_safety', ''),
                
                # Product Codes
                'product_code': self._extract_product_code(device_data),
                'product_code_name': self._extract_product_code_name(device_data),
                
                # Contact Information
                'customer_phone': self._extract_customer_phone(device_data),
                'customer_email': self._extract_customer_email(device_data),
                
                # Version Information
                'public_version_number': device_data.get('public_version_number', ''),
                'public_version_date': self._parse_date(device_data.get('public_version_date', '')),
                'public_version_status': device_data.get('public_version_status', ''),
                'publish_date': self._parse_date(device_data.get('publish_date', '')),
                
                # Package Information
                'device_count_in_base_package': self._parse_int(device_data.get('device_count_in_base_package', '1')),
                'labeler_duns_number': device_data.get('labeler_duns_number', ''),
                
                # 510k Information
                'premarket_submissions': self._extract_premarket_submissions(device_data),
                
                # Raw data for reference
                'raw_data': device_data
            }
            
            # Calculate confidence score based on available data
            confidence = self._calculate_confidence(device_info)
            device_info['confidence_score'] = confidence
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error parsing device data: {e}")
            return None
    
    def _extract_gmdn_term(self, device_data: Dict) -> str:
        """Extract GMDN term from device data"""
        gmdn_terms = device_data.get('gmdn_terms', [])
        if isinstance(gmdn_terms, list) and len(gmdn_terms) > 0:
            return gmdn_terms[0].get('name', '')
        elif isinstance(gmdn_terms, dict):
            return gmdn_terms.get('name', '')
        return ''
    
    def _extract_gmdn_code(self, device_data: Dict) -> str:
        """Extract GMDN code from device data"""
        gmdn_terms = device_data.get('gmdn_terms', [])
        if isinstance(gmdn_terms, list) and len(gmdn_terms) > 0:
            return gmdn_terms[0].get('code', '')
        elif isinstance(gmdn_terms, dict):
            return gmdn_terms.get('code', '')
        return ''
    
    def _extract_gmdn_definition(self, device_data: Dict) -> str:
        """Extract GMDN definition from device data"""
        gmdn_terms = device_data.get('gmdn_terms', [])
        if isinstance(gmdn_terms, list) and len(gmdn_terms) > 0:
            return gmdn_terms[0].get('definition', '')
        elif isinstance(gmdn_terms, dict):
            return gmdn_terms.get('definition', '')
        return ''
    
    def _extract_implantable_status(self, device_data: Dict) -> bool:
        """Extract implantable status from device data"""
        gmdn_terms = device_data.get('gmdn_terms', [])
        if isinstance(gmdn_terms, list) and len(gmdn_terms) > 0:
            return gmdn_terms[0].get('implantable', 'false') == 'true'
        elif isinstance(gmdn_terms, dict):
            return gmdn_terms.get('implantable', 'false') == 'true'
        return False
    
    def _extract_fda_class(self, device_data: Dict) -> str:
        """Extract FDA class from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            openfda = product_codes[0].get('openfda', {})
            return openfda.get('device_class', '')
        elif isinstance(product_codes, dict):
            openfda = product_codes.get('openfda', {})
            return openfda.get('device_class', '')
        return ''
    
    def _extract_fda_class_name(self, device_data: Dict) -> str:
        """Extract FDA class name from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            return product_codes[0].get('name', '')
        elif isinstance(product_codes, dict):
            return product_codes.get('name', '')
        return ''
    
    def _extract_regulation_number(self, device_data: Dict) -> str:
        """Extract regulation number from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            openfda = product_codes[0].get('openfda', {})
            return openfda.get('regulation_number', '')
        elif isinstance(product_codes, dict):
            openfda = product_codes.get('openfda', {})
            return openfda.get('regulation_number', '')
        return ''
    
    def _extract_medical_specialty(self, device_data: Dict) -> str:
        """Extract medical specialty from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            openfda = product_codes[0].get('openfda', {})
            return openfda.get('medical_specialty_description', '')
        elif isinstance(product_codes, dict):
            openfda = product_codes.get('openfda', {})
            return openfda.get('medical_specialty_description', '')
        return ''
    
    def _extract_primary_udi(self, device_data: Dict) -> str:
        """Extract primary UDI from device data"""
        identifiers = device_data.get('identifiers', [])
        for identifier in identifiers:
            if identifier.get('type') == 'Primary':
                return identifier.get('id', '')
        return ''
    
    def _extract_package_udi(self, device_data: Dict) -> str:
        """Extract package UDI from device data"""
        identifiers = device_data.get('identifiers', [])
        for identifier in identifiers:
            if identifier.get('type') == 'Package':
                return identifier.get('id', '')
        return ''
    
    def _extract_issuing_agency(self, device_data: Dict) -> str:
        """Extract issuing agency from device data"""
        identifiers = device_data.get('identifiers', [])
        if len(identifiers) > 0:
            return identifiers[0].get('issuing_agency', '')
        return ''
    
    def _extract_sterilization_info(self, device_data: Dict, field: str) -> str:
        """Extract sterilization information from device data"""
        sterilization = device_data.get('sterilization', {})
        if field == 'is_sterile':
            return sterilization.get('is_sterile', 'false') == 'true'
        elif field == 'sterilization_methods':
            return sterilization.get('sterilization_methods', '')
        elif field == 'is_sterilization_prior_use':
            return sterilization.get('is_sterilization_prior_use', 'false') == 'true'
        return ''
    
    def _extract_product_code(self, device_data: Dict) -> str:
        """Extract product code from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            return product_codes[0].get('code', '')
        elif isinstance(product_codes, dict):
            return product_codes.get('code', '')
        return ''
    
    def _extract_product_code_name(self, device_data: Dict) -> str:
        """Extract product code name from device data"""
        product_codes = device_data.get('product_codes', [])
        if isinstance(product_codes, list) and len(product_codes) > 0:
            return product_codes[0].get('name', '')
        elif isinstance(product_codes, dict):
            return product_codes.get('name', '')
        return ''
    
    def _extract_customer_phone(self, device_data: Dict) -> str:
        """Extract customer phone from device data"""
        contacts = device_data.get('customer_contacts', [])
        if isinstance(contacts, list) and len(contacts) > 0:
            return contacts[0].get('phone', '')
        elif isinstance(contacts, dict):
            return contacts.get('phone', '')
        return ''
    
    def _extract_customer_email(self, device_data: Dict) -> str:
        """Extract customer email from device data"""
        contacts = device_data.get('customer_contacts', [])
        if isinstance(contacts, list) and len(contacts) > 0:
            return contacts[0].get('email', '')
        elif isinstance(contacts, dict):
            return contacts.get('email', '')
        return ''
    
    def _parse_date(self, date_str: str) -> str:
        """Parse date string to ISO format"""
        if not date_str:
            return ''
        try:
            from datetime import datetime
            # Try different date formats
            for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
                try:
                    return datetime.strptime(date_str, fmt).strftime('%Y-%m-%d')
                except ValueError:
                    continue
            return date_str
        except:
            return date_str
    
    def _parse_int(self, value: str) -> int:
        """Parse integer from string"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return 1
    
    def _extract_premarket_submissions(self, device_data: Dict) -> List[Dict]:
        """Extract premarket submissions (510k data) from device data"""
        try:
            # Check if premarket_submissions exists in raw_data
            raw_data = device_data.get('raw_data', {})
            if isinstance(raw_data, dict) and 'premarket_submissions' in raw_data:
                submissions = raw_data['premarket_submissions']
                if isinstance(submissions, list):
                    return submissions
            
            # Fallback: check direct field
            submissions = device_data.get('premarket_submissions', [])
            if isinstance(submissions, list):
                return submissions
                
            return []
        except Exception as e:
            logger.error(f"Error extracting premarket submissions: {e}")
            return []

    def _calculate_confidence(self, device_info: Dict) -> float:
        """Calculate confidence score for device match"""
        score = 0.0
        
        # Base score for having device identifier
        if device_info.get('device_identifier'):
            score += 0.3
        
        # Score for brand name match
        if device_info.get('brand_name'):
            score += 0.2
        
        # Score for model number match
        if device_info.get('model_number'):
            score += 0.2
        
        # Score for manufacturer match
        if device_info.get('manufacturer_name'):
            score += 0.2
        
        # Score for device description
        if device_info.get('device_description'):
            score += 0.1
        
        return min(score, 1.0)
    
    def get_device_by_udi(self, udi: str) -> Optional[Dict]:
        """Get specific device by UDI"""
        try:
            params = {
                'search': f'udi:"{udi}"',
                'limit': 1,
                'format': 'json'
            }
            
            response = self._make_request('/device/udi.json', params)
            
            if response and 'results' in response and len(response['results']) > 0:
                return self._parse_device_data(response['results'][0])
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error getting device by UDI: {e}")
            return None
    
    def search_510k(self, device_id: str, limit: int = 10) -> List[Dict]:
        """Search for 510k information for a device with pagination support"""
        try:
            query_parts = [
                f"device_name:{device_id}",
                f"product_code:{device_id}",
                f"k_number:{device_id}"
            ]
            query = " OR ".join(query_parts)

            results = []
            skip = 0
            page_size = 100  # FDA API max is 100 per request
            max_pages = (limit + page_size - 1) // page_size

            logger.info(f"Searching 510k for: {query} (target limit={limit}, max_pages={max_pages})")

            for page in range(max_pages):
                params = {
                    'search': query,
                    'limit': page_size,
                    'skip': skip
                }
                
                logger.info(f"Fetching 510k page {page + 1} (skip={skip}, limit={page_size})")
                response = self._make_request('/device/510k.json', params)

                if not response or 'results' not in response or not response['results']:
                    logger.info("No more 510k results available")
                    break

                for item in response['results']:
                    result = self._parse_510k_data(item)
                    if result:
                        results.append(result)

                logger.info(f"Page {page + 1}: Found {len(response['results'])} 510k records (total so far: {len(results)})")

                if len(results) >= limit:
                    results = results[:limit] # Trim to exact limit
                    logger.info(f"Reached target limit of {limit} 510k records")
                    break

                skip += page_size

                if len(response['results']) < page_size:
                    logger.info("Reached end of available 510k results")
                    break
            
            logger.info(f"510k search complete: Found {len(results)} records total")
            return results
            
        except Exception as e:
            logger.error(f"Error searching 510k: {e}")
            return []
    
    def _parse_510k_data(self, data: Dict) -> Optional[Dict]:
        """Parse 510k data from FDA API response - capture all available fields"""
        try:
            # Extract openfda data if available
            openfda = data.get('openfda', {})
            
            return {
                # Basic 510k Information
                'k_number': str(data.get('k_number', '')),
                'decision_code': str(data.get('decision_code', '')),
                'decision_date': str(data.get('decision_date', '')),
                'decision_description': str(data.get('decision_description', '')),
                'clearance_type': str(data.get('clearance_type', '')),
                'date_received': str(data.get('date_received', '')),
                
                # Device Information
                'device_name': str(data.get('device_name', '')),
                'product_code': str(data.get('product_code', '')),
                'regulation_number': str(data.get('regulation_number', '')),
                'statement_or_summary': str(data.get('statement_or_summary', '')),
                
                # Applicant Information
                'applicant': str(data.get('applicant', '')),
                'contact': str(data.get('contact', '')),
                'address_1': str(data.get('address_1', '')),
                'address_2': str(data.get('address_2', '')),
                'city': str(data.get('city', '')),
                'state': str(data.get('state', '')),
                'zip_code': str(data.get('zip_code', '')),
                'postal_code': str(data.get('postal_code', '')),
                'country_code': str(data.get('country_code', '')),
                
                # Review Information
                'advisory_committee': str(data.get('advisory_committee', '')),
                'advisory_committee_description': str(data.get('advisory_committee_description', '')),
                'review_advisory_committee': str(data.get('review_advisory_committee', '')),
                'expedited_review_flag': str(data.get('expedited_review_flag', '')),
                'third_party_flag': str(data.get('third_party_flag', '')),
                
                # OpenFDA Data (if available)
                'device_class': str(openfda.get('device_class', '')),
                'medical_specialty_description': str(openfda.get('medical_specialty_description', '')),
                'registration_numbers': ','.join(openfda.get('registration_number', [])),
                'fei_numbers': ','.join(openfda.get('fei_number', []))
            }
        except Exception as e:
            logger.error(f"Error parsing 510k data: {e}")
            return None
    
    def search_recalls(self, days_back: int = 30) -> List[Dict]:
        """Search for recent recalls"""
        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                'search': f'recall_date:[{start_date.strftime("%Y%m%d")}+TO+{end_date.strftime("%Y%m%d")}]',
                'limit': 100,
                'format': 'json'
            }
            
            logger.info(f"Searching for recalls from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            response = self._make_request('/device/enforcement.json', params)
            
            if response and 'results' in response:
                recalls = []
                for recall in response['results']:
                    recall_info = self._parse_recall_data(recall)
                    if recall_info:
                        recalls.append(recall_info)
                
                logger.info(f"Found {len(recalls)} recalls")
                return recalls
            else:
                logger.warning("No recalls found or API error")
                return []
                
        except Exception as e:
            logger.error(f"Error searching recalls: {e}")
            return []
    
    def search_recalls_by_k_number(self, k_number: str) -> List[Dict]:
        """Search for recalls related to a specific 510k number"""
        try:
            params = {
                'search': f'k_number:{k_number}',
                'limit': 100,
                'format': 'json'
            }
            
            logger.info(f"Searching for recalls related to K number: {k_number}")
            response = self._make_request('/device/enforcement.json', params)
            
            if response and 'results' in response:
                recalls = []
                for recall in response['results']:
                    recall_info = self._parse_recall_data(recall)
                    if recall_info:
                        recalls.append(recall_info)
                
                logger.info(f"Found {len(recalls)} recalls for K number {k_number}")
                return recalls
            else:
                logger.warning(f"No recalls found for K number {k_number}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching recalls by K number: {e}")
            return []
    
    def search_adverse_events_by_k_number(self, k_number: str) -> List[Dict]:
        """Search for adverse events related to a specific 510k number"""
        try:
            params = {
                'search': f'k_number:{k_number}',
                'limit': 100,
                'format': 'json'
            }
            
            logger.info(f"Searching for adverse events related to K number: {k_number}")
            response = self._make_request('/device/event.json', params)
            
            if response and 'results' in response:
                events = []
                for event in response['results']:
                    event_info = self._parse_adverse_event_data(event)
                    if event_info:
                        events.append(event_info)
                
                logger.info(f"Found {len(events)} adverse events for K number {k_number}")
                return events
            else:
                logger.warning(f"No adverse events found for K number {k_number}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching adverse events by K number: {e}")
            return []
    
    def search_device_problems_by_k_number(self, k_number: str) -> List[Dict]:
        """Search for device problems related to a specific 510k number"""
        try:
            params = {
                'search': f'k_number:{k_number}',
                'limit': 100,
                'format': 'json'
            }
            
            logger.info(f"Searching for device problems related to K number: {k_number}")
            response = self._make_request('/device/event.json', params)
            
            if response and 'results' in response:
                problems = []
                for problem in response['results']:
                    problem_info = self._parse_device_problem_data(problem)
                    if problem_info:
                        problems.append(problem_info)
                
                logger.info(f"Found {len(problems)} device problems for K number {k_number}")
                return problems
            else:
                logger.warning(f"No device problems found for K number {k_number}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching device problems by K number: {e}")
            return []
    
    def _parse_recall_data(self, recall_data: Dict) -> Optional[Dict]:
        """Parse FDA recall data into standardized format"""
        try:
            recall_info = {
                'fda_recall_number': recall_data.get('recall_number', ''),
                'recall_date': recall_data.get('recall_date', ''),
                'product_description': recall_data.get('product_description', ''),
                'reason_for_recall': recall_data.get('reason_for_recall', ''),
                'manufacturer_name': recall_data.get('manufacturer_name', ''),
                'product_code': recall_data.get('product_code', ''),
                'recall_classification': recall_data.get('recall_classification', ''),
                'k_number': recall_data.get('k_number', ''),
                'raw_data': recall_data
            }
            
            return recall_info
            
        except Exception as e:
            logger.error(f"Error parsing recall data: {e}")
            return None
    
    def _parse_adverse_event_data(self, event_data: Dict) -> Optional[Dict]:
        """Parse FDA adverse event data into standardized format"""
        try:
            event_info = {
                'report_number': event_data.get('report_number', ''),
                'event_date': event_data.get('event_date', ''),
                'k_number': event_data.get('k_number', ''),
                'device_name': event_data.get('device_name', ''),
                'manufacturer_name': event_data.get('manufacturer_name', ''),
                'product_code': event_data.get('product_code', ''),
                'event_type': event_data.get('event_type', ''),
                'event_description': event_data.get('event_description', ''),
                'patient_problem': event_data.get('patient_problem', ''),
                'device_problem': event_data.get('device_problem', ''),
                'malfunction_flag': event_data.get('malfunction_flag', ''),
                'raw_data': event_data
            }
            
            return event_info
            
        except Exception as e:
            logger.error(f"Error parsing adverse event data: {e}")
            return None
    
    def _parse_device_problem_data(self, problem_data: Dict) -> Optional[Dict]:
        """Parse FDA device problem data into standardized format"""
        try:
            problem_info = {
                'report_number': problem_data.get('report_number', ''),
                'event_date': problem_data.get('event_date', ''),
                'k_number': problem_data.get('k_number', ''),
                'device_name': problem_data.get('device_name', ''),
                'manufacturer_name': problem_data.get('manufacturer_name', ''),
                'product_code': problem_data.get('product_code', ''),
                'device_problem': problem_data.get('device_problem', ''),
                'patient_problem': problem_data.get('patient_problem', ''),
                'malfunction_flag': problem_data.get('malfunction_flag', ''),
                'raw_data': problem_data
            }
            
            return problem_info
            
        except Exception as e:
            logger.error(f"Error parsing device problem data: {e}")
            return None
    
    def get_manufacturer_suggestions(self, partial_name: str) -> List[str]:
        """Get manufacturer name suggestions for autocomplete"""
        try:
            params = {
                'search': f'company_name:{partial_name}*',
                'limit': 20
            }
            
            response = self._make_request('/device/udi.json', params)
            
            if response and 'results' in response:
                manufacturers = set()
                for device in response['results']:
                    if device.get('company_name'):
                        manufacturers.add(device['company_name'])
                
                return sorted(list(manufacturers))
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error getting manufacturer suggestions: {e}")
            return []

class OUILookup:
    """MAC OUI lookup service"""
    
    def __init__(self):
        self.api_url = 'https://api.macvendors.com'
        self.cache = {}
    
    def lookup_manufacturer(self, mac_address: str) -> Optional[str]:
        """Look up manufacturer from MAC address"""
        try:
            # Clean MAC address
            mac = mac_address.replace(':', '').replace('-', '').upper()
            if len(mac) < 6:
                return None
            
            # Get OUI (first 6 characters)
            oui = mac[:6]
            
            # Check cache first
            if oui in self.cache:
                return self.cache[oui]
            
            # Make API request
            response = requests.get(f"{self.api_url}/{oui}", timeout=10)
            
            if response.status_code == 200:
                manufacturer = response.text.strip()
                if manufacturer and manufacturer != 'Not Found':
                    self.cache[oui] = manufacturer
                    return manufacturer
            
            return None
            
        except Exception as e:
            logger.error(f"Error looking up OUI: {e}")
            return None

def main():
    """Main function for command-line interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 fda_integration.py <command> [args...]")
        print("Commands:")
        print("  search_devices <manufacturer> [model]")
        print("  get_suggestions <partial_name>")
        print("  search_510k <device_id> [--limit <number>]")
        print("  search_recalls [days_back]")
        print("  search_recalls_by_k_number <k_number>")
        print("  search_adverse_events_by_k_number <k_number>")
        print("  search_device_problems_by_k_number <k_number>")
        sys.exit(1)
    
    command = sys.argv[1]
    fda = FDAIntegration()
    
    try:
        if command == "search_devices":
            if len(sys.argv) < 3:
                print("Error: Manufacturer is required")
                sys.exit(1)
            
            manufacturer = sys.argv[2]
            model = sys.argv[3] if len(sys.argv) > 3 else None
            limit = int(sys.argv[4]) if len(sys.argv) > 4 else 10
            
            devices = fda.search_devices(manufacturer, model, limit)
            print(json.dumps(devices))
            
        elif command == "get_suggestions":
            if len(sys.argv) < 3:
                print("Error: Partial name is required")
                sys.exit(1)
            
            partial_name = sys.argv[2]
            suggestions = fda.get_manufacturer_suggestions(partial_name)
            print(json.dumps(suggestions))
            
        elif command == "search_510k":
            if len(sys.argv) < 3:
                print("Error: Device ID is required")
                sys.exit(1)
            
            device_id = sys.argv[2]
            limit = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == '--limit' else 10
            results = fda.search_510k(device_id, limit)
            print(json.dumps(results))
            
        elif command == "search_recalls":
            days_back = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            recalls = fda.search_recalls(days_back)
            print(json.dumps(recalls))
            
        elif command == "search_recalls_by_k_number":
            if len(sys.argv) < 3:
                print("Error: K number is required")
                sys.exit(1)
            
            k_number = sys.argv[2]
            recalls = fda.search_recalls_by_k_number(k_number)
            print(json.dumps(recalls))
            
        elif command == "search_adverse_events_by_k_number":
            if len(sys.argv) < 3:
                print("Error: K number is required")
                sys.exit(1)
            
            k_number = sys.argv[2]
            events = fda.search_adverse_events_by_k_number(k_number)
            print(json.dumps(events))
            
        elif command == "search_device_problems_by_k_number":
            if len(sys.argv) < 3:
                print("Error: K number is required")
                sys.exit(1)
            
            k_number = sys.argv[2]
            problems = fda.search_device_problems_by_k_number(k_number)
            print(json.dumps(problems))
            
        else:
            print(f"Error: Unknown command '{command}'")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
