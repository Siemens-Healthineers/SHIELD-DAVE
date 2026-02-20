#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
MAC OUI Lookup Service for Device Assessment and Vulnerability Exposure ()
Handles MAC address to manufacturer lookups
"""

import requests
import json
import logging
from typing import Optional, Dict
import time

# Configure logging - only if log file is writable
try:
    log_file = '/var/www/html/logs/oui_lookup.log'
    # Check if log directory exists and is writable
    import os
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    handlers = []
    try:
        handlers.append(logging.FileHandler(log_file))
    except (IOError, PermissionError):
        # If can't write to file, just use StreamHandler
        pass
    
    handlers.append(logging.StreamHandler())
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
except Exception:
    # Fallback: minimal logging
    logging.basicConfig(
        level=logging.WARNING,
        format='%(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

logger = logging.getLogger(__name__)

class OUILookup:
    """MAC OUI lookup service"""
    
    def __init__(self):
        self.api_url = 'https://api.macvendors.com'
        self.cache = {}
        self.rate_limit = 100  # requests per minute
        self.request_count = 0
        self.last_reset = time.time()
    
    def lookup_manufacturer(self, mac_address: str) -> Optional[str]:
        """Look up manufacturer from MAC address"""
        try:
            # Clean MAC address
            mac = mac_address.replace(':', '').replace('-', '').upper()
            if len(mac) < 6:
                logger.warning(f"Invalid MAC address: {mac_address}")
                return None
            
            # Get OUI (first 6 characters)
            oui = mac[:6]
            
            # Check cache first
            if oui in self.cache:
                logger.info(f"Cache hit for OUI: {oui}")
                return self.cache[oui]
            
            # Check rate limit
            current_time = time.time()
            if current_time - self.last_reset > 60:  # Reset every minute
                self.request_count = 0
                self.last_reset = current_time
            
            if self.request_count >= self.rate_limit:
                wait_time = 60 - (current_time - self.last_reset)
                logger.warning(f"Rate limit reached. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                self.request_count = 0
                self.last_reset = time.time()
            
            # Make API request
            logger.info(f"Looking up OUI: {oui}")
            response = requests.get(f"{self.api_url}/{oui}", timeout=10)
            self.request_count += 1
            
            if response.status_code == 200:
                manufacturer = response.text.strip()
                if manufacturer and manufacturer != 'Not Found':
                    self.cache[oui] = manufacturer
                    logger.info(f"Found manufacturer: {manufacturer}")
                    return manufacturer
                else:
                    logger.warning(f"No manufacturer found for OUI: {oui}")
                    return None
            else:
                logger.error(f"API error: {response.status_code} - {response.text}")
                return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Error looking up OUI: {e}")
            return None
    
    def batch_lookup(self, mac_addresses: list) -> Dict[str, str]:
        """Look up multiple MAC addresses"""
        results = {}
        
        for mac in mac_addresses:
            manufacturer = self.lookup_manufacturer(mac)
            if manufacturer:
                results[mac] = manufacturer
            else:
                results[mac] = None
        
        return results
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'cache_size': len(self.cache),
            'cached_ouis': list(self.cache.keys()),
            'request_count': self.request_count,
            'rate_limit': self.rate_limit
        }

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='OUI Lookup Service')
    parser.add_argument('--lookup', type=str, help='MAC address to lookup')
    parser.add_argument('--test', action='store_true', help='Run test lookups')
    
    args = parser.parse_args()
    
    oui = OUILookup()
    
    if args.lookup:
        # Single lookup from command line - suppress all logging to stderr
        import sys
        import logging
        
        # Suppress all logging output
        logger.setLevel(logging.CRITICAL + 1)  # Above CRITICAL
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.CRITICAL + 1)
        
        # Remove all handlers
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
        
        # Also redirect stderr to suppress any errors/warnings
        old_stderr = sys.stderr
        sys.stderr = open('/dev/null', 'w')
        
        try:
            manufacturer = oui.lookup_manufacturer(args.lookup)
            if manufacturer:
                print(manufacturer, flush=True)
        finally:
            # Restore stderr
            sys.stderr.close()
            sys.stderr = old_stderr
        return
    
    if args.test:
        # Test single lookup
        print("Testing single OUI lookup...")
        manufacturer = oui.lookup_manufacturer("00:50:56")
        print(f"MAC 00:50:56 -> {manufacturer}")
        
        # Test batch lookup
        print("\nTesting batch lookup...")
        macs = ["00:50:56", "08:00:27", "52:54:00"]
        results = oui.batch_lookup(macs)
        for mac, manufacturer in results.items():
            print(f"MAC {mac} -> {manufacturer}")
        
        # Test cache stats
        print("\nCache statistics:")
        stats = oui.get_cache_stats()
        print(json.dumps(stats, indent=2))
    else:
        # Default: run tests
        print("Testing single OUI lookup...")
        manufacturer = oui.lookup_manufacturer("00:50:56")
        print(f"MAC 00:50:56 -> {manufacturer}")

if __name__ == "__main__":
    main()
