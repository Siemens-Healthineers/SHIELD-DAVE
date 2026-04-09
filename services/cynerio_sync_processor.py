#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

This script processes Cynerio synchronization queue items and exits.
Designed to be run via cron every few minutes.
"""

import os
import sys
import json
import logging

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Load .env file manually from project root
env_file_path = os.path.join(project_root, '.env')
if os.path.exists(env_file_path):
    with open(env_file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                # Handle KEY=VALUE format
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    # Only set if not already in environment
                    if key and not os.getenv(key):
                        os.environ[key] = value

from python.services.ingest_cynerio import ingest_cynerio_assets_into_dave

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'cynerio_integration.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('cynerio_cron_processor')

# Log .env file loading status
if os.path.exists(env_file_path):
    logger.info(f"Loaded environment variables from: {env_file_path}")
else:
    logger.warning(f".env file not found at: {env_file_path}")

class CynerioCronProcessor:
    """Cron-based Cynerio processor"""

    def __init__(self):
        pass

    def run(self):
        try:
            # Run the full ingestion process
            ingest_cynerio_assets_into_dave()

        except Exception as e:
            logger.error(f"Error: {e}")


def main():
    """Main entry point"""
    processor = CynerioCronProcessor()
    processor.run()

if __name__ == "__main__":
    main()
