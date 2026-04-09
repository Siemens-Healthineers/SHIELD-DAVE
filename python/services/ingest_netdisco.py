"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
import sys
import requests
import json
import csv
from io import StringIO
from datetime import datetime
from typing import List, Optional, Dict, Any
import logging
import os


# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(project_root)

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

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Use INFO for normal operation, DEBUG for troubleshooting
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/netdisco_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Log .env file loading status
if os.path.exists(env_file_path):
    logger.info(f"Loaded environment variables from: {env_file_path}")
else:
    logger.warning(f".env file not found at: {env_file_path}")

# NetDisco API Configuration
NETDISCO_API_URL = os.getenv("NETDISCO_API_URL")
# No authentication required for NetDisco


#####################################################################################################################
def fetch_netdisco_devices() -> List[Dict[str, Any]]:
    """
    Fetch all devices from NetDisco API.
    
    NetDisco API endpoint: /api/v1/search/device?q=a&matchall=true&seeallcolumns=true
    No authentication required.
    
    The API can return either JSON or CSV depending on the Accept header.
    We request JSON format using Accept: application/json header.
    
    Returns:
        list: List of all devices from NetDisco
    
    Raises:
        requests.HTTPError: If the API request fails
    """
    url = NETDISCO_API_URL
    params = {
        "q": "a",  # Search query (using 'a' to match most devices)
        "matchall": "true",  # Match all results
        "seeallcolumns": "true"  # Get all available columns
    }
    
    # Request JSON format explicitly
    headers = {
        "Accept": "application/json"
    }
    
    logger.info(f"Fetching devices from NetDisco API: {url}")
    logger.info(f"Request parameters: {params}")
    
    try:
        response = requests.get(url+"/search/device", params=params, headers=headers, timeout=30)
        
        # Log response details for debugging
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content type: {response.headers.get('Content-Type', 'unknown')}")
        logger.info(f"Response content length: {len(response.content)}")
        
        response.raise_for_status()
        
        # Check if response is empty
        if not response.content or len(response.content.strip()) == 0:
            logger.warning("NetDisco API returned empty response")
            return []
        
        # Check content type and parse accordingly
        content_type = response.headers.get('Content-Type', '')
        
        if 'json' in content_type.lower():
            # Parse JSON response
            try:
                devices = response.json()
                logger.info(f"Successfully fetched {len(devices)} devices from NetDisco (JSON format)")
                return devices
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                logger.error(f"Response text: {response.text[:1000]}")
                raise
        elif 'csv' in content_type.lower() or 'comma-separated' in content_type.lower():
            # Parse CSV response
            logger.info("NetDisco returned CSV format, parsing...")
            devices = parse_netdisco_csv(response.text)
            logger.info(f"Successfully parsed {len(devices)} devices from NetDisco (CSV format)")
            return devices
        else:
            logger.warning(f"Unexpected content type: {content_type}")
            logger.warning(f"Response text: {response.text[:1000]}")
            # Try JSON first, then CSV
            try:
                devices = response.json()
                logger.info(f"Successfully fetched {len(devices)} devices from NetDisco (JSON format)")
                return devices
            except json.JSONDecodeError:
                logger.info("JSON parsing failed, trying CSV...")
                devices = parse_netdisco_csv(response.text)
                logger.info(f"Successfully parsed {len(devices)} devices from NetDisco (CSV format)")
                return devices
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching devices from NetDisco: {e}")
        raise


#####################################################################################################################
def parse_netdisco_csv(csv_text: str) -> List[Dict[str, Any]]:
    """
    Parse CSV response from NetDisco API and convert to list of dictionaries.
    
    CSV columns from NetDisco:
    Device, Location, System Name, Model, OS Version, Management IP, Serials, First Seen, Last Discovered
    
    Args:
        csv_text: CSV text from NetDisco API
        
    Returns:
        list: List of device dictionaries
    """
    devices = []
    
    try:
        # Parse CSV
        csv_reader = csv.DictReader(StringIO(csv_text))
        
        for row in csv_reader:
            # Map CSV columns to our expected format
            device = {
                "ip": row.get("Device", "").strip() or row.get("Management IP", "").strip(),
                "location": row.get("Location", "").strip(),
                "name": row.get("System Name", "").strip(),
                "model": row.get("Model", "").strip(),
                "os_ver": row.get("OS Version", "").strip(),
                "serial": row.get("Serials", "").strip(),
                "first_seen_stamp": row.get("First Seen", "").strip(),
                "last_discover_stamp": row.get("Last Discovered", "").strip(),
                # Set defaults for fields not in CSV
                "mac": None,
                "vendor": None,
                "os": None,
                "description": None,
                "contact": None,
                "uptime": 0,  # Not available in CSV, assume active if in list
                "dns": None,
                "snmp_class": None,
                "chassis_id": None
            }
            
            # Only add if we have at least an IP address
            if device["ip"]:
                devices.append(device)
        
        logger.info(f"Parsed {len(devices)} devices from CSV")
        
    except Exception as e:
        logger.error(f"Error parsing NetDisco CSV: {e}")
        logger.error(f"CSV text: {csv_text[:1000]}")
        raise
    
    return devices


#####################################################################################################################
def map_netdisco_to_dave_asset(netdisco_device: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a NetDisco device to DAVE asset format.
    
    IMPORTANT: This function does NOT generate asset_id. The DAVE API will generate
    a UUID for asset_id. Instead, we use the 'source' field with a NetDisco identifier
    (based on MAC address or IP) to track which assets came from NetDisco and enable
    updates on subsequent runs.
    
    NetDisco Field Mapping:
    -----------------------
    NetDisco Field          DAVE Field              Type            Notes
    -------------------------------------------------------------------------------
    ip                      ip_address              string          Device IP address
    mac                     mac_address             string          Device MAC address
    name                    hostname                string          Device hostname/name
    dns                     hostname (fallback)     string          DNS name if hostname empty
    vendor                  manufacturer            string          Device vendor/manufacturer
    model                   model                   string          Device model
    serial                  serial_number           string          Device serial number
    description             description             string          Device description
    os                      os_version              string          Operating system
    os_ver                  firmware_version        string          OS/firmware version
    location                location                string          Physical location
    contact                 notes                   string          Contact information
    uptime                  uptime                  integer         Device uptime in seconds
    first_seen_stamp        first_seen              datetime        First discovery timestamp
    last_discover_stamp     last_seen               datetime        Last discovery timestamp
    layers                  -                       -               Network layers (informational)
    snmp_class              -                       -               SNMP device class
    chassis_id              -                       -               Chassis identifier
    
    Status Mapping:
    - If uptime > 0: Active
    - Otherwise: Inactive
    
    Args:
        netdisco_device: Device data from NetDisco API
        
    Returns:
        dict: Asset data formatted for DAVE API
    """
    
    # Determine status based on uptime
    # If we have uptime data, use it; otherwise assume Active since device is in NetDisco
    uptime = netdisco_device.get("uptime")
    if uptime is not None:
        try:
            status = "Active" if int(uptime) > 0 else "Inactive"
        except (ValueError, TypeError):
            status = "Active"  # Default to Active if uptime is not a valid number
    else:
        status = "Active"  # Default to Active if no uptime data
    
    # Get hostname - prioritize 'name', fallback to 'dns', then generate from other fields
    hostname = (netdisco_device.get("name") or "").strip()
    if not hostname:
        hostname = (netdisco_device.get("dns") or "").strip()
    if not hostname:
        # Generate hostname from vendor, model, and IP
        vendor = (netdisco_device.get("vendor") or "unknown").lower().replace(" ", "-")
        model = (netdisco_device.get("model") or "device").lower().replace(" ", "-")
        ip = (netdisco_device.get("ip") or "").replace(".", "-")
        hostname = f"{vendor}-{model}-{ip}"
    
    # Generate source identifier from MAC or IP for tracking
    # This will be used to find existing assets from NetDisco
    mac_address = (netdisco_device.get("mac") or "").strip()
    ip_address = (netdisco_device.get("ip") or "").strip()
    
    if mac_address:
        # Use MAC address as source identifier (normalized)
        source_id = f"netdisco-mac-{mac_address.replace(':', '').lower()}"
    elif ip_address:
        # Use IP address as source identifier
        source_id = f"netdisco-ip-{ip_address.replace('.', '-')}"
    else:
        # Fallback to hostname-based ID
        source_id = f"netdisco-hostname-{hostname}"
    
    # Format timestamps
    first_seen = format_netdisco_timestamp(netdisco_device.get("first_seen_stamp"))
    last_seen = format_netdisco_timestamp(netdisco_device.get("last_discover_stamp"))
    
    # Combine OS and version for firmware_version
    os_name = netdisco_device.get("os") or ""
    os_version = netdisco_device.get("os_ver") or ""
    firmware_version = f"{os_name} {os_version}".strip() if os_name or os_version else None
    
    # Build notes from contact and other metadata
    notes_parts = []
    contact = netdisco_device.get("contact")
    if contact:
        notes_parts.append(f"Contact: {contact}")
    snmp_class = netdisco_device.get("snmp_class")
    if snmp_class:
        notes_parts.append(f"SNMP Class: {snmp_class}")
    chassis_id = netdisco_device.get("chassis_id")
    if chassis_id:
        notes_parts.append(f"Chassis ID: {chassis_id}")
    notes = " | ".join(notes_parts) if notes_parts else None
    
    # Map to DAVE asset format
    # Note: asset_id is NOT included - let DAVE API generate UUID
    # We use 'source' field to track NetDisco origin
    dave_asset = {
        "source": source_id,  # NetDisco identifier for tracking
        "hostname": hostname,
        "ip_address": ip_address or "0.0.0.0",
        "mac_address": mac_address,
        "asset_type": "Switch",  # NetDisco discovers network infrastructure - use 'Switch' as valid asset_type
        "manufacturer": netdisco_device.get("vendor"),
        "model": netdisco_device.get("model"),
        "serial_number": netdisco_device.get("serial"),
        "description": netdisco_device.get("description"),
        "location": netdisco_device.get("location"),
        "status": status,
        "firmware_version": firmware_version,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "os_version": netdisco_device.get("os"),
        "notes": notes,
        "criticality": "Non-Essential",  # Default criticality
    }
    
    # Remove None values
    dave_asset = {k: v for k, v in dave_asset.items() if v is not None and v != ""}
    
    return dave_asset


#####################################################################################################################
def format_netdisco_timestamp(timestamp_str: Optional[str]) -> Optional[str]:
    """
    Format NetDisco timestamp string for DAVE API compatibility.
    
    NetDisco timestamps are in format: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD HH:MM:SS.microseconds"
    
    Args:
        timestamp_str: Timestamp string from NetDisco
        
    Returns:
        str: ISO formatted datetime string for DAVE
    """
    if not timestamp_str:
        return None
    
    try:
        # NetDisco format: "2026-02-26 17:20" or "2026-02-26 17:20:43.87851"
        if isinstance(timestamp_str, str):
            # Try parsing with microseconds first
            try:
                parsed_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    # Try parsing without seconds
                    parsed_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M")
                except ValueError:
                    # Try parsing with seconds but no microseconds
                    parsed_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            return parsed_dt.isoformat()
        
        return str(timestamp_str)
    except Exception as e:
        logger.warning(f"Could not parse NetDisco timestamp '{timestamp_str}': {e}")
        return None


#####################################################################################################################
def check_asset_exists_by_source(dave_endpoint: str, headers: Dict[str, str], source_id: str) -> Optional[Dict[str, Any]]:
    """
    Check if an asset exists in DAVE by searching for the source identifier.
    
    Since the API search may not properly filter by source field, we fetch
    all assets and filter in Python.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        source_id: Source identifier to search for (from NetDisco)
        
    Returns:
        dict or None: Asset data if exists, None if not found
    """
    # Get all assets (or at least a large batch)
    url = f"{dave_endpoint}/assets"
    params = {
        "limit": 1000  # Get a large batch to search through
    }
    
    try:
        response = requests.get(url+"/search/device", params=params, headers=headers)
        if response.status_code == 200:
            result = response.json()
            assets = result.get("data", [])
            
            # Filter assets by source field in Python
            for asset in assets:
                if asset.get("source") == source_id:
                    logger.debug(f"Found existing asset with source '{source_id}': {asset.get('asset_id')}")
                    return asset
            
            logger.debug(f"No existing asset found with source '{source_id}'")
            return None
        else:
            logger.warning(f"Unexpected response when searching for assets: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error checking if asset with source {source_id} exists: {e}")
        return None


#####################################################################################################################
def create_asset_in_dave(dave_endpoint: str, headers: Dict[str, str], asset_data: Dict[str, Any]) -> Optional[str]:
    """
    Create a new asset in DAVE using the POST /assets endpoint.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        asset_data: Asset data to create (should NOT include asset_id)
        
    Returns:
        str or None: Generated asset_id if successful, None otherwise
    """
    url = f"{dave_endpoint}/assets/"
    
    # Prepare the asset data with required fields for DAVE POST API
    current_time = datetime.now().isoformat()
    
    create_payload = {
        # asset_id is NOT included - let DAVE generate UUID
        "source": asset_data.get("source"),  # NetDisco identifier
        "hostname": asset_data.get("hostname", ""),
        "ip_address": asset_data.get("ip_address"),
        "mac_address": asset_data.get("mac_address"),
        "asset_type": asset_data.get("asset_type", "Switch"),  # Default to Switch for network devices
        "manufacturer": asset_data.get("manufacturer"),
        "model": asset_data.get("model"),
        "serial_number": asset_data.get("serial_number"),
        "description": asset_data.get("description"),
        "location": asset_data.get("location", ""),
        "criticality": asset_data.get("criticality", "Non-Essential"),
        "status": asset_data.get("status", "Active"),
        "firmware_version": asset_data.get("firmware_version"),
        "os_version": asset_data.get("os_version"),
        "notes": asset_data.get("notes"),
        "first_seen": asset_data.get("first_seen", current_time),
        "last_seen": asset_data.get("last_seen", current_time),
        "created_at": current_time,
        "updated_at": current_time
    }
    
    # Remove None values
    create_payload = {k: v for k, v in create_payload.items() if v is not None}
    
    try:
        logger.debug(f"Creating asset with payload: {json.dumps(create_payload, indent=2)}")
        response = requests.post(url, json=create_payload, headers=headers)
        if response.status_code in [200, 201]:
            result = response.json()
            generated_asset_id = result.get("data", {}).get("asset_id")
            logger.info(f"Successfully created asset with ID {generated_asset_id} and source {asset_data.get('source')}")
            return generated_asset_id
        else:
            logger.error(f"Failed to create asset with source {asset_data.get('source', 'unknown')}: {response.status_code} - {response.text}")
            logger.error(f"Payload sent: {json.dumps(create_payload, indent=2)}")
            return None
    except Exception as e:
        logger.error(f"Error creating asset with source {asset_data.get('source', 'unknown')}: {e}")
        return None


#####################################################################################################################
def update_asset_in_dave(dave_endpoint: str, headers: Dict[str, str], asset_id: str, asset_data: Dict[str, Any]) -> bool:
    """
    Update an existing asset in DAVE.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        asset_id: Asset ID to update
        asset_data: Asset data to update
        
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{dave_endpoint}/assets/{asset_id}"
    
    # Remove asset_id from the update payload as it's in the URL
    # Also remove source field from update - it should not be changed
    update_payload = {k: v for k, v in asset_data.items() if k not in ["asset_id", "source"]}
    
    # Add updated_at timestamp
    update_payload["updated_at"] = datetime.now().isoformat()
    
    try:
        logger.debug(f"Updating asset {asset_id} with payload: {json.dumps(update_payload, indent=2)}")
        response = requests.put(url, json=update_payload, headers=headers)
        if response.status_code == 200:
            logger.info(f"Successfully updated asset {asset_id} (source: {asset_data.get('source')})")
            return True
        else:
            logger.error(f"Failed to update asset {asset_id}: {response.status_code} - {response.text}")
            logger.error(f"Update payload sent: {json.dumps(update_payload, indent=2)}")
            return False
    except Exception as e:
        logger.error(f"Error updating asset {asset_id}: {e}")
        return False


#####################################################################################################################
def ingest_netdisco_assets_into_dave():
    """
    Ingest NetDisco devices into DAVE system as assets.
    
    This function:
    1. Fetches all devices from NetDisco API
    2. Maps NetDisco device data to DAVE asset format
    3. Creates or updates assets in DAVE
    
    Asset Management Strategy:
    - Does NOT generate asset_id (lets DAVE API generate UUID)
    - Uses 'source' field with NetDisco identifier (MAC or IP based) for tracking
    - Searches for existing assets by 'source' field
    - Updates existing assets or creates new ones
    
    Field Mapping Summary:
    - IP Address, MAC Address, Hostname/Name
    - Vendor/Manufacturer, Model, Serial Number
    - OS Version, Firmware Version
    - Location, Description
    - First Seen, Last Seen timestamps
    - Status based on uptime
    - Source identifier for NetDisco tracking
    """
    # DAVE API configuration
    dave_endpoint = os.getenv("DAVE_API_URL", "http://localhost/api") + "/v1"
    dave_api_key = os.getenv("DAVE_INTEGRATION_API_KEY")

    if not dave_api_key:
        logger.error("DAVE_INTEGRATION_API_KEY must be set in .env file")
        logger.info("Please copy .env.sample to .env and configure your DAVE API credentials")
        return
    
    dave_headers = {
        "X-API-Key": f"{dave_api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        # Fetch all devices from NetDisco
        logger.info("Fetching devices from NetDisco...")
        netdisco_devices = fetch_netdisco_devices()
        
        logger.info(f"Retrieved {len(netdisco_devices)} devices from NetDisco")
        
        if not netdisco_devices:
            logger.warning("No devices found in NetDisco")
            return
        
        # Process each device
        successful_updates = 0
        successful_creations = 0
        errors = 0
        
        for device in netdisco_devices:
            try:
                logger.debug(f"Processing device: {json.dumps(device, indent=2)}")
                
                # Map NetDisco device to DAVE format
                dave_asset = map_netdisco_to_dave_asset(device)
                
                logger.debug(f"Mapped to DAVE asset: {json.dumps(dave_asset, indent=2)}")
                
                # Validate required fields
                source_id = dave_asset.get("source")
                if not source_id:
                    logger.warning(f"Skipping device without source identifier: {device.get('ip', 'unknown')}")
                    errors += 1
                    continue
                
                logger.info(f"Processing device {device.get('ip', 'unknown')} with source: {source_id}")
                
                # Check if asset exists in DAVE (by source field)
                existing_asset = check_asset_exists_by_source(dave_endpoint, dave_headers, source_id)
                
                if existing_asset:
                    # Asset exists, update it using its asset_id
                    asset_id = existing_asset.get("asset_id")
                    logger.info(f"Found existing asset {asset_id} for source {source_id}, updating...")
                    success = update_asset_in_dave(dave_endpoint, dave_headers, asset_id, dave_asset)
                    if success:
                        successful_updates += 1
                    else:
                        errors += 1
                else:
                    # Asset doesn't exist, create it (DAVE will generate asset_id)
                    logger.info(f"No existing asset found for source {source_id}, creating new...")
                    generated_asset_id = create_asset_in_dave(dave_endpoint, dave_headers, dave_asset)
                    if generated_asset_id:
                        successful_creations += 1
                    else:
                        errors += 1
                    
            except Exception as e:
                logger.error(f"Error processing device {device.get('ip', 'unknown')}: {e}")
                logger.error(f"Device data: {json.dumps(device, indent=2)}")
                logger.exception("Full traceback:")
                errors += 1
        
        # Summary
        logger.info("=" * 80)
        logger.info("NetDisco Asset Ingestion Completed")
        logger.info("=" * 80)
        logger.info(f"Total devices processed: {len(netdisco_devices)}")
        logger.info(f"Successfully updated: {successful_updates}")
        logger.info(f"Successfully created: {successful_creations}")
        logger.info(f"Errors: {errors}")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Error during NetDisco asset ingestion: {e}", exc_info=True)


#####################################################################################################################
# Main execution
#####################################################################################################################
if __name__ == "__main__":
    logger.info("Starting NetDisco to DAVE asset ingestion...")
    ingest_netdisco_assets_into_dave()
    logger.info("NetDisco asset ingestion process completed.")
