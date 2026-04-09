"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
import sys
import requests
import json
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
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/blueflow_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Log .env file loading status
if os.path.exists(env_file_path):
    logger.info(f"Loaded environment variables from: {env_file_path}")
else:
    logger.warning(f".env file not found at: {env_file_path}")

# BlueFlow API Configuration
BLUEFLOW_API_BASE_URL = os.getenv("BLUEFLOW_API_URL")
# No authentication required for the mock API


#####################################################################################################################
def fetch_blueflow_assets() -> List[Dict[str, Any]]:
    """
    Fetch assets from BlueFlow API.
    
    BlueFlow API provides individual asset endpoints: /api/assets/1, /api/assets/2, etc.
    We fetch assets starting from ID 1 and continue until we receive a 404 response.
    Maximum limit of 10000 assets to prevent infinite loops.
    
    Returns:
        list: List of all assets from BlueFlow
    
    Raises:
        requests.HTTPError: If the API request fails
    """
    assets = []
    asset_id = 1
    max_assets = 10000
    
    logger.info(f"Fetching assets from BlueFlow API starting at ID {asset_id} (max: {max_assets})...")
    
    while asset_id <= max_assets:
        url = f"{BLUEFLOW_API_BASE_URL}/assets/{asset_id}"
        
        try:
            logger.info(f"Fetching asset {asset_id} from: {url}")
            response = requests.get(url, timeout=30)
            
            # Stop if we get a 404 - no more assets
            if response.status_code == 404:
                logger.info(f"Received 404 for asset {asset_id}, stopping fetch")
                break
            
            response.raise_for_status()
            
            asset = response.json()
            assets.append(asset)
            logger.info(f"Successfully fetched asset {asset_id}: {asset.get('name', 'Unknown')}")
            
            # Move to next asset
            asset_id += 1
            
        except requests.exceptions.RequestException as e:
            # Check if it's a 404 error
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                logger.info(f"Received 404 for asset {asset_id}, stopping fetch")
                break
            
            logger.error(f"Error fetching asset {asset_id} from BlueFlow: {e}")
            # For other errors, continue with next asset
            asset_id += 1
            continue
    
    if asset_id > max_assets:
        logger.warning(f"Reached maximum asset limit of {max_assets}, stopping fetch")
    
    logger.info(f"Successfully fetched {len(assets)} assets from BlueFlow")
    return assets


#####################################################################################################################
def map_blueflow_to_dave_asset(blueflow_asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a BlueFlow asset to DAVE asset format.
    
    IMPORTANT: This function does NOT generate asset_id. The DAVE API will generate
    a UUID for asset_id. Instead, we use the 'source' field with BlueFlow asset ID
    to track which assets came from BlueFlow and enable updates on subsequent runs.
    
    BlueFlow Field Mapping:
    -----------------------
    BlueFlow Field          DAVE Field              Type            Notes
    -------------------------------------------------------------------------------
    id                      source                  string          BlueFlow asset ID (as "blueflow-{id}")
    name                    hostname                string          Asset name/hostname
    hostname                hostname (fallback)     string          If name is empty
    ip_address              ip_address              string          IPv4 address
    mac_address             mac_address             string          MAC address
    manufacturer            manufacturer            string          Device manufacturer
    model                   model                   string          Device model
    serial_number           serial_number           string          Device serial number
    category                asset_type              string          Asset category -> mapped to valid type
    os                      os_version              string          Operating system
    app_sw_version          firmware_version        string          Application/software version
    owner                   department              string          Owner/department
    location                location                string          Physical location (formatted)
    status                  status                  string          Asset status
    date_added              first_seen              datetime        First seen timestamp
    last_updated            last_seen               datetime        Last seen timestamp
    cpe                     notes                   string          CPE string in notes
    network_segment         notes                   string          Network segment in notes
    
    Category Mapping to Asset Type:
    - CT Scanner, MRI Scanner, X-Ray -> Medical Device
    - Switch, Router, Firewall -> Switch
    - Server -> Server
    - Laptop, Workstation -> Laptop
    - Default -> Medical Device (healthcare context)
    
    Args:
        blueflow_asset: Asset data from BlueFlow API
        
    Returns:
        dict: Asset data formatted for DAVE API
    """
    
    # Generate source identifier from BlueFlow asset ID
    blueflow_id = blueflow_asset.get("id")
    source_id = f"blueflow-{blueflow_id}"
    
    # Get hostname - prioritize 'hostname', fallback to 'name'
    hostname = blueflow_asset.get("hostname", "").strip()
    if not hostname:
        hostname = blueflow_asset.get("name", "").strip()
    if not hostname:
        hostname = f"blueflow-asset-{blueflow_id}"
    
    # Map category to valid asset_type
    category = blueflow_asset.get("category", "").lower()
    asset_type_mapping = {
        "ct scanner": "Medical Device",
        "mri scanner": "Medical Device",
        "x-ray": "Medical Device",
        "ultrasound": "Medical Device",
        "ventilator": "Medical Device",
        "infusion pump": "Medical Device",
        "patient monitor": "Medical Device",
        "switch": "Switch",
        "router": "Switch",
        "firewall": "Switch",
        "server": "Server",
        "laptop": "Laptop",
        "workstation": "Laptop",
        "desktop": "Laptop",
    }
    
    # Find matching asset type or default to Medical Device (healthcare context)
    asset_type = "Medical Device"  # Default for healthcare
    for key, value in asset_type_mapping.items():
        if key in category:
            asset_type = value
            break
    
    # Format location from nested location object
    location_obj = blueflow_asset.get("location", {})
    if location_obj and isinstance(location_obj, dict):
        location_parts = []
        if location_obj.get("facility"):
            location_parts.append(location_obj.get("facility"))
        if location_obj.get("building"):
            location_parts.append(location_obj.get("building"))
        if location_obj.get("floor"):
            location_parts.append(f"Floor {location_obj.get('floor')}")
        if location_obj.get("room"):
            location_parts.append(f"Room {location_obj.get('room')}")
        location = " | ".join(location_parts) if location_parts else None
    else:
        location = None
    
    # Format timestamps
    first_seen = format_blueflow_timestamp(blueflow_asset.get("date_added"))
    last_seen = format_blueflow_timestamp(blueflow_asset.get("last_updated"))
    
    # Build notes from CPE and network segment
    notes_parts = []
    cpe = blueflow_asset.get("cpe")
    if cpe:
        notes_parts.append(f"CPE: {cpe}")
    network_segment = blueflow_asset.get("network_segment")
    if network_segment:
        notes_parts.append(f"Network: {network_segment}")
    owner = blueflow_asset.get("owner")
    if owner:
        notes_parts.append(f"Owner: {owner}")
    notes = " | ".join(notes_parts) if notes_parts else None
    
    # Map risk scores to criticality
    # Valid values: 'Clinical-High', 'Business-Medium', 'Non-Essential'
    risk_score = blueflow_asset.get("risk_score", 0)
    if risk_score >= 7:
        criticality = "Clinical-High"
    elif risk_score >= 4:
        criticality = "Business-Medium"
    else:
        criticality = "Non-Essential"
    
    # Map to DAVE asset format
    # Note: asset_id is NOT included - let DAVE API generate UUID
    # We use 'source' field to track BlueFlow origin
    dave_asset = {
        "source": source_id,  # BlueFlow identifier for tracking
        "hostname": hostname,
        "ip_address": blueflow_asset.get("ip_address") or "0.0.0.0",
        "mac_address": blueflow_asset.get("mac_address"),
        "asset_type": asset_type,
        "manufacturer": blueflow_asset.get("manufacturer"),
        "model": blueflow_asset.get("model"),
        "serial_number": blueflow_asset.get("serial_number"),
        "udi": blueflow_asset.get("udi"),
        "location": location,
        "status": blueflow_asset.get("status", "Active"),
        "firmware_version": blueflow_asset.get("app_sw_version"),
        "os_version": blueflow_asset.get("os"),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "notes": notes,
        "criticality": criticality,
        "department": owner,
    }
    
    # Remove None values and empty strings
    dave_asset = {k: v for k, v in dave_asset.items() if v is not None and v != ""}
    
    return dave_asset


#####################################################################################################################
def format_blueflow_timestamp(timestamp_str: Optional[str]) -> Optional[str]:
    """
    Format BlueFlow timestamp string for DAVE API compatibility.
    
    BlueFlow timestamps are in ISO format: "2024-06-03T09:17:54.263534Z"
    
    Args:
        timestamp_str: Timestamp string from BlueFlow
        
    Returns:
        str: ISO formatted datetime string for DAVE
    """
    if not timestamp_str:
        return None
    
    try:
        # BlueFlow uses ISO format with Z suffix
        if isinstance(timestamp_str, str):
            # Parse ISO format and convert to DAVE format
            parsed_dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return parsed_dt.isoformat()
        
        return str(timestamp_str)
    except Exception as e:
        logger.warning(f"Could not parse BlueFlow timestamp '{timestamp_str}': {e}")
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
        source_id: Source identifier to search for (from BlueFlow)
        
    Returns:
        dict or None: Asset data if exists, None if not found
    """
    # Get all assets (or at least a large batch)
    url = f"{dave_endpoint}/assets"
    params = {
        "limit": 1000  # Get a large batch to search through
    }
    
    try:
        response = requests.get(url, params=params, headers=headers)
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
        "source": asset_data.get("source"),  # BlueFlow identifier
        "hostname": asset_data.get("hostname", ""),
        "ip_address": asset_data.get("ip_address"),
        "mac_address": asset_data.get("mac_address"),
        "asset_type": asset_data.get("asset_type", "Medical Device"),
        "manufacturer": asset_data.get("manufacturer"),
        "model": asset_data.get("model"),
        "serial_number": asset_data.get("serial_number"),
        "udi": asset_data.get("udi"),
        "location": asset_data.get("location", ""),
        "criticality": asset_data.get("criticality", "Non-Essential"),
        "status": asset_data.get("status", "Active"),
        "firmware_version": asset_data.get("firmware_version"),
        "os_version": asset_data.get("os_version"),
        "notes": asset_data.get("notes"),
        "department": asset_data.get("department"),
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
def ingest_blueflow_assets_into_dave():
    """
    Ingest BlueFlow assets into DAVE system.
    
    This function:
    1. Fetches assets 1-5 from BlueFlow API
    2. Maps BlueFlow asset data to DAVE asset format
    3. Creates or updates assets in DAVE
    
    Asset Management Strategy:
    - Does NOT generate asset_id (lets DAVE API generate UUID)
    - Uses 'source' field with BlueFlow asset ID (e.g., "blueflow-1") for tracking
    - Searches for existing assets by 'source' field
    - Updates existing assets or creates new ones
    
    Field Mapping Summary:
    - ID -> Source identifier
    - IP Address, MAC Address, Hostname/Name
    - Manufacturer, Model, Serial Number, UDI
    - OS Version, Firmware/Software Version
    - Location (formatted from nested object), Owner/Department
    - Risk Score -> Criticality mapping (Clinical-High, Business-Medium, Non-Essential)
    - First Seen, Last Seen timestamps
    - Status, CPE, Network Segment
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
        # Fetch assets from BlueFlow
        logger.info("Fetching assets from BlueFlow...")
        blueflow_assets = fetch_blueflow_assets()
        
        logger.info(f"Retrieved {len(blueflow_assets)} assets from BlueFlow")
        
        if not blueflow_assets:
            logger.warning("No assets found in BlueFlow")
            return
        
        # Process each asset
        successful_updates = 0
        successful_creations = 0
        errors = 0
        
        for asset in blueflow_assets:
            try:
                blueflow_id = asset.get("id", "unknown")
                asset_name = asset.get("name", "Unknown")
                
                logger.info(f"Processing BlueFlow asset {blueflow_id}: {asset_name}")
                
                # Map BlueFlow asset to DAVE format
                dave_asset = map_blueflow_to_dave_asset(asset)
                
                logger.debug(f"Mapped to DAVE asset: {json.dumps(dave_asset, indent=2)}")
                
                # Validate required fields
                source_id = dave_asset.get("source")
                if not source_id:
                    logger.warning(f"Skipping asset without source identifier: {blueflow_id}")
                    errors += 1
                    continue
                
                logger.info(f"Processing BlueFlow asset {blueflow_id} with source: {source_id}")
                
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
                logger.error(f"Error processing BlueFlow asset {asset.get('id', 'unknown')}: {e}")
                logger.exception("Full traceback:")
                errors += 1
        
        # Summary
        logger.info("=" * 80)
        logger.info("BlueFlow Asset Ingestion Completed")
        logger.info("=" * 80)
        logger.info(f"Total assets processed: {len(blueflow_assets)}")
        logger.info(f"Successfully updated: {successful_updates}")
        logger.info(f"Successfully created: {successful_creations}")
        logger.info(f"Errors: {errors}")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Error during BlueFlow asset ingestion: {e}", exc_info=True)


#####################################################################################################################
# Main execution
#####################################################################################################################
if __name__ == "__main__":
    logger.info("Starting BlueFlow to DAVE asset ingestion...")
    ingest_blueflow_assets_into_dave()
    logger.info("BlueFlow asset ingestion process completed.")
