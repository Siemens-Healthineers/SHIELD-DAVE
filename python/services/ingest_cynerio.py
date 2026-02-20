"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
import sys
import requests
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from email.utils import parsedate_to_datetime
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
        logging.FileHandler('/var/www/html/logs/cynerio_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Log .env file loading status
if os.path.exists(env_file_path):
    logger.info(f"Loaded environment variables from: {env_file_path}")
else:
    logger.warning(f".env file not found at: {env_file_path}")

# Configuration from environment variables
client_id = os.getenv("CYNERIO_CLIENT_ID")
client_secret = os.getenv("CYNERIO_CLIENT_SECRET")
endpoint = os.getenv("CYNERIO_ENDPOINT", "https://us.app.cynerio.com")
auth_endpoint = os.getenv("CYNERIO_AUTH_ENDPOINT", "https://us-portal-login.cynerio.com")

# Validate required environment variables
if not client_id or not client_secret:
    raise ValueError("CLIENT_ID and CLIENT_SECRET must be set in .env file")

#####################################################################################################################
def get_token() -> Dict[str, Any]:
    """
    Authenticate using client_id and secret to get access token and refresh token.
    
    Returns:
        dict: Response containing accessToken, refreshToken, expires, and expires_in
    
    Raises:
        requests.HTTPError: If the authentication request fails
    """
    url = f"{auth_endpoint}/identity/resources/auth/v1/api-token"
    
    payload = {
        "clientId": client_id,
        "secret": client_secret
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    logger.info("Requesting new access token...")
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    
    logger.info("Successfully obtained new access token")

    data = response.json()
    return data["accessToken"]


#####################################################################################################################
def fetch_assets(
    endpoint: str,
    headers: Dict[str, str],
    page: int = 1,
    per_page: int = 100,
    filters: Optional[Dict[str, Any]] = None,
    sort_by: Optional[str] = None,
    sort_order: str = "asc"
) -> Dict[str, Any]:
    """
    Fetch assets from Cynerio API.
    
    Args:
        endpoint: Base API endpoint URL
        headers: Authorization headers
        page: Page number (default: 1)
        per_page: Number of items per page (default: 100)
        filters: Optional filters to apply
        sort_by: Optional field to sort by
        sort_order: Sort order 'asc' or 'desc' (default: 'asc')
    
    Returns:
        dict: Assets data response
    """
    url = f"{endpoint}/outbound-integrations/integration/v1/assets"
    
    payload = {
        "page": page,
        "per_page": per_page
    }
    
    if filters:
        payload["filters"] = filters
    
    if sort_by:
        payload["sort"] = {
            "by": sort_by,
            "order": sort_order
        }
    
    logger.info(f"Fetching assets (page {page}, per_page {per_page})...")
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    
    data = response.json()
    logger.info(f"Successfully fetched {len(data.get('items', []))} assets")
    
    return data

#####################################################################################################################
def fetch_all_assets(
    endpoint: str,
    headers: Dict[str, str],
    filters: Optional[Dict[str, Any]] = None,
    sort_by: Optional[str] = None,
    sort_order: str = "asc",
    max_pages: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Fetch all assets across multiple pages.
    
    Args:
        endpoint: Base API endpoint URL
        headers: Authorization headers
        filters: Optional filters to apply
        sort_by: Optional field to sort by
        sort_order: Sort order 'asc' or 'desc' (default: 'asc')
        max_pages: Maximum number of pages to fetch (None for all)
    
    Returns:
        list: List of all assets
    """
    all_assets = []
    page = 1
    
    while True:
        if max_pages and page > max_pages:
            break
        
        response = fetch_assets(
            endpoint=endpoint,
            headers=headers,
            page=page,
            per_page=100,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        items = response.get("items", [])
        all_assets.extend(items)
        
        # Check if there are more pages
        total_pages = response.get("total_pages", 1)
        if page >= total_pages:
            break
        
        page += 1
    
    logger.info(f"Fetched total of {len(all_assets)} assets across {page} pages")
    return all_assets
        
#####################################################################################################################

def fetch_risks(
    endpoint: str,
    headers: Dict[str, str],
    page: int = 1,
    per_page: int = 100,
    cursor: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Fetch risks from Cynerio API.
    
    Args:
        endpoint: Base API endpoint URL
        headers: Authorization headers
        page: Page number (default: 1)
        per_page: Number of items per page (default: 100)
        cursor: Cursor for pagination - use instead of page for faster pagination
        filters: Optional filters to apply (e.g., asset_id)
    
    Returns:
        dict: Risks data response
        
    Example filters:
        {
            "asset_id": "01c35ck9-bv07-4811-9602-62f729609890"
        }
    """
    url = f"{endpoint}/outbound-integrations/integration/v1/risks"
    
    payload = {
        "per_page": per_page
    }
    
    # Use cursor for pagination if provided, otherwise use page
    if cursor:
        payload["cursor"] = cursor
    else:
        payload["page"] = page
    
    if filters:
        payload["filters"] = filters
    
    logger.info(f"Fetching risks (page {page}, per_page {per_page})...")
    if cursor:
        logger.info(f"Using cursor: {cursor}")
    
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    
    data = response.json()
    items_count = len(data.get('items', []))
    total_count = data.get('total', 0)
    
    logger.info(f"Successfully fetched {items_count} risks (total: {total_count})")
    
    return data

#####################################################################################################################

def fetch_all_risks(
    endpoint: str,
    headers: Dict[str, str],
    filters: Optional[Dict[str, Any]] = None,
    max_pages: Optional[int] = None,
    use_cursor: bool = True
) -> List[Dict[str, Any]]:
    """
    Fetch all risks across multiple pages.
    
    Args:
        endpoint: Base API endpoint URL
        headers: Authorization headers
        filters: Optional filters to apply
        max_pages: Maximum number of pages to fetch (None for all)
        use_cursor: Whether to use cursor-based pagination for better performance
    
    Returns:
        list: List of all risks
    """
    all_risks = []
    page = 1
    cursor = None
    
    while True:
        if max_pages and page > max_pages:
            break
        
        response = fetch_risks(
            endpoint=endpoint,
            headers=headers,
            page=page,
            per_page=100,
            cursor=cursor if use_cursor else None,
            filters=filters
        )
        
        items = response.get("items", [])
        all_risks.extend(items)
        
        # Get next cursor for pagination
        if use_cursor:
            cursor = response.get("next_cursor")
            if not cursor:  # No more pages
                break
        else:
            # Check if there are more pages using traditional pagination
            current_page = response.get("page", 1)
            total_pages = response.get("pages", 1)
            if current_page >= total_pages:
                break
        
        page += 1
    
    logger.info(f"Fetched total of {len(all_risks)} risks across {page} pages")
    return all_risks

#####################################################################################################################


def fetch_risks_by_asset(
    endpoint: str,
    headers: Dict[str, str],
    asset_id: str,
    max_pages: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Fetch all risks for a specific asset.
    
    Args:
        endpoint: Base API endpoint URL
        headers: Authorization headers
        asset_id: The asset ID to filter risks by
        max_pages: Maximum number of pages to fetch (None for all)
    
    Returns:
        list: List of risks for the specified asset
    """
    filters = {"asset_id": asset_id}
    
    logger.info(f"Fetching risks for asset: {asset_id}")
    risks = fetch_all_risks(
        endpoint=endpoint,
        headers=headers,
        filters=filters,
        max_pages=max_pages
    )
    
    return risks

#####################################################################################################################

def ingest_cynerio_assets_into_dave():
    """
    Ingest Cynerio assets into  system.
    
    Fields to map:
    
    Cynerio Field       Type      Field          Type              Mapping Status  Notes
    ------------------------------------------------------------------------------------------
    id                  string   asset_id            string (uuid)     Direct          Both serve as unique asset identifiers
    status              string   status              string            Direct          Asset operational status (Active/Offline mapped to Active/Inactive/Maintenance/Retired)
    vendor              string   manufacturer        string            Direct          Device manufacturer/vendor
    model               string   model               string            Direct          Device model information
    ip                  string   ip_address          string (ipv4)     Direct          IPv4 address
    mac                 string   mac_address         string            Direct          MAC address
    serial_number       string   serial_number       string            Direct          Device serial number
    department          string   department          string            Direct          Department assignment
    firmware_version    string   firmware_version    string            Direct          Firmware version
    first_seen          string   first_seen          string (datetime) Direct          First discovery timestamp (Maybe format conversion needed)
    last_seen           string   last_seen           string (datetime) Direct          Last seen timestamp (Maybe format conversion needed)
    """
    #  API configuration - update these values as needed
    dave_endpoint = os.getenv("DAVE_API_URL", "http://localhost/api") + "/v1"
    dave_api_key = os.getenv("DAVE_INTEGRATION_API_KEY")

    if not dave_api_key:
        logger.error("DAVE_API_KEY must be set in .env file")
        logger.info("Please copy .env.sample to .env and configure your DAVE API credentials")
        return
    
    dave_headers = {
        "X-API-Key": f"{dave_api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        # Get Cynerio access token
        token = get_token()
        cynerio_headers = {
            "Authorization": f"Bearer {token}"
        }
        
        # Fetch all assets from Cynerio
        logger.info("Fetching assets from Cynerio...")
        cynerio_assets = fetch_all_assets(
            endpoint=endpoint,
            headers=cynerio_headers
        )
        
        logger.info(f"Retrieved {len(cynerio_assets)} assets from Cynerio")
        
        if not cynerio_assets:
            logger.warning("No assets found in Cynerio")
            return
        
        # Process each asset
        successful_updates = 0
        successful_creations = 0
        errors = 0
        assets_to_create = []
        
        for asset in cynerio_assets:
            try:
                # Map Cynerio asset to  format
                dave_asset = map_cynerio_to_dave_asset(asset)
                
                # Validate required fields
                if not dave_asset.get("asset_id"):
                    logger.warning(f"Skipping asset without ID: {asset}")
                    errors += 1
                    continue
                
                # Check if asset exists in 
                asset_id = dave_asset["asset_id"]
                existing_asset = check_asset_exists_in_dave(dave_endpoint, dave_headers, asset_id)
                
                if existing_asset:
                    # Asset exists, update it
                    success = update_asset_in_dave(dave_endpoint, dave_headers, asset_id, dave_asset)
                    if success:
                        successful_updates += 1
                        logger.info(f"Updated asset {asset_id} in ")
                    else:
                        errors += 1
                else:
                    # Asset doesn't exist - collect for potential bulk creation
                    assets_to_create.append(dave_asset)
                    logger.info(f"Asset {asset_id} marked for creation")
                    
            except Exception as e:
                logger.error(f"Error processing asset {asset.get('id', 'unknown')}: {e}")
                errors += 1
        
        # Handle assets that need to be created
        if assets_to_create:
            logger.info(f"Creating {len(assets_to_create)} new assets in ...")
            
            for asset in assets_to_create:
                try:
                    success = create_asset_in_dave(dave_endpoint, dave_headers, asset)
                    if success:
                        successful_creations += 1
                        logger.info(f"Created asset {asset.get('asset_id')} in ")
                    else:
                        errors += 1
                except Exception as e:
                    logger.error(f"Error creating asset {asset.get('asset_id', 'unknown')}: {e}")
                    errors += 1
        
        logger.info(f"Asset ingestion completed:")
        logger.info(f"  - Successfully updated: {successful_updates}")
        logger.info(f"  - Successfully created: {successful_creations}")
        logger.info(f"  - Errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error during asset ingestion: {e}")


def create_asset_in_dave(dave_endpoint: str, headers: Dict[str, str], asset_data: Dict[str, Any]) -> bool:
    """
    Create a new asset in  using the POST /assets endpoint.
    
    Args:
        dave_endpoint:  API base URL
        headers: Authorization headers for 
        asset_data: Asset data to create
        
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{dave_endpoint}/assets/"
    
    # Prepare the asset data with required fields for  POST API
    current_time = datetime.now().isoformat()
    
    create_payload = {
        "asset_id": asset_data.get("asset_id"),
        "hostname": asset_data.get("hostname", ""),
        "ip_address": asset_data.get("ip_address"),
        "mac_address": asset_data.get("mac_address"),
        "asset_type": asset_data.get("asset_type", "Medical Device"),  # Default type
        "manufacturer": asset_data.get("manufacturer"),
        "model": asset_data.get("model"),
        "serial_number": asset_data.get("serial_number"),
        "department": asset_data.get("department"),
        "location": asset_data.get("location", ""),  # Default empty if not provided
        "criticality": asset_data.get("criticality", "Non-Essential"),  # Default criticality
        "status": asset_data.get("status", "Active"),  # Default status
        "firmware_version": asset_data.get("firmware_version"),
        "first_seen": asset_data.get("first_seen", current_time),
        "last_seen": asset_data.get("last_seen", current_time),
        "created_at": current_time,
        "updated_at": current_time
    }
    
    # Remove None values
    create_payload = {k: v for k, v in create_payload.items() if v is not None}
    
    try:
        response = requests.post(url, json=create_payload, headers=headers)
        print(response.status_code)
        if response.status_code in [200, 201]:
            return True
        else:
            logger.error(f"Failed to create asset {asset_data.get('asset_id', 'unknown')}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error creating asset {asset_data.get('asset_id', 'unknown')}: {e}")
        return False


def map_cynerio_to_dave_asset(cynerio_asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a Cynerio asset to  format based on the field mapping.
    
    Args:
        cynerio_asset: Asset data from Cynerio API
        
    Returns:
        dict: Asset data formatted for  API
    """
    # Map status values
    status_mapping = {
        "Active": "Active",
        "Offline": "Inactive",
        "Inactive": "Inactive"
    }
    
    cynerio_status = cynerio_asset.get("status", "")
    dave_status = status_mapping.get(cynerio_status, "Inactive")
    
    # Generate hostname if not available
    hostname = cynerio_asset.get("hostname", "")
    if not hostname and cynerio_asset.get("id"):
        # Generate hostname from manufacturer, model, and last 4 chars of asset_id
        asset_id_suffix = cynerio_asset.get("id", "")[-4:] if cynerio_asset.get("id") else "0000"
        manufacturer = cynerio_asset.get("vendor", "unknown").lower().replace(" ", "-")
        model = cynerio_asset.get("model", "device").lower().replace(" ", "-")
        hostname = f"{manufacturer}-{model}-{asset_id_suffix}"
    
    # Basic required fields mapping for  POST API
    dave_asset = {
        "asset_id": cynerio_asset.get("id"),
        "hostname": hostname,
        "ip_address": cynerio_asset.get("ip") or "0.0.0.0",
        "mac_address": cynerio_asset.get("mac"),
        "asset_type": "Medical Device",  # Default type for medical devices
        "manufacturer": cynerio_asset.get("vendor"),
        "model": cynerio_asset.get("model"),
        "serial_number": cynerio_asset.get("serial_number"),
        "department": cynerio_asset.get("department"),
        "location": cynerio_asset.get("location", ""),  # Default empty
        "criticality": "Non-Essential",  # Default criticality, could be enhanced based on device type
        "status": dave_status,
        "firmware_version": cynerio_asset.get("firmware_version"),
        "first_seen": format_datetime_for_dave(cynerio_asset.get("first_seen")),
        "last_seen": format_datetime_for_dave(cynerio_asset.get("last_seen"))
    }
    
    # Remove None values
    dave_asset = {k: v for k, v in dave_asset.items() if v is not None}
    
    return dave_asset


def format_datetime_for_dave(datetime_str: Optional[str]) -> Optional[str]:
    """
    Format datetime string for  API compatibility.
    
    Args:
        datetime_str: Datetime string from Cynerio
        
    Returns:
        str: Formatted datetime string for 
    """
    if not datetime_str:
        return None
    
    try:
        # Parse the datetime and ensure it's in ISO format
        if isinstance(datetime_str, str):
            # Try to parse and reformat to ensure consistency
            parsed_dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
            return parsed_dt.isoformat()
        return datetime_str
    except Exception as e:
        logger.warning(f"Could not parse datetime '{datetime_str}': {e}")
        return datetime_str


def check_asset_exists_in_dave(dave_endpoint: str, headers: Dict[str, str], asset_id: str) -> Optional[Dict[str, Any]]:
    """
    Check if an asset exists in  by attempting to retrieve it.
    
    Args:
        dave_endpoint:  API base URL
        headers: Authorization headers for 
        asset_id: Asset ID to check
        
    Returns:
        dict or None: Asset data if exists, None if not found
    """
    url = f"{dave_endpoint}/assets/{asset_id}"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("data")
        elif response.status_code == 404:
            return None
        else:
            logger.warning(f"Unexpected response when checking asset {asset_id}: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error checking if asset {asset_id} exists: {e}")
        return None


def update_asset_in_dave(dave_endpoint: str, headers: Dict[str, str], asset_id: str, asset_data: Dict[str, Any]) -> bool:
    """
    Update an existing asset in .
    
    Args:
        dave_endpoint:  API base URL
        headers: Authorization headers for 
        asset_id: Asset ID to update
        asset_data: Asset data to update
        
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{dave_endpoint}/assets/{asset_id}"
    
    # Remove asset_id from the update payload as it's in the URL
    update_payload = {k: v for k, v in asset_data.items() if k != "asset_id"}
    
    try:
        response = requests.put(url, json=update_payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            logger.error(f"Failed to update asset {asset_id}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error updating asset {asset_id}: {e}")
        return False

def create_assets_via_bulk_import(assets_to_create: List[Dict[str, Any]], dave_endpoint: str, headers: Dict[str, str]) -> bool:
    """
    Create assets in  using the bulk import endpoint.
    Note: This would require CSV format. This is a placeholder for future implementation.
    
    Args:
        assets_to_create: List of asset data to create
        dave_endpoint:  API base URL
        headers: Authorization headers for 
        
    Returns:
        bool: True if successful, False otherwise
    """
    logger.info("Bulk asset creation via CSV import not implemented yet")
    logger.info(f"Would create {len(assets_to_create)} assets via /assets/import endpoint")
    logger.info("This would require converting asset data to CSV format and uploading as multipart/form-data")
    return False


#####################################################################################################################

def ingest_cynerio_risks_into_dave():
    """
    Ingest Cynerio risks into DAVE system as risks.
    
    Field Mapping (All Cynerio fields mapped directly to DAVE fields):
    
    Cynerio Field                   DAVE Field                      Notes
    ---------------------------------------------------------------------------------
    asset_id                        asset_id                        Direct mapping
    availability_score              availability_score              Direct mapping
    category                        category                        Direct mapping
    comment                         comment                         Direct mapping
    confidentiality_score           confidentiality_score           Direct mapping
    cvss                            cvss                            Direct mapping
    description                     description                     Direct mapping
    detected_on                     detected_on                     Direct mapping
    device_class                    device_class                    Direct mapping
    display_name                    display_name                    Direct mapping
    due_date                        due_date                        Direct mapping
    epss                            epss                            Direct mapping
    has_malware                     has_malware                     Direct mapping
    id                              external_id                     Direct mapping (Cynerio risk ID)
    impact_confidentiality          impact_confidentiality          Direct mapping
    impact_patient_safety           impact_patient_safety           Direct mapping
    impact_service_disruption       impact_service_disruption       Direct mapping
    integrity_score                 integrity_score                 Direct mapping
    latest_status_update            latest_status_update            Direct mapping
    link                            link                            Direct mapping
    name                            name                            Direct mapping
    nhs_published_date              nhs_published_date              Direct mapping
    nhs_severity                    nhs_severity                    Direct mapping
    nhs_threat_id                   nhs_threat_id                   Direct mapping
    owner                           owner                           Direct mapping
    response                        response                        Direct mapping
    risk_group                      risk_group                      Direct mapping
    risk_id                         risk_id                         Direct mapping
    risk_score                      risk_score                      Direct mapping
    risk_score_level                risk_score_level                Direct mapping
    risk_type_display_name          risk_type_display_name          Direct mapping
    site                            site                            Direct mapping
    status_display_name             status_display_name             Direct mapping
    tags_easy_to_weaponize          tags_easy_to_weaponize          Direct mapping
    tags_exploit_code_maturity      tags_exploit_code_maturity      Direct mapping
    tags_exploited_in_the_wild      tags_exploited_in_the_wild      Direct mapping
    tags_lateral_movement           tags_lateral_movement           Direct mapping
    tags_malware                    tags_malware                    Direct mapping
    type                            type                            Direct mapping
    type_display_name               type_display_name               Direct mapping
    vlan                            vlan                            Direct mapping
    """

    #  API configuration - update these values as needed
    dave_endpoint = os.getenv("DAVE_API_URL", "http://localhost/api") + "/v1"
    dave_api_key = os.getenv("DAVE_INTEGRATION_API_KEY")
    
    if not dave_api_key:
        logger.error("DAVE_API_KEY must be set in .env file")
        logger.info("Please copy .env.sample to .env and configure your DAVE API credentials")
        return
    
    dave_headers = {
        "X-API-Key": f"{dave_api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        # Get Cynerio access token
        token = get_token()
        cynerio_headers = {
            "Authorization": f"Bearer {token}"
        }
        
        # Fetch all risks from Cynerio
        logger.info("Fetching risks from Cynerio...")
        cynerio_risks = fetch_all_risks(
            endpoint=endpoint,
            headers=cynerio_headers
        )
        
        logger.info(f"Retrieved {len(cynerio_risks)} risks from Cynerio")
        
        if not cynerio_risks:
            logger.warning("No risks found in Cynerio")
            return
        
        # Process each risk individually (no grouping needed since we're using all Cynerio fields)
        successful_creations = 0
        successful_updates = 0
        errors = 0
        
        for risk in cynerio_risks:
            try:
                risk_id = risk.get("id")
                if not risk_id:
                    logger.warning(f"Skipping risk without ID: {risk}")
                    errors += 1
                    continue
                
                # Map Cynerio risk to DAVE risk format (direct field mapping)
                dave_risk = map_cynerio_risk_to_dave_risk(
                    risk,
                    []  # affected_assets not used with direct mapping
                )
                
                # Validate required fields
                if not dave_risk.get("external_id"):
                    logger.warning(f"Skipping risk without external_id after mapping")
                    errors += 1
                    continue

                # Try to create the risk - if it exists, it will be updated automatically
                success = create_risk_in_dave(
                    dave_endpoint, 
                    dave_headers, 
                    dave_risk
                )
                
                if success:
                    # Note: create_risk_in_dave handles both create and update
                    # We'll count as creation for now (actual stats tracked in the function)
                    successful_creations += 1
                    logger.info(f"Processed risk {risk_id} successfully")
                else:
                    errors += 1
                    
            except Exception as e:
                logger.error(f"Error processing risk {risk.get('id', 'unknown')}: {e}")
                errors += 1
        
        logger.info(f"risk ingestion completed:")
        logger.info(f"  - Successfully processed: {successful_creations}")
        logger.info(f"  - Errors: {errors}")
        logger.info(f"  - Note: 'processed' includes both new creations and updates")
        
    except Exception as e:
        logger.error(f"Error during risk ingestion: {e}")


def map_cynerio_risk_to_dave_risk(
    cynerio_risk: Dict[str, Any], 
    affected_assets: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Map a Cynerio risk to DAVE risk format.
    All Cynerio fields are mapped directly to DAVE fields as-is.
    
    Args:
        cynerio_risk: Risk data from Cynerio API
        affected_assets: List of assets affected by this risk (not used with direct mapping)
        
    Returns:
        dict: risk data formatted for DAVE API with all Cynerio fields
    """
    
    # Map all Cynerio fields directly to DAVE
    dave_risk = {
        "asset_id": cynerio_risk.get("asset_id"),
        "availability_score": cynerio_risk.get("availability_score"),
        "category": cynerio_risk.get("category"),
        "comment": cynerio_risk.get("comment"),
        "confidentiality_score": cynerio_risk.get("confidentiality_score"),
        "cvss": cynerio_risk.get("cvss"),
        "description": cynerio_risk.get("description"),
        "detected_on": cynerio_risk.get("detected_on"),
        "device_class": cynerio_risk.get("device_class"),
        "display_name": cynerio_risk.get("display_name"),
        "due_date": cynerio_risk.get("due_date"),
        "epss": cynerio_risk.get("epss"),
        "has_malware": cynerio_risk.get("has_malware"),
        "external_id": cynerio_risk.get("id"),  # Map Cynerio id to DAVE external_id
        "impact_confidentiality": cynerio_risk.get("impact_confidentiality"),
        "impact_patient_safety": cynerio_risk.get("impact_patient_safety"),
        "impact_service_disruption": cynerio_risk.get("impact_service_disruption"),
        "integrity_score": cynerio_risk.get("integrity_score"),
        "latest_status_update": cynerio_risk.get("latest_status_update"),
        "link": cynerio_risk.get("link"),
        "name": cynerio_risk.get("name"),
        "nhs_published_date": cynerio_risk.get("nhs_published_date"),
        "nhs_severity": cynerio_risk.get("nhs_severity"),
        "nhs_threat_id": cynerio_risk.get("nhs_threat_id"),
        "owner": cynerio_risk.get("owner"),
        "response": cynerio_risk.get("response"),
        "risk_group": cynerio_risk.get("risk_group"),
        "risk_id": cynerio_risk.get("risk_id"),
        "risk_score": cynerio_risk.get("risk_score"),
        "risk_score_level": cynerio_risk.get("risk_score_level"),
        "risk_type_display_name": cynerio_risk.get("risk_type_display_name"),
        "site": cynerio_risk.get("site"),
        "status_display_name": cynerio_risk.get("status_display_name"),
        "tags_easy_to_weaponize": cynerio_risk.get("tags_easy_to_weaponize"),
        "tags_exploit_code_maturity": cynerio_risk.get("tags_exploit_code_maturity"),
        "tags_exploited_in_the_wild": cynerio_risk.get("tags_exploited_in_the_wild"),
        "tags_lateral_movement": cynerio_risk.get("tags_lateral_movement"),
        "tags_malware": cynerio_risk.get("tags_malware"),
        "type": cynerio_risk.get("type"),
        "type_display_name": cynerio_risk.get("type_display_name"),
        "vlan": cynerio_risk.get("vlan")
    }
    
    # Remove None values to keep the payload clean
    dave_risk = {k: v for k, v in dave_risk.items() if v is not None}
    
    return dave_risk


def create_risk_in_dave(
    dave_endpoint: str, 
    headers: Dict[str, str], 
    risk_data: Dict[str, Any]
) -> bool:
    """
    Create a new risk in DAVE using the POST /risks endpoint.
    All Cynerio fields are passed directly.
    
    If the risk already exists (based on external_id or risk_id), 
    this will attempt to update it instead.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        risk_data: risk data to create (all Cynerio fields)
        
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{dave_endpoint}/risks/"
    
    # Use all Cynerio fields as-is
    create_payload = risk_data.copy()
    
    # Remove None values
    create_payload = {k: v for k, v in create_payload.items() if v is not None}
    
    try:
        response = requests.post(url, json=create_payload, headers=headers)
        if response.status_code in [200, 201]:
            return True
        elif response.status_code == 409:
            # Risk already exists - try to get the existing UUID and update
            logger.warning(f"Risk with external_id {risk_data.get('external_id')} already exists, attempting update...")
            
            error_data = response.json()
            existing_uuid = error_data.get('error', {}).get('existing_uuid')
            
            if existing_uuid:
                # We have the UUID from the error response, use it to update
                logger.info(f"Got existing UUID {existing_uuid} from error response, updating...")
                return update_risk_in_dave(dave_endpoint, headers, existing_uuid, risk_data)
            else:
                # Fallback: search for the risk
                logger.info(f"No UUID in error response, searching for existing risk...")
                external_id = risk_data.get('external_id')
                existing_risk = check_risk_exists_in_dave(dave_endpoint, headers, external_id)
                
                if existing_risk:
                    dave_uuid = existing_risk.get('id')
                    if dave_uuid:
                        logger.info(f"Found existing risk with UUID {dave_uuid}, updating...")
                        return update_risk_in_dave(dave_endpoint, headers, dave_uuid, risk_data)
                
                logger.error(f"Could not find existing risk to update for external_id {external_id}")
                return False
        else:
            logger.error(f"Failed to create risk {risk_data.get('external_id', 'unknown')}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error creating risk {risk_data.get('external_id', 'unknown')}: {e}")
        return False


def check_risk_exists_in_dave(
    dave_endpoint: str, 
    headers: Dict[str, str], 
    risk_id: str
) -> Optional[Dict[str, Any]]:
    """
    Check if a risk exists in DAVE by querying for external_id.
    Since the API doesn't support external_id filtering, we'll fetch risks in batches
    and search for a matching external_id in Python.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        risk_id: Cynerio risk ID to check (maps to external_id in DAVE)
        
    Returns:
        dict or None: risk data if exists (with UUID 'id' field), None if not found
    """
    # Query for risks - we'll need to paginate through to find matches
    # Start with a reasonable page size
    url = f"{dave_endpoint}/risks/"
    page = 1
    limit = 100
    
    try:
        while True:
            params = {
                "page": page,
                "limit": limit
            }
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                risks = data.get("data", [])
                
                # Search for matching external_id in this batch
                for risk in risks:
                    if risk.get("external_id") == risk_id:
                        logger.info(f"Found existing risk with external_id={risk_id}, UUID id={risk.get('id')}")
                        return risk
                
                # Check if there are more pages
                pagination = data.get("pagination", {})
                current_page = pagination.get("page", 1)
                total_pages = pagination.get("pages", 1)
                
                if current_page >= total_pages:
                    # No more pages, risk not found
                    return None
                
                page += 1
            elif response.status_code == 404:
                return None
            else:
                logger.warning(f"Unexpected response when checking risk {risk_id}: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Error checking if risk {risk_id} exists: {e}")
        return None


def update_risk_in_dave(
    dave_endpoint: str, 
    headers: Dict[str, str], 
    risk_id: str, 
    risk_data: Dict[str, Any]
) -> bool:
    """
    Update an existing risk in DAVE.
    All Cynerio fields are passed directly.
    
    Args:
        dave_endpoint: DAVE API base URL
        headers: Authorization headers for DAVE
        risk_id: DAVE internal risk ID (not Cynerio external_id) to update
        risk_data: risk data to update (all Cynerio fields)
        
    Returns:
        bool: True if successful, False otherwise
    """
    url = f"{dave_endpoint}/risks/{risk_id}"
    
    # Remove id and risk_id from the update payload as it's in the URL
    update_payload = {k: v for k, v in risk_data.items() if k not in ["id", "risk_id"]}
    
    # Remove None values
    update_payload = {k: v for k, v in update_payload.items() if v is not None}
    
    try:
        response = requests.put(url, json=update_payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            logger.error(f"Failed to update risk {risk_id}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error updating risk {risk_id}: {e}")
        return False


#####################################################################################################################        
# Example usage
if __name__ == "__main__":
    try:
        # Run the full ingestion process
        logger.info("Starting Cynerio to DAVE synchronization...")
        
        # Sync assets
        logger.info("\n" + "="*80)
        logger.info("SYNCING ASSETS")
        logger.info("="*80)
        ingest_cynerio_assets_into_dave()
        
        # Sync risks as risks
        logger.info("\n" + "="*80)
        logger.info("SYNCING RISKS AS risks")
        logger.info("="*80)
        ingest_cynerio_risks_into_dave()
        
        logger.info("\n" + "="*80)
        logger.info("SYNCHRONIZATION COMPLETED")
        logger.info("="*80)

    except Exception as e:
        logger.error(f"Error: {e}")


# Alternative example usage for testing individual functions
def test_individual_functions():
    """Test individual functions for development/debugging"""
    try:
        # Initialize the token and start auto-refresh
        token = get_token()
        headers = {
            "Authorization": f"Bearer {token}"
        }

        assets = fetch_all_assets(
            endpoint=endpoint,
            headers=headers,
            max_pages=1  # Limit for testing
        )

        print(f"Fetched {len(assets)} assets")

        # Show first asset mapping
        if assets:
            first_asset = assets[0]
            print("\nFirst asset from Cynerio:")
            print(json.dumps(first_asset, indent=2))
            
            mapped_asset = map_cynerio_to_dave_asset(first_asset)
            print("\nMapped to  format:")
            print(json.dumps(mapped_asset, indent=2))

    except Exception as e:
        logger.error(f"Error: {e}")