#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
SBOM Parser Service for Device Assessment and Vulnerability Exposure ()
Handles parsing of Software Bill of Materials (SBOM) files in various formats
"""

import json
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional, Any
import os
import sys
from datetime import datetime

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'logs', 'sbom_parser.log'))
    ]
)
logger = logging.getLogger(__name__)

class SBOMParser:
    """SBOM parser for multiple formats"""
    
    def __init__(self):
        self.supported_formats = ['cyclonedx', 'spdx', 'json', 'xml']
    
    def parse_sbom(self, file_path: str, format_type: str = None) -> Dict:
        """Parse SBOM file and extract components"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"SBOM file not found: {file_path}")
            
            # Detect format if not specified
            if not format_type:
                format_type = self._detect_format(file_path)
            
            logger.info(f"Parsing SBOM file: {file_path} (Format: {format_type})")
            
            if format_type == 'cyclonedx':
                return self._parse_cyclonedx(file_path)
            elif format_type == 'spdx':
                return self._parse_spdx(file_path)
            elif format_type == 'spdx-tag-value':
                return self._parse_spdx_tag_value(file_path)
            elif format_type == 'json':
                return self._parse_json_sbom(file_path)
            elif format_type == 'xml':
                return self._parse_xml_sbom(file_path)
            else:
                raise ValueError(f"Unsupported SBOM format: {format_type}")
                
        except Exception as e:
            logger.error(f"Error parsing SBOM file: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def _detect_format(self, file_path: str) -> str:
        """Detect SBOM format based on file content"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 characters
            
            # Check for CycloneDX
            if '"bomFormat"' in content and '"CycloneDX"' in content:
                return 'cyclonedx'
            
            # Check for SPDX tag-value format first (more specific)
            if 'SPDXVersion:' in content or 'DocumentNamespace:' in content:
                return 'spdx-tag-value'
            
            # Check for SPDX JSON format
            if '"spdxVersion"' in content or 'SPDXRef-' in content:
                return 'spdx'
            
            # Check for JSON
            if content.strip().startswith('{'):
                return 'json'
            
            # Check for XML
            if content.strip().startswith('<'):
                return 'xml'
            
            # Default to JSON
            return 'json'
            
        except Exception as e:
            logger.warning(f"Could not detect format: {e}")
            return 'json'
    
    def _parse_cyclonedx(self, file_path: str) -> Dict:
        """Parse CycloneDX SBOM format"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            components = []
            metadata = {
                'format': 'CycloneDX',
                'version': data.get('specVersion', ''),
                'timestamp': data.get('metadata', {}).get('timestamp', ''),
                'tools': data.get('metadata', {}).get('tools', []),
                'authors': data.get('metadata', {}).get('authors', [])
            }
            
            # Parse components
            for component in data.get('components', []):
                comp_info = {
                    'name': component.get('name', ''),
                    'version': component.get('version', ''),
                    'vendor': component.get('group', '') or component.get('publisher', ''),
                    'type': component.get('type', ''),
                    'purl': component.get('purl', ''),
                    'cpe': component.get('cpe', ''),
                    'description': component.get('description', ''),
                    'licenses': component.get('licenses', []),
                    'external_references': component.get('externalReferences', []),
                    'properties': component.get('properties', [])
                }
                
                # Extract license information
                if comp_info['licenses']:
                    comp_info['license'] = comp_info['licenses'][0].get('id', '')
                
                components.append(comp_info)
            
            logger.info(f"Parsed {len(components)} components from CycloneDX SBOM")
            
            return {
                'success': True,
                'format': 'cyclonedx',
                'components': components,
                'metadata': metadata,
                'total_components': len(components)
            }
            
        except Exception as e:
            logger.error(f"Error parsing CycloneDX SBOM: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def _parse_spdx(self, file_path: str) -> Dict:
        """Parse SPDX SBOM format"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            components = []
            metadata = {
                'format': 'SPDX',
                'version': data.get('spdxVersion', ''),
                'name': data.get('name', ''),
                'dataLicense': data.get('dataLicense', ''),
                'documentNamespace': data.get('documentNamespace', ''),
                'creationInfo': data.get('creationInfo', {})
            }
            
            # Parse packages
            for package in data.get('packages', []):
                comp_info = {
                    'name': package.get('name', ''),
                    'version': package.get('versionInfo', ''),
                    'vendor': package.get('supplier', ''),
                    'type': 'package',
                    'description': package.get('description', ''),
                    'download_location': package.get('downloadLocation', ''),
                    'homepage': package.get('homepage', ''),
                    'license': package.get('licenseDeclared', ''),
                    'copyright': package.get('copyrightText', ''),
                    'external_refs': package.get('externalRefs', [])
                }
                
                # Extract CPE from external references
                for ref in comp_info['external_refs']:
                    if ref.get('referenceType') == 'cpe23Type':
                        cpe = ref.get('referenceLocator', '')
                        # Clean up CPE name - replace spaces with underscores
                        comp_info['cpe'] = self._clean_cpe_name(cpe)
                        break
                
                # If no CPE found, generate one from component name and version
                if not comp_info.get('cpe'):
                    comp_info['cpe'] = self._generate_cpe_name(comp_info['name'], comp_info['version'])
                
                components.append(comp_info)
            
            logger.info(f"Parsed {len(components)} components from SPDX SBOM")
            
            return {
                'success': True,
                'format': 'spdx',
                'components': components,
                'metadata': metadata,
                'total_components': len(components)
            }
            
        except Exception as e:
            logger.error(f"Error parsing SPDX SBOM: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def _clean_cpe_name(self, cpe: str) -> str:
        """Clean CPE name by replacing spaces with underscores and fixing common issues"""
        if not cpe:
            return ''
        
        # Replace spaces with underscores
        cpe = cpe.replace(' ', '_')
        
        # Fix common issues
        cpe = cpe.replace('.net_framework', 'microsoft:.net_framework')
        cpe = cpe.replace('7-zip', '7-zip:7-zip')
        
        return cpe
    
    def _generate_cpe_name(self, name: str, version: str) -> str:
        """Generate a CPE name from component name and version"""
        if not name:
            return ''
        
        # Clean the name
        clean_name = name.lower().replace(' ', '_').replace('-', '_')
        
        # Handle special cases
        if 'microsoft' in clean_name or '.net' in clean_name:
            vendor = 'microsoft'
        elif 'adobe' in clean_name:
            vendor = 'adobe'
        elif 'apache' in clean_name:
            vendor = 'apache'
        else:
            vendor = '*'
        
        # Generate CPE
        version_part = version if version else '*'
        return f"cpe:2.3:a:{vendor}:{clean_name}:{version_part}:*:*:*:*:*:*:*"

    def _parse_spdx_tag_value(self, file_path: str) -> Dict:
        """Parse SPDX tag-value format"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            components = []
            metadata = {
                'format': 'SPDX Tag-Value',
                'version': '',
                'name': '',
                'dataLicense': '',
                'documentNamespace': '',
                'creationInfo': {}
            }
            
            lines = content.split('\n')
            current_package = None
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse document metadata
                if line.startswith('SPDXVersion:'):
                    metadata['version'] = line.split(':', 1)[1].strip()
                elif line.startswith('DocumentName:'):
                    metadata['name'] = line.split(':', 1)[1].strip()
                elif line.startswith('DataLicense:'):
                    metadata['dataLicense'] = line.split(':', 1)[1].strip()
                elif line.startswith('DocumentNamespace:'):
                    metadata['documentNamespace'] = line.split(':', 1)[1].strip()
                elif line.startswith('Created:'):
                    metadata['creationInfo']['created'] = line.split(':', 1)[1].strip()
                elif line.startswith('Creator:'):
                    if 'creators' not in metadata['creationInfo']:
                        metadata['creationInfo']['creators'] = []
                    metadata['creationInfo']['creators'].append(line.split(':', 1)[1].strip())
                
                # Parse package information
                elif line.startswith('PackageName:'):
                    if current_package:
                        components.append(current_package)
                    current_package = {
                        'name': line.split(':', 1)[1].strip(),
                        'version': '',
                        'vendor': '',
                        'type': 'library',
                        'purl': '',
                        'cpe': '',
                        'description': '',
                        'licenses': [],
                        'external_references': [],
                        'properties': [],
                        'license': ''
                    }
                elif line.startswith('PackageVersion:') and current_package:
                    current_package['version'] = line.split(':', 1)[1].strip()
                elif line.startswith('PackageSupplier:') and current_package:
                    current_package['vendor'] = line.split(':', 1)[1].strip()
                elif line.startswith('PackageDescription:') and current_package:
                    current_package['description'] = line.split(':', 1)[1].strip()
                elif line.startswith('PackageLicenseDeclared:') and current_package:
                    license_text = line.split(':', 1)[1].strip()
                    current_package['license'] = license_text
                    current_package['licenses'] = [{'id': license_text}]
                elif line.startswith('PackageDownloadLocation:') and current_package:
                    download_location = line.split(':', 1)[1].strip()
                    if download_location and download_location != 'NOASSERTION':
                        current_package['external_references'].append({
                            'type': 'download',
                            'url': download_location
                        })
            
            # Add the last package if it exists
            if current_package:
                # Generate CPE name if not present
                if not current_package.get('cpe'):
                    current_package['cpe'] = self._generate_cpe_name(current_package['name'], current_package['version'])
                components.append(current_package)
            
            logger.info(f"Parsed {len(components)} components from SPDX Tag-Value SBOM")
            
            return {
                'success': True,
                'format': 'spdx-tag-value',
                'components': components,
                'metadata': metadata,
                'total_components': len(components)
            }
            
        except Exception as e:
            logger.error(f"Error parsing SPDX Tag-Value SBOM: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def _parse_json_sbom(self, file_path: str) -> Dict:
        """Parse generic JSON SBOM format"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            components = []
            metadata = {
                'format': 'JSON',
                'timestamp': datetime.now().isoformat()
            }
            
            # Try to find components in various JSON structures
            components_data = None
            
            if 'components' in data:
                components_data = data['components']
            elif 'packages' in data:
                components_data = data['packages']
            elif 'dependencies' in data:
                components_data = data['dependencies']
            elif isinstance(data, list):
                components_data = data
            
            if components_data:
                for component in components_data:
                    if isinstance(component, dict):
                        comp_info = {
                            'name': component.get('name', ''),
                            'version': component.get('version', ''),
                            'vendor': component.get('vendor', '') or component.get('author', ''),
                            'type': component.get('type', ''),
                            'description': component.get('description', ''),
                            'license': component.get('license', ''),
                            'homepage': component.get('homepage', ''),
                            'repository': component.get('repository', '')
                        }
                        components.append(comp_info)
            
            logger.info(f"Parsed {len(components)} components from JSON SBOM")
            
            return {
                'success': True,
                'format': 'json',
                'components': components,
                'metadata': metadata,
                'total_components': len(components)
            }
            
        except Exception as e:
            logger.error(f"Error parsing JSON SBOM: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def _parse_xml_sbom(self, file_path: str) -> Dict:
        """Parse XML SBOM format"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            components = []
            metadata = {
                'format': 'XML',
                'timestamp': datetime.now().isoformat()
            }
            
            # Generic XML parsing - look for common component patterns
            for elem in root.iter():
                if elem.tag.lower() in ['component', 'package', 'dependency', 'library']:
                    comp_info = {
                        'name': elem.get('name', '') or elem.findtext('name', ''),
                        'version': elem.get('version', '') or elem.findtext('version', ''),
                        'vendor': elem.get('vendor', '') or elem.findtext('vendor', ''),
                        'type': elem.get('type', '') or elem.findtext('type', ''),
                        'description': elem.findtext('description', ''),
                        'license': elem.findtext('license', '')
                    }
                    
                    if comp_info['name']:  # Only add if name exists
                        components.append(comp_info)
            
            logger.info(f"Parsed {len(components)} components from XML SBOM")
            
            return {
                'success': True,
                'format': 'xml',
                'components': components,
                'metadata': metadata,
                'total_components': len(components)
            }
            
        except Exception as e:
            logger.error(f"Error parsing XML SBOM: {e}")
            return {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
    
    def extract_software_components(self, sbom_data: Dict) -> List[Dict]:
        """Extract software components from parsed SBOM data"""
        components = []
        
        for comp in sbom_data.get('components', []):
            # Create standardized component record
            component = {
                'name': comp.get('name', '').strip(),
                'version': comp.get('version', '').strip(),
                'vendor': comp.get('vendor', '').strip(),
                'type': comp.get('type', 'library'),
                'description': comp.get('description', '').strip(),
                'license': comp.get('license', '').strip(),
                'homepage': comp.get('homepage', '').strip(),
                'repository': comp.get('repository', '').strip(),
                'purl': comp.get('purl', '').strip(),
                'cpe': comp.get('cpe', '').strip()
            }
            
            # Only include components with names
            if component['name']:
                components.append(component)
        
        return components
    
    def validate_sbom(self, sbom_data: Dict) -> Dict:
        """Validate SBOM data structure"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check required fields
        if not sbom_data.get('components'):
            validation_result['valid'] = False
            validation_result['errors'].append('No components found in SBOM')
        
        # Check component structure
        for i, component in enumerate(sbom_data.get('components', [])):
            if not component.get('name'):
                validation_result['warnings'].append(f'Component {i} missing name')
            
            if not component.get('version'):
                validation_result['warnings'].append(f'Component {i} missing version')
        
        return validation_result

def main():
    """Main function for command line usage"""
    import sys
    
    if len(sys.argv) < 2:
        # Test mode - run with sample data
        parser = SBOMParser()
        
        # Test with sample data
        sample_cyclonedx = {
            'specVersion': '1.4',
            'bomFormat': 'CycloneDX',
            'components': [
                {
                    'name': 'Apache HTTP Server',
                    'version': '2.4.41',
                    'group': 'Apache Software Foundation',
                    'type': 'library',
                    'purl': 'pkg:maven/org.apache.httpcomponents/httpclient@4.5.13'
                },
                {
                    'name': 'OpenSSL',
                    'version': '1.1.1f',
                    'group': 'OpenSSL Software Foundation',
                    'type': 'library'
                }
            ]
        }
        
        print("Testing SBOM parser...")
        result = parser.extract_software_components(sample_cyclonedx)
        print(f"Extracted {len(result)} components:")
        for comp in result:
            print(f"  - {comp['name']} {comp['version']} ({comp['vendor']})")
    else:
        # Production mode - parse file from command line
        file_path = sys.argv[1]
        parser = SBOMParser()
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"SBOM file not found: {file_path}")
            
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"Cannot read SBOM file: {file_path}")
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                raise ValueError("SBOM file is empty")
            
            result = parser.parse_sbom(file_path)
            print(json.dumps(result))
        except Exception as e:
            error_result = {
                'success': False,
                'error': str(e),
                'components': [],
                'metadata': {}
            }
            print(json.dumps(error_result))

if __name__ == "__main__":
    main()
