#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
Report Generator Service for Device Assessment and Vulnerability Exposure ()
Advanced report generation with PDF, Excel, and data visualization
"""

import sys
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'logs', 'report_generator.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """Advanced report generation service"""
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'port': os.getenv('DB_PORT'),
            'database': os.getenv('DB_NAME'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD')
        }
        
        # Set up matplotlib for better plots
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def generate_comprehensive_report(self, report_type: str, date_from: str = None, 
                                    date_to: str = None, filters: Dict = None) -> Dict:
        """Generate comprehensive report with data and visualizations"""
        try:
            logger.info(f"Generating {report_type} report from {date_from} to {date_to}")
            
            # Get report data
            report_data = self._get_report_data(report_type, date_from, date_to, filters)
            
            # Generate visualizations
            visualizations = self._generate_visualizations(report_type, report_data)
            
            # Create summary statistics
            summary = self._create_summary(report_type, report_data)
            
            # Generate insights
            insights = self._generate_insights(report_type, report_data)
            
            return {
                'success': True,
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'date_range': {'from': date_from, 'to': date_to},
                'data': report_data,
                'visualizations': visualizations,
                'summary': summary,
                'insights': insights
            }
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_report_data(self, report_type: str, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get data for specific report type"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            if report_type == 'asset_summary':
                return self._get_asset_data(cursor, date_from, date_to, filters)
            elif report_type == 'vulnerability_report':
                return self._get_vulnerability_data(cursor, date_from, date_to, filters)
            elif report_type == 'recall_report':
                return self._get_recall_data(cursor, date_from, date_to, filters)
            elif report_type == 'compliance_report':
                return self._get_compliance_data(cursor, date_from, date_to, filters)
            elif report_type == 'security_dashboard':
                return self._get_security_dashboard_data(cursor, date_from, date_to, filters)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
                
        except Exception as e:
            logger.error(f"Error getting report data: {e}")
            return {}
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _get_asset_data(self, cursor, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get asset summary data"""
        try:
            # Build where clause
            where_conditions = []
            params = []
            
            if date_from:
                where_conditions.append("a.created_at >= %s")
                params.append(date_from)
            
            if date_to:
                where_conditions.append("a.created_at <= %s")
                params.append(date_to)
            
            if filters and filters.get('department'):
                where_conditions.append("a.department = %s")
                params.append(filters['department'])
            
            if filters and filters.get('status'):
                where_conditions.append("a.status = %s")
                params.append(filters['status'])
            
            where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
            
            # Asset statistics
            sql = f"""
                SELECT 
                    COUNT(*) as total_assets,
                    COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_assets,
                    COUNT(CASE WHEN a.status = 'Inactive' THEN 1 END) as inactive_assets,
                    COUNT(CASE WHEN a.status = 'Maintenance' THEN 1 END) as maintenance_assets,
                    COUNT(DISTINCT a.department) as departments,
                    COUNT(DISTINCT a.location) as locations,
                    COUNT(CASE WHEN a.created_at >= %s THEN 1 END) as new_assets
                FROM assets a {where_clause}
            """
            
            cursor.execute(sql, params + [date_from or '1900-01-01'])
            stats = cursor.fetchone()
            
            # Assets by department
            sql = f"""
                SELECT 
                    a.department,
                    COUNT(*) as asset_count,
                    COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_count,
                    ROUND(
                        (COUNT(CASE WHEN a.status = 'Active' THEN 1 END) * 100.0 / COUNT(*)), 2
                    ) as active_percentage
                FROM assets a {where_clause}
                GROUP BY a.department
                ORDER BY asset_count DESC
            """
            
            cursor.execute(sql, params)
            by_department = cursor.fetchall()
            
            # Assets by location
            sql = f"""
                SELECT 
                    a.location,
                    COUNT(*) as asset_count,
                    COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_count
                FROM assets a {where_clause}
                GROUP BY a.location
                ORDER BY asset_count DESC
            """
            
            cursor.execute(sql, params)
            by_location = cursor.fetchall()
            
            # Recent assets
            sql = f"""
                SELECT 
                    a.asset_id,
                    a.hostname,
                    a.ip_address,
                    a.department,
                    a.location,
                    a.status,
                    a.created_at
                FROM assets a {where_clause}
                ORDER BY a.created_at DESC
                LIMIT 20
            """
            
            cursor.execute(sql, params)
            recent_assets = cursor.fetchall()
            
            return {
                'statistics': dict(stats) if stats else {},
                'by_department': [dict(row) for row in by_department],
                'by_location': [dict(row) for row in by_location],
                'recent_assets': [dict(row) for row in recent_assets]
            }
            
        except Exception as e:
            logger.error(f"Error getting asset data: {e}")
            return {}
    
    def _get_vulnerability_data(self, cursor, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get vulnerability data"""
        try:
            where_conditions = []
            params = []
            
            if date_from:
                where_conditions.append("v.published_date >= %s")
                params.append(date_from)
            
            if date_to:
                where_conditions.append("v.published_date <= %s")
                params.append(date_to)
            
            if filters and filters.get('severity'):
                where_conditions.append("v.severity = %s")
                params.append(filters['severity'])
            
            where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
            
            # Vulnerability statistics
            sql = f"""
                SELECT 
                    COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
                    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_count,
                    COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) as medium_count,
                    COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) as low_count,
                    COUNT(DISTINCT dvl.device_id) as affected_devices,
                    AVG(v.cvss_v3_score) as avg_cvss_score,
                    MAX(v.cvss_v3_score) as max_cvss_score
                FROM vulnerabilities v
                LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                {where_clause}
            """
            
            cursor.execute(sql, params)
            stats = cursor.fetchone()
            
            # Vulnerabilities by severity
            sql = f"""
                SELECT 
                    v.severity,
                    COUNT(*) as count,
                    AVG(v.cvss_v3_score) as avg_score,
                    MAX(v.cvss_v3_score) as max_score
                FROM vulnerabilities v {where_clause}
                GROUP BY v.severity
                ORDER BY 
                    CASE v.severity 
                        WHEN 'Critical' THEN 1 
                        WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 
                        WHEN 'Low' THEN 4 
                        ELSE 5 
                    END
            """
            
            cursor.execute(sql, params)
            by_severity = cursor.fetchall()
            
            # Top vulnerabilities
            sql = f"""
                SELECT 
                    v.cve_id,
                    v.description,
                    v.severity,
                    v.cvss_v3_score,
                    v.published_date,
                    COUNT(DISTINCT dvl.device_id) as affected_devices
                FROM vulnerabilities v
                LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                {where_clause}
                GROUP BY v.cve_id, v.description, v.severity, v.cvss_v3_score, v.published_date
                ORDER BY v.cvss_v3_score DESC
                LIMIT 20
            """
            
            cursor.execute(sql, params)
            top_vulnerabilities = cursor.fetchall()
            
            return {
                'statistics': dict(stats) if stats else {},
                'by_severity': [dict(row) for row in by_severity],
                'top_vulnerabilities': [dict(row) for row in top_vulnerabilities]
            }
            
        except Exception as e:
            logger.error(f"Error getting vulnerability data: {e}")
            return {}
    
    def _get_recall_data(self, cursor, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get recall data"""
        try:
            where_conditions = []
            params = []
            
            if date_from:
                where_conditions.append("r.recall_date >= %s")
                params.append(date_from)
            
            if date_to:
                where_conditions.append("r.recall_date <= %s")
                params.append(date_to)
            
            if filters and filters.get('classification'):
                where_conditions.append("r.recall_classification = %s")
                params.append(filters['classification'])
            
            where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
            
            # Recall statistics
            sql = f"""
                SELECT 
                    COUNT(DISTINCT r.recall_id) as total_recalls,
                    COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls,
                    COUNT(DISTINCT drl.device_id) as affected_devices,
                    COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations,
                    COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class I' THEN r.recall_id END) as class_i_recalls,
                    COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class II' THEN r.recall_id END) as class_ii_recalls,
                    COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class III' THEN r.recall_id END) as class_iii_recalls
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                {where_clause}
            """
            
            cursor.execute(sql, params)
            stats = cursor.fetchone()
            
            # Recalls by classification
            sql = f"""
                SELECT 
                    r.recall_classification,
                    COUNT(*) as count,
                    COUNT(DISTINCT drl.device_id) as affected_devices
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                {where_clause}
                GROUP BY r.recall_classification
                ORDER BY count DESC
            """
            
            cursor.execute(sql, params)
            by_classification = cursor.fetchall()
            
            # Recent recalls
            sql = f"""
                SELECT 
                    r.recall_id,
                    r.fda_recall_number,
                    r.recall_date,
                    r.product_description,
                    r.manufacturer_name,
                    r.recall_classification,
                    COUNT(DISTINCT drl.device_id) as affected_devices
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                {where_clause}
                GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.product_description, 
                         r.manufacturer_name, r.recall_classification
                ORDER BY r.recall_date DESC
                LIMIT 20
            """
            
            cursor.execute(sql, params)
            recent_recalls = cursor.fetchall()
            
            return {
                'statistics': dict(stats) if stats else {},
                'by_classification': [dict(row) for row in by_classification],
                'recent_recalls': [dict(row) for row in recent_recalls]
            }
            
        except Exception as e:
            logger.error(f"Error getting recall data: {e}")
            return {}
    
    def _get_compliance_data(self, cursor, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get compliance data"""
        try:
            # Compliance statistics
            sql = """
                SELECT 
                    COUNT(DISTINCT a.asset_id) as total_assets,
                    COUNT(DISTINCT CASE WHEN a.compliance_status = 'Compliant' THEN a.asset_id END) as compliant_assets,
                    COUNT(DISTINCT CASE WHEN a.compliance_status = 'Non-Compliant' THEN a.asset_id END) as non_compliant_assets,
                    COUNT(DISTINCT CASE WHEN a.compliance_status = 'Under Review' THEN a.asset_id END) as under_review_assets,
                    COUNT(DISTINCT a.department) as departments,
                    ROUND(
                        (COUNT(DISTINCT CASE WHEN a.compliance_status = 'Compliant' THEN a.asset_id END) * 100.0 / COUNT(DISTINCT a.asset_id)), 2
                    ) as compliance_rate
                FROM assets a
            """
            
            cursor.execute(sql)
            stats = cursor.fetchone()
            
            # Compliance by department
            sql = """
                SELECT 
                    a.department,
                    COUNT(*) as total_assets,
                    COUNT(CASE WHEN a.compliance_status = 'Compliant' THEN 1 END) as compliant_count,
                    COUNT(CASE WHEN a.compliance_status = 'Non-Compliant' THEN 1 END) as non_compliant_count,
                    ROUND(
                        (COUNT(CASE WHEN a.compliance_status = 'Compliant' THEN 1 END) * 100.0 / COUNT(*)), 2
                    ) as compliance_rate
                FROM assets a
                GROUP BY a.department
                ORDER BY compliance_rate DESC
            """
            
            cursor.execute(sql)
            by_department = cursor.fetchall()
            
            # Compliance issues
            sql = """
                SELECT 
                    a.asset_id,
                    a.hostname,
                    a.department,
                    a.compliance_status,
                    a.compliance_notes,
                    a.last_compliance_check
                FROM assets a
                WHERE a.compliance_status != 'Compliant'
                ORDER BY a.last_compliance_check DESC
            """
            
            cursor.execute(sql)
            compliance_issues = cursor.fetchall()
            
            return {
                'statistics': dict(stats) if stats else {},
                'by_department': [dict(row) for row in by_department],
                'compliance_issues': [dict(row) for row in compliance_issues]
            }
            
        except Exception as e:
            logger.error(f"Error getting compliance data: {e}")
            return {}
    
    def _get_security_dashboard_data(self, cursor, date_from: str, date_to: str, filters: Dict) -> Dict:
        """Get security dashboard data"""
        try:
            # Security overview
            sql = """
                SELECT 
                    COUNT(DISTINCT a.asset_id) as total_assets,
                    COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
                    COUNT(DISTINCT r.recall_id) as total_recalls,
                    COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN v.cve_id END) as critical_vulnerabilities,
                    COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls,
                    COUNT(DISTINCT CASE WHEN a.compliance_status = 'Non-Compliant' THEN a.asset_id END) as non_compliant_assets
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
                LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
                LEFT JOIN recalls r ON drl.recall_id = r.recall_id
            """
            
            cursor.execute(sql)
            overview = cursor.fetchone()
            
            # Risk assessment by department
            sql = """
                SELECT 
                    a.department,
                    COUNT(*) as total_assets,
                    COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) as critical_vulnerabilities,
                    COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) as active_recalls,
                    COUNT(CASE WHEN a.compliance_status = 'Non-Compliant' THEN 1 END) as non_compliant_assets,
                    ROUND(
                        (COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) * 100.0 / COUNT(*)), 2
                    ) as critical_vulnerability_rate,
                    ROUND(
                        (COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) * 100.0 / COUNT(*)), 2
                    ) as recall_rate
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
                LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
                LEFT JOIN recalls r ON drl.recall_id = r.recall_id
                GROUP BY a.department
                ORDER BY critical_vulnerability_rate DESC, recall_rate DESC
            """
            
            cursor.execute(sql)
            risk_assessment = cursor.fetchall()
            
            return {
                'overview': dict(overview) if overview else {},
                'risk_assessment': [dict(row) for row in risk_assessment]
            }
            
        except Exception as e:
            logger.error(f"Error getting security dashboard data: {e}")
            return {}
    
    def _generate_visualizations(self, report_type: str, data: Dict) -> Dict:
        """Generate visualizations for the report"""
        try:
            visualizations = {}
            
            if report_type == 'asset_summary':
                visualizations = self._create_asset_visualizations(data)
            elif report_type == 'vulnerability_report':
                visualizations = self._create_vulnerability_visualizations(data)
            elif report_type == 'recall_report':
                visualizations = self._create_recall_visualizations(data)
            elif report_type == 'compliance_report':
                visualizations = self._create_compliance_visualizations(data)
            elif report_type == 'security_dashboard':
                visualizations = self._create_security_visualizations(data)
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
            return {}
    
    def _create_asset_visualizations(self, data: Dict) -> Dict:
        """Create asset visualizations"""
        try:
            visualizations = {}
            
            # Department distribution pie chart
            if data.get('by_department'):
                df = pd.DataFrame(data['by_department'])
                plt.figure(figsize=(10, 6))
                plt.pie(df['asset_count'], labels=df['department'], autopct='%1.1f%%')
                plt.title('Assets by Department')
                plt.tight_layout()
                
                # Convert to base64
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['department_pie'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            # Status distribution bar chart
            if data.get('statistics'):
                stats = data['statistics']
                statuses = ['Active', 'Inactive', 'Maintenance']
                counts = [
                    stats.get('active_assets', 0),
                    stats.get('inactive_assets', 0),
                    stats.get('maintenance_assets', 0)
                ]
                
                plt.figure(figsize=(10, 6))
                bars = plt.bar(statuses, counts, color=['green', 'red', 'orange'])
                plt.title('Asset Status Distribution')
                plt.ylabel('Number of Assets')
                
                # Add value labels on bars
                for bar, count in zip(bars, counts):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                            str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['status_bar'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error creating asset visualizations: {e}")
            return {}
    
    def _create_vulnerability_visualizations(self, data: Dict) -> Dict:
        """Create vulnerability visualizations"""
        try:
            visualizations = {}
            
            # Severity distribution
            if data.get('by_severity'):
                df = pd.DataFrame(data['by_severity'])
                plt.figure(figsize=(10, 6))
                colors = {'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'}
                bar_colors = [colors.get(severity, 'gray') for severity in df['severity']]
                
                bars = plt.bar(df['severity'], df['count'], color=bar_colors)
                plt.title('Vulnerabilities by Severity')
                plt.ylabel('Number of Vulnerabilities')
                plt.xticks(rotation=45)
                
                # Add value labels
                for bar, count in zip(bars, df['count']):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                            str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['severity_distribution'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            # CVSS score distribution
            if data.get('top_vulnerabilities'):
                df = pd.DataFrame(data['top_vulnerabilities'])
                plt.figure(figsize=(12, 6))
                plt.scatter(range(len(df)), df['cvss_v3_score'], 
                           c=df['cvss_v3_score'], cmap='RdYlGn_r', s=100)
                plt.title('CVSS Score Distribution (Top Vulnerabilities)')
                plt.xlabel('Vulnerability Rank')
                plt.ylabel('CVSS Score')
                plt.colorbar(label='CVSS Score')
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['cvss_distribution'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error creating vulnerability visualizations: {e}")
            return {}
    
    def _create_recall_visualizations(self, data: Dict) -> Dict:
        """Create recall visualizations"""
        try:
            visualizations = {}
            
            # Recall classification distribution
            if data.get('by_classification'):
                df = pd.DataFrame(data['by_classification'])
                plt.figure(figsize=(10, 6))
                colors = {'Class I': 'red', 'Class II': 'orange', 'Class III': 'yellow'}
                bar_colors = [colors.get(classification, 'gray') for classification in df['recall_classification']]
                
                bars = plt.bar(df['recall_classification'], df['count'], color=bar_colors)
                plt.title('Recalls by Classification')
                plt.ylabel('Number of Recalls')
                plt.xticks(rotation=45)
                
                # Add value labels
                for bar, count in zip(bars, df['count']):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                            str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['classification_distribution'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error creating recall visualizations: {e}")
            return {}
    
    def _create_compliance_visualizations(self, data: Dict) -> Dict:
        """Create compliance visualizations"""
        try:
            visualizations = {}
            
            # Compliance rate by department
            if data.get('by_department'):
                df = pd.DataFrame(data['by_department'])
                plt.figure(figsize=(12, 6))
                bars = plt.bar(df['department'], df['compliance_rate'], 
                              color=['green' if rate >= 80 else 'orange' if rate >= 60 else 'red' 
                                    for rate in df['compliance_rate']])
                plt.title('Compliance Rate by Department')
                plt.ylabel('Compliance Rate (%)')
                plt.xticks(rotation=45)
                plt.ylim(0, 100)
                
                # Add value labels
                for bar, rate in zip(bars, df['compliance_rate']):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                            f'{rate}%', ha='center', va='bottom')
                
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['compliance_by_department'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error creating compliance visualizations: {e}")
            return {}
    
    def _create_security_visualizations(self, data: Dict) -> Dict:
        """Create security visualizations"""
        try:
            visualizations = {}
            
            # Risk assessment heatmap
            if data.get('risk_assessment'):
                df = pd.DataFrame(data['risk_assessment'])
                plt.figure(figsize=(12, 8))
                
                # Create risk matrix
                risk_data = df[['department', 'critical_vulnerability_rate', 'recall_rate']].set_index('department')
                
                sns.heatmap(risk_data.T, annot=True, fmt='.1f', cmap='RdYlGn_r', 
                           cbar_kws={'label': 'Risk Level'})
                plt.title('Risk Assessment Heatmap')
                plt.xlabel('Department')
                plt.ylabel('Risk Factors')
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.getvalue()).decode()
                visualizations['risk_heatmap'] = f"data:image/png;base64,{image_base64}"
                plt.close()
            
            return visualizations
            
        except Exception as e:
            logger.error(f"Error creating security visualizations: {e}")
            return {}
    
    def _create_summary(self, report_type: str, data: Dict) -> Dict:
        """Create summary statistics"""
        try:
            summary = {
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'key_metrics': {},
                'trends': {},
                'recommendations': []
            }
            
            if report_type == 'asset_summary':
                stats = data.get('statistics', {})
                summary['key_metrics'] = {
                    'total_assets': stats.get('total_assets', 0),
                    'active_assets': stats.get('active_assets', 0),
                    'departments': stats.get('departments', 0),
                    'locations': stats.get('locations', 0)
                }
                
                if stats.get('total_assets', 0) > 0:
                    active_rate = (stats.get('active_assets', 0) / stats.get('total_assets', 1)) * 100
                    summary['trends']['active_asset_rate'] = round(active_rate, 2)
            
            elif report_type == 'vulnerability_report':
                stats = data.get('statistics', {})
                summary['key_metrics'] = {
                    'total_vulnerabilities': stats.get('total_vulnerabilities', 0),
                    'critical_count': stats.get('critical_count', 0),
                    'affected_devices': stats.get('affected_devices', 0),
                    'avg_cvss_score': round(stats.get('avg_cvss_score', 0), 2)
                }
                
                if stats.get('total_vulnerabilities', 0) > 0:
                    critical_rate = (stats.get('critical_count', 0) / stats.get('total_vulnerabilities', 1)) * 100
                    summary['trends']['critical_vulnerability_rate'] = round(critical_rate, 2)
            
            elif report_type == 'recall_report':
                stats = data.get('statistics', {})
                summary['key_metrics'] = {
                    'total_recalls': stats.get('total_recalls', 0),
                    'active_recalls': stats.get('active_recalls', 0),
                    'affected_devices': stats.get('affected_devices', 0),
                    'class_i_recalls': stats.get('class_i_recalls', 0)
                }
            
            elif report_type == 'compliance_report':
                stats = data.get('statistics', {})
                summary['key_metrics'] = {
                    'total_assets': stats.get('total_assets', 0),
                    'compliant_assets': stats.get('compliant_assets', 0),
                    'compliance_rate': stats.get('compliance_rate', 0),
                    'non_compliant_assets': stats.get('non_compliant_assets', 0)
                }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error creating summary: {e}")
            return {}
    
    def _generate_insights(self, report_type: str, data: Dict) -> List[str]:
        """Generate insights and recommendations"""
        try:
            insights = []
            
            if report_type == 'asset_summary':
                stats = data.get('statistics', {})
                if stats.get('inactive_assets', 0) > stats.get('active_assets', 1) * 0.1:
                    insights.append("High number of inactive assets detected. Consider reviewing and decommissioning unused assets.")
                
                if stats.get('maintenance_assets', 0) > 0:
                    insights.append(f"{stats.get('maintenance_assets', 0)} assets are in maintenance. Monitor their status and return to service when ready.")
            
            elif report_type == 'vulnerability_report':
                stats = data.get('statistics', {})
                if stats.get('critical_count', 0) > 0:
                    insights.append(f"{stats.get('critical_count', 0)} critical vulnerabilities require immediate attention.")
                
                if stats.get('avg_cvss_score', 0) > 7.0:
                    insights.append("Average CVSS score is high. Prioritize vulnerability remediation efforts.")
            
            elif report_type == 'recall_report':
                stats = data.get('statistics', {})
                if stats.get('class_i_recalls', 0) > 0:
                    insights.append(f"{stats.get('class_i_recalls', 0)} Class I recalls detected. These require immediate action.")
                
                if stats.get('open_remediations', 0) > 0:
                    insights.append(f"{stats.get('open_remediations', 0)} devices have open remediation items. Follow up on remediation progress.")
            
            elif report_type == 'compliance_report':
                stats = data.get('statistics', {})
                if stats.get('compliance_rate', 0) < 80:
                    insights.append("Compliance rate is below 80%. Review and address non-compliant assets.")
                
                if stats.get('non_compliant_assets', 0) > 0:
                    insights.append(f"{stats.get('non_compliant_assets', 0)} assets are non-compliant. Develop remediation plan.")
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating insights: {e}")
            return []

def main():
    """Main function for testing"""
    generator = ReportGenerator()
    
    # Test asset summary report
    print("Generating asset summary report...")
    result = generator.generate_comprehensive_report(
        'asset_summary',
        date_from='2024-01-01',
        date_to='2024-12-31'
    )
    
    if result['success']:
        print("Report generated successfully!")
        print(f"Generated at: {result['generated_at']}")
        print(f"Summary: {result['summary']}")
        print(f"Insights: {result['insights']}")
    else:
        print(f"Error: {result['error']}")

if __name__ == "__main__":
    main()
