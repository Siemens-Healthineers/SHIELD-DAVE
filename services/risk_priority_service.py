#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""

import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import logging
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'risk_priority_service.log')),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('risk_priority_service')

# Database configuration (read from environment or config file)
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}


def get_db_connection():
    """Establish database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise


def auto_dismiss_remediated_items():
    """
    Auto-dismiss items that are:
    - Status: 'Resolved', 'Mitigated', or 'False Positive'
    - Past due date
    - No longer appear in open priorities
    
    These items will be removed from the risk_priority_view by changing their status
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Find items to auto-dismiss
        query = """
        SELECT 
            link_id,
            cve_id,
            remediation_status,
            due_date,
            CURRENT_DATE - due_date as days_past_due
        FROM device_vulnerabilities_link
        WHERE remediation_status IN ('Resolved', 'Mitigated', 'False Positive')
        AND due_date < CURRENT_DATE
        AND remediation_status != 'Archived'
        """
        
        cursor.execute(query)
        items_to_dismiss = cursor.fetchall()
        
        if not items_to_dismiss:
            logger.info("No items found for auto-dismiss")
            return 0
        
        dismissed_count = 0
        for item in items_to_dismiss:
            # Archive the item (we don't actually delete, just mark as archived)
            update_query = """
            UPDATE device_vulnerabilities_link
            SET 
                remediation_status = 'Archived',
                remediation_notes = COALESCE(remediation_notes, '') || 
                    E'\n\n[AUTO-DISMISSED on ' || CURRENT_DATE || 
                    ']: Item was ' || %s || ' and past due date by ' || %s || ' days.'
            WHERE link_id = %s
            """
            
            cursor.execute(update_query, (
                item['remediation_status'],
                item['days_past_due'],
                item['link_id']
            ))
            
            dismissed_count += 1
            logger.info(f"Auto-dismissed {item['cve_id']} (link_id: {item['link_id']}) - "
                       f"Status: {item['remediation_status']}, Days past due: {item['days_past_due']}")
        
        conn.commit()
        logger.info(f"Auto-dismissed {dismissed_count} items")
        return dismissed_count
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error in auto_dismiss_remediated_items: {e}")
        return 0
    finally:
        if conn:
            conn.close()


def restore_overdue_open_items():
    """
    Restore items back to active view if they are:
    - Status: 'Open' or 'In Progress'
    - Past due date
    - Were previously archived but shouldn't be
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Find items that should be restored
        query = """
        SELECT 
            link_id,
            cve_id,
            remediation_status,
            due_date
        FROM device_vulnerabilities_link
        WHERE remediation_status IN ('Open', 'In Progress')
        AND due_date IS NOT NULL
        AND due_date < CURRENT_DATE
        """
        
        cursor.execute(query)
        items = cursor.fetchall()
        
        if items:
            logger.info(f"Found {len(items)} overdue open items (these remain in priority view)")
            for item in items:
                logger.info(f"Overdue: {item['cve_id']} (due: {item['due_date']}) - Status: {item['remediation_status']}")
        
        return len(items)
        
    except Exception as e:
        logger.error(f"Error in restore_overdue_open_items: {e}")
        return 0
    finally:
        if conn:
            conn.close()


def refresh_materialized_view():
    """Refresh the risk_priority_view materialized view"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        logger.info("Refreshing risk_priority_view materialized view...")
        cursor.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY risk_priority_view")
        conn.commit()
        
        # Get count of priorities
        cursor.execute("SELECT COUNT(*) FROM risk_priority_view")
        count = cursor.fetchone()[0]
        
        logger.info(f"Materialized view refreshed successfully. Total priorities: {count}")
        return True
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error refreshing materialized view: {e}")
        return False
    finally:
        if conn:
            conn.close()


def recalculate_priority_scores():
    """
    Recalculate priority tier and risk scores for all vulnerability links
    This ensures scores are up-to-date with current configuration
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        logger.info("Recalculating priority scores for all vulnerability links...")
        
        # Trigger the update trigger for all rows by touching updated_at
        # The trigger will automatically recalculate priority_tier and risk_score
        update_query = """
        UPDATE device_vulnerabilities_link
        SET updated_at = CURRENT_TIMESTAMP
        WHERE remediation_status IN ('Open', 'In Progress')
        """
        
        cursor.execute(update_query)
        updated_count = cursor.rowcount
        conn.commit()
        
        logger.info(f"Recalculated priority scores for {updated_count} vulnerability links")
        return updated_count
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error recalculating priority scores: {e}")
        return 0
    finally:
        if conn:
            conn.close()


def generate_statistics():
    """Generate and log current statistics"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Overall statistics
        cursor.execute("""
        SELECT 
            priority_tier,
            COUNT(*) as count,
            COUNT(CASE WHEN days_overdue > 0 THEN 1 END) as overdue_count
        FROM risk_priority_view
        GROUP BY priority_tier
        ORDER BY priority_tier
        """)
        
        tier_stats = cursor.fetchall()
        
        logger.info("=== Current Risk Priority Statistics ===")
        for stat in tier_stats:
            logger.info(f"Tier {stat['priority_tier']}: {stat['count']} total, "
                       f"{stat['overdue_count']} overdue")
        
        # KEV statistics
        cursor.execute("""
        SELECT 
            COUNT(*) as total_kevs,
            COUNT(CASE WHEN remediation_status = 'Open' THEN 1 END) as open_kevs,
            COUNT(CASE WHEN days_overdue > 0 THEN 1 END) as overdue_kevs
        FROM risk_priority_view
        WHERE is_kev = TRUE
        """)
        
        kev_stats = cursor.fetchone()
        logger.info(f"KEVs: {kev_stats['total_kevs']} total, "
                   f"{kev_stats['open_kevs']} open, "
                   f"{kev_stats['overdue_kevs']} overdue")
        
        # Vendor status breakdown
        cursor.execute("""
        SELECT 
            vendor_status,
            COUNT(*) as count
        FROM risk_priority_view
        WHERE vendor_status IS NOT NULL
        GROUP BY vendor_status
        ORDER BY count DESC
        """)
        
        vendor_stats = cursor.fetchall()
        logger.info("Vendor Status Breakdown:")
        for stat in vendor_stats:
            logger.info(f"  {stat['vendor_status']}: {stat['count']}")
        
        logger.info("======================================")
        
    except Exception as e:
        logger.error(f"Error generating statistics: {e}")
    finally:
        if conn:
            conn.close()


def main():
    """Main execution function"""
    logger.info("=" * 60)
    logger.info("Risk Priority Service - Starting")
    logger.info("=" * 60)
    
    try:
        # Step 1: Auto-dismiss remediated items past due date
        logger.info("Step 1: Auto-dismissing remediated items...")
        dismissed = auto_dismiss_remediated_items()
        
        # Step 2: Check for overdue open items
        logger.info("Step 2: Checking for overdue open items...")
        overdue = restore_overdue_open_items()
        
        # Step 3: Recalculate priority scores
        logger.info("Step 3: Recalculating priority scores...")
        recalculated = recalculate_priority_scores()
        
        # Step 4: Refresh materialized view
        logger.info("Step 4: Refreshing materialized view...")
        refresh_success = refresh_materialized_view()
        
        # Step 5: Generate statistics
        logger.info("Step 5: Generating statistics...")
        generate_statistics()
        
        # Summary
        logger.info("=" * 60)
        logger.info("Risk Priority Service - Completed Successfully")
        logger.info(f"  - Items dismissed: {dismissed}")
        logger.info(f"  - Overdue open items: {overdue}")
        logger.info(f"  - Scores recalculated: {recalculated}")
        logger.info(f"  - View refresh: {'Success' if refresh_success else 'Failed'}")
        logger.info("=" * 60)
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error in main execution: {e}")
        logger.info("=" * 60)
        logger.info("Risk Priority Service - Failed")
        logger.info("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())

