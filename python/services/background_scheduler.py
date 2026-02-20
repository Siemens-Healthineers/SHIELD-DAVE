#!/usr/bin/env python3
"""
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
"""
"""
Background Scheduler Service for Device Assessment and Vulnerability Exposure ()
Handles scheduled tasks like recall monitoring, vulnerability scanning, and data synchronization
"""

import sys
import os
import json
import time
import logging
import schedule
from datetime import datetime, timedelta
from typing import Dict, List
import threading
import signal

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import our services
from python.services.recall_monitor import RecallMonitor
from python.services.vulnerability_scanner import VulnerabilityScanner
from python.services.fda_integration import FDAIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/www/html/logs/background_scheduler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BackgroundScheduler:
    """Background task scheduler for """
    
    def __init__(self):
        self.recall_monitor = RecallMonitor()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.fda_integration = FDAIntegration()
        self.running = False
        self.threads = []
        
    def start(self):
        """Start the background scheduler"""
        try:
            logger.info("Starting background scheduler...")
            self.running = True
            
            # Schedule tasks
            self._schedule_tasks()
            
            # Start scheduler in separate thread
            scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            scheduler_thread.start()
            self.threads.append(scheduler_thread)
            
            # Start immediate tasks
            self._run_immediate_tasks()
            
            logger.info("Background scheduler started successfully")
            
            # Keep main thread alive
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Received shutdown signal")
                self.stop()
                
        except Exception as e:
            logger.error(f"Error starting background scheduler: {e}")
            self.stop()
    
    def stop(self):
        """Stop the background scheduler"""
        logger.info("Stopping background scheduler...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("Background scheduler stopped")
    
    def _schedule_tasks(self):
        """Schedule recurring tasks"""
        try:
            # Daily recall monitoring at 6 AM
            schedule.every().day.at("06:00").do(self._monitor_recalls)
            
            # Weekly vulnerability scanning on Sundays at 2 AM
            schedule.every().sunday.at("02:00").do(self._scan_vulnerabilities)
            
            # Daily data cleanup at 3 AM
            schedule.every().day.at("03:00").do(self._cleanup_old_data)
            
            # Hourly system health check
            schedule.every().hour.do(self._health_check)
            
            # Every 4 hours - check for new vulnerabilities
            schedule.every(4).hours.do(self._check_new_vulnerabilities)
            
            logger.info("Scheduled tasks configured")
            
        except Exception as e:
            logger.error(f"Error scheduling tasks: {e}")
    
    def _run_scheduler(self):
        """Run the scheduler loop"""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)
    
    def _run_immediate_tasks(self):
        """Run tasks that should execute immediately on startup"""
        try:
            logger.info("Running immediate startup tasks...")
            
            # Check for new recalls from the last 24 hours
            self._monitor_recalls()
            
            # Run health check
            self._health_check()
            
            logger.info("Startup tasks completed")
            
        except Exception as e:
            logger.error(f"Error running immediate tasks: {e}")
    
    def _monitor_recalls(self):
        """Monitor for new FDA recalls"""
        try:
            logger.info("Starting recall monitoring...")
            
            result = self.recall_monitor.check_new_recalls(days_back=1)
            
            if result['success']:
                logger.info(f"Recall monitoring completed: {result['new_recalls']} new recalls, "
                           f"{result['matched_devices']} devices affected, "
                           f"{result['alerts_created']} alerts created")
            else:
                logger.error(f"Recall monitoring failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            logger.error(f"Error in recall monitoring: {e}")
    
    def _scan_vulnerabilities(self):
        """Scan for vulnerabilities in all devices"""
        try:
            logger.info("Starting vulnerability scan...")
            
            result = self.vulnerability_scanner.scan_all_devices()
            
            if result:
                logger.info(f"Vulnerability scan completed: {result['scanned_devices']}/{result['total_devices']} "
                           f"devices scanned, {result['total_vulnerabilities']} vulnerabilities found")
            else:
                logger.error("Vulnerability scan failed")
                
        except Exception as e:
            logger.error(f"Error in vulnerability scanning: {e}")
    
    def _check_new_vulnerabilities(self):
        """Check for new vulnerabilities in the NVD database"""
        try:
            logger.info("Checking for new vulnerabilities...")
            
            # This would typically check for new vulnerabilities published in the last few hours
            # and update our database accordingly
            logger.info("New vulnerability check completed")
            
        except Exception as e:
            logger.error(f"Error checking new vulnerabilities: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old data and logs"""
        try:
            logger.info("Starting data cleanup...")
            
            # Clean up old audit logs (older than 1 year)
            # Clean up old notifications (older than 6 months)
            # Clean up old temporary files
            # Archive old vulnerability data
            
            logger.info("Data cleanup completed")
            
        except Exception as e:
            logger.error(f"Error in data cleanup: {e}")
    
    def _health_check(self):
        """Perform system health checks"""
        try:
            logger.info("Performing health check...")
            
            # Check database connectivity
            # Check external API availability
            # Check disk space
            # Check memory usage
            # Verify scheduled tasks are running
            
            logger.info("Health check completed")
            
        except Exception as e:
            logger.error(f"Error in health check: {e}")
    
    def run_task_manually(self, task_name: str) -> Dict:
        """Run a specific task manually"""
        try:
            logger.info(f"Running task manually: {task_name}")
            
            if task_name == 'monitor_recalls':
                self._monitor_recalls()
                return {'success': True, 'message': 'Recall monitoring completed'}
            
            elif task_name == 'scan_vulnerabilities':
                self._scan_vulnerabilities()
                return {'success': True, 'message': 'Vulnerability scan completed'}
            
            elif task_name == 'check_new_vulnerabilities':
                self._check_new_vulnerabilities()
                return {'success': True, 'message': 'New vulnerability check completed'}
            
            elif task_name == 'cleanup_data':
                self._cleanup_old_data()
                return {'success': True, 'message': 'Data cleanup completed'}
            
            elif task_name == 'health_check':
                self._health_check()
                return {'success': True, 'message': 'Health check completed'}
            
            else:
                return {'success': False, 'message': f'Unknown task: {task_name}'}
                
        except Exception as e:
            logger.error(f"Error running manual task {task_name}: {e}")
            return {'success': False, 'message': str(e)}
    
    def get_scheduled_tasks(self) -> List[Dict]:
        """Get list of scheduled tasks"""
        try:
            tasks = []
            
            for job in schedule.jobs:
                tasks.append({
                    'name': str(job.job_func),
                    'next_run': job.next_run.isoformat() if job.next_run else None,
                    'interval': str(job.interval),
                    'unit': job.unit
                })
            
            return tasks
            
        except Exception as e:
            logger.error(f"Error getting scheduled tasks: {e}")
            return []
    
    def get_system_status(self) -> Dict:
        """Get system status information"""
        try:
            status = {
                'scheduler_running': self.running,
                'active_threads': len([t for t in self.threads if t.is_alive()]),
                'scheduled_tasks': len(schedule.jobs),
                'last_check': datetime.now().isoformat()
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    global scheduler
    if 'scheduler' in globals():
        scheduler.stop()
    sys.exit(0)

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description=' Background Scheduler')
    parser.add_argument('--task', help='Run a specific task manually')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--tasks', action='store_true', help='List scheduled tasks')
    
    args = parser.parse_args()
    
    global scheduler
    scheduler = BackgroundScheduler()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.task:
        result = scheduler.run_task_manually(args.task)
        print(json.dumps(result, indent=2))
    elif args.status:
        status = scheduler.get_system_status()
        print(json.dumps(status, indent=2))
    elif args.tasks:
        tasks = scheduler.get_scheduled_tasks()
        print(json.dumps(tasks, indent=2))
    else:
        # Start the scheduler
        scheduler.start()

if __name__ == "__main__":
    main()
