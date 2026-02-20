
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Background Services

This directory contains background services for the Device Assessment and Vulnerability Exposure (DAVE).

## Services

### SBOM Evaluation Service

**File**: `sbom_evaluation_service.py`

Automatically evaluates Software Bill of Materials (SBOMs) against the National Vulnerability Database (NVD).

**Features**:
- Automatic queue processing
- NVD API rate limiting
- Comprehensive logging
- Error handling and retries

**Installation**:
```bash
sudo bash install_service.sh
```

**Documentation**: See [/docs/sbom-evaluation-service.md](/docs/sbom-evaluation-service.md)

## Service Files

- `sbom_evaluation_service.py` - Main Python service
- `dave-sbom-evaluation.service` - Systemd service configuration
- `install_service.sh` - Installation script

## Quick Start

1. Install the service:
   ```bash
   sudo bash services/install_service.sh
   ```

2. Monitor the service:
   ```bash
   sudo systemctl status dave-sbom-evaluation
   ```

3. View logs:
   ```bash
   sudo journalctl -u dave-sbom-evaluation -f
   ```

4. Access web dashboard:
   ```
   https://your-server/pages/vulnerabilities/evaluation-queue.php
   ```

## Management Commands

Start service:
```bash
sudo systemctl start dave-sbom-evaluation
```

Stop service:
```bash
sudo systemctl stop dave-sbom-evaluation
```

Restart service:
```bash
sudo systemctl restart dave-sbom-evaluation
```

View status:
```bash
sudo systemctl status dave-sbom-evaluation
```

## Configuration

- Database config: `/var/www/html/config/database.php`
- NVD API key: `/var/www/html/config/nvd_api_key.txt`
- Log files: `/var/www/html/logs/sbom_evaluation.log`

## Support

For detailed documentation, see:
- [SBOM Evaluation Service Documentation](/docs/sbom-evaluation-service.md)
- [System Logs](/var/www/html/logs/)

