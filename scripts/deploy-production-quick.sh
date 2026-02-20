#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


# Quick deployment wrapper - runs deploy-production.sh in automated mode
exec "$(dirname "$0")/deploy-production.sh" automated

