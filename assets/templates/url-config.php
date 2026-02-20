<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
// Security check
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}
?>
<script id="dave-config" type="application/json">
{
    "baseUrl": "<?php echo dave_htmlspecialchars(getBaseUrl()); ?>",
    "apiUrl": "<?php echo dave_htmlspecialchars(getApiUrl()); ?>",
    "assetsUrl": "<?php echo dave_htmlspecialchars(getAssetsUrl()); ?>",
    "pagesUrl": "<?php echo dave_htmlspecialchars(getPageUrl('pages')); ?>"
}
</script>
