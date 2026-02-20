<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once __DIR__ . '/../../../config/database.php';

try {
    $db = DatabaseConfig::getInstance();
    
    $sql = "SELECT user_id, username, email FROM users WHERE is_active = true ORDER BY username";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $users = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $users,
        'count' => count($users)
    ]);
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>








