<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Get user info before logout for logging
$username = $_SESSION['username'] ?? 'unknown';
$user_id = $_SESSION['user_id'] ?? null;

// Log the logout attempt
logMessage('INFO', 'User logged out', [
    'user_id' => $user_id,
    'username' => $username,
    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
]);

// Clear session data
$_SESSION = array();

// Destroy the session
session_destroy();

// Start a new session
session_start();

// Regenerate session ID for security
session_regenerate_id(true);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logged Out - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/login.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .logout-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-primary);
            padding: 20px;
        }
        
        .logout-box {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            max-width: 400px;
            width: 100%;
            box-shadow: var(--shadow-lg);
        }
        
        .logout-icon {
            font-size: 4rem;
            color: var(--siemens-petrol);
            margin-bottom: 20px;
        }
        
        .logout-title {
            color: var(--text-primary);
            font-size: var(--font-size-h2);
            font-weight: var(--font-weight-bold);
            margin-bottom: 15px;
        }
        
        .logout-message {
            color: var(--text-secondary);
            font-size: var(--font-size-body);
            margin-bottom: 30px;
            line-height: 1.6;
        }
        
        .logout-actions {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: var(--font-weight-medium);
            transition: all 0.2s ease;
            border: none;
            cursor: pointer;
            font-size: var(--font-size-body);
        }
        
        .btn-primary {
            background: var(--siemens-petrol);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--siemens-petrol-dark);
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: transparent;
            color: var(--text-primary);
            border: 1px solid var(--border-primary);
        }
        
        .btn-secondary:hover {
            background: var(--bg-hover);
            border-color: var(--siemens-petrol);
        }
        
        .auto-redirect {
            color: var(--text-muted);
            font-size: var(--font-size-small);
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="logout-container">
        <div class="logout-box">
            <div class="logout-icon">
                <i class="fas fa-sign-out-alt"></i>
            </div>
            
            <h1 class="logout-title">Successfully Logged Out</h1>
            
            <p class="logout-message">
                You have been securely logged out of the Device Assessment and Vulnerability Exposure. 
                Your session has been terminated and all authentication tokens have been cleared.
            </p>
            
            <div class="logout-actions">
                <a href="/pages/login.php" class="btn btn-primary">
                    <i class="fas fa-sign-in-alt"></i> Login Again
                </a>
                
                <a href="/" class="btn btn-secondary">
                    <i class="fas fa-home"></i> Return to Home
                </a>
            </div>
            
            <p class="auto-redirect">
                You will be automatically redirected to the login page in <span id="countdown">5</span> seconds.
            </p>
        </div>
    </div>

    <script>
        // Auto-redirect after 5 seconds
        let countdown = 5;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            
            if (countdown <= 0) {
                clearInterval(timer);
                window.location.href = '/pages/login.php';
            }
        }, 1000);
    </script>
</body>
</html>
