<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * 500 Internal Server Error Page for Device Assessment and Vulnerability Exposure ()
 * Handles server errors
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Error - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .error-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #ff9ff3 0%, #f368e0 100%);
            color: white;
            text-align: center;
            padding: 20px;
        }
        
        .error-content {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 60px 40px;
            max-width: 600px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        
        .error-icon {
            font-size: 6rem;
            margin-bottom: 30px;
            opacity: 0.8;
        }
        
        .error-title {
            font-size: 3rem;
            margin-bottom: 20px;
            font-weight: 700;
        }
        
        .error-message {
            font-size: 1.2rem;
            margin-bottom: 40px;
            opacity: 0.9;
            line-height: 1.6;
        }
        
        .error-actions {
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 15px 30px;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 2px solid rgba(255, 255, 255, 0.3);
        }
        
        .btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        
        .btn-primary {
            background: rgba(255, 255, 255, 0.9);
            color: #f368e0;
            border-color: rgba(255, 255, 255, 0.9);
        }
        
        .btn-primary:hover {
            background: white;
            color: #f368e0;
        }
        
        @media (max-width: 768px) {
            .error-content {
                padding: 40px 20px;
            }
            
            .error-title {
                font-size: 2rem;
            }
            
            .error-icon {
                font-size: 4rem;
            }
            
            .error-actions {
                flex-direction: column;
                align-items: center;
            }
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-content">
            <div class="error-icon">
                <i class="fas fa-exclamation-circle"></i>
            </div>
            
            <h1 class="error-title">500</h1>
            
            <p class="error-message">
                Internal server error. Something went wrong on our end. 
                We're working to fix this issue. Please try again later.
            </p>
            
            <div class="error-actions">
                <a href="/pages/dashboard.php" class="btn btn-primary">
                    <i class="fas fa-home"></i>
                    Go to Dashboard
                </a>
                
                <a href="javascript:location.reload()" class="btn">
                    <i class="fas fa-redo"></i>
                    Try Again
                </a>
                
                <a href="/pages/login.php" class="btn">
                    <i class="fas fa-sign-in-alt"></i>
                    Login
                </a>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh after 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
