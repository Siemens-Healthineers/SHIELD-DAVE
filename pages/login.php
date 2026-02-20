<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');

try {
    require_once __DIR__ . '/../config/config.php';
    require_once __DIR__ . '/../includes/auth.php';
    require_once __DIR__ . '/../includes/security.php';

    // Initialize auth but don't use session middleware for login page
    $auth = new Auth();
} catch (Exception $e) {
    die("Login page initialization error: " . $e->getMessage() . "<br>Stack trace: " . $e->getTraceAsString());
}

// Redirect if already logged in
if ($auth->isLoggedIn()) {
    $redirect_url = validate_redirect_url($_GET['redirect'] ?? '/pages/dashboard.php');
    header('Location: ' . $redirect_url);
    exit;
}

$error = '';
$success = '';
$showMFA = false;
$username = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $mfaCode = trim($_POST['mfa_code'] ?? '');
    
    if (empty($username) || empty($password)) {
        $error = 'Please enter both username and password.';
    } else {
        $result = $auth->login($username, $password, $mfaCode);
        
        if ($result['success']) {
            $redirect_url = validate_redirect_url($_POST['redirect'] ?? '/pages/dashboard.php');
            header('Location: ' . $redirect_url);
            exit;
        } else {
            $error = $result['message'];
            
            // Check if MFA is required
            if (strpos($error, 'MFA code required') !== false) {
                $showMFA = true;
            }
        }
    }
}

// Handle AJAX requests
if (isset($_GET['ajax']) && $_GET['ajax'] === 'check_mfa') {
    header('Content-Type: application/json');
    
    $username = trim($_GET['username'] ?? '');
    if (empty($username)) {
        echo json_encode(['mfa_required' => false]);
        exit;
    }
    
    $db = DatabaseConfig::getInstance();
    $sql = "SELECT mfa_enabled FROM users WHERE username = ? AND is_active = TRUE";
    $stmt = $db->query($sql, [$username]);
    $user = $stmt->fetch();
    
    echo json_encode(['mfa_required' => $user ? $user['mfa_enabled'] : false]);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/login.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="login-container">
        <div class="login-box">
            <div class="login-header">
                <div class="logo">
                    <img src="/assets/images/siemens-healthineers-logo.png" alt="Siemens Healthineers" class="logo-image">
                </div>
                <p class="subtitle">Medical Device Management & Cybersecurity Platform</p>
            </div>
            
            <form id="loginForm" method="POST" action="">
                <div class="form-group">
                    <label for="username">
                        <i class="fas fa-user"></i>
                        Username
                    </label>
                    <input type="text" id="username" name="username" value="<?php echo dave_htmlspecialchars($username); ?>" required>
                </div>
                
                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-lock"></i>
                        Password
                    </label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div id="mfaGroup" class="form-group" style="<?php echo $showMFA ? 'display: block;' : 'display: none;'; ?>">
                    <label for="mfa_code">
                        <i class="fas fa-key"></i>
                        MFA Code
                    </label>
                    <input type="text" id="mfa_code" name="mfa_code" placeholder="Enter 6-digit code" maxlength="6">
                    <small class="help-text">Enter the 6-digit code from your authenticator app</small>
                </div>
                
                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <?php echo dave_htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo dave_htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>
                
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-sign-in-alt"></i>
                    Login
                </button>
            </form>
            
            <div class="login-footer">
            </div>
        </div>
        
        <div class="login-info">
            <h2><?php echo getApplicationName(); ?></h2>
            <h3>System Features</h3>
            <ul>
                <li><i class="fas fa-check"></i> Asset Management & Discovery</li>
                <li><i class="fas fa-check"></i> FDA Device Mapping</li>
                <li><i class="fas fa-check"></i> Recall Monitoring</li>
                <li><i class="fas fa-check"></i> Vulnerability Management</li>
                <li><i class="fas fa-check"></i> Compliance Reporting</li>
            </ul>
        </div>
    </div>
    
    <script>
        // Check MFA requirement on username change
        document.getElementById('username').addEventListener('blur', function() {
            const username = this.value.trim();
            if (username) {
                fetch('?ajax=check_mfa&username=' + encodeURIComponent(username))
                    .then(response => response.json())
                    .then(data => {
                        const mfaGroup = document.getElementById('mfaGroup');
                        if (data.mfa_required) {
                            mfaGroup.style.display = 'block';
                            document.getElementById('mfa_code').required = true;
                        } else {
                            mfaGroup.style.display = 'none';
                            document.getElementById('mfa_code').required = false;
                        }
                    })
                    .catch(error => console.error('Error checking MFA:', error));
            }
        });
        
        // Form validation
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const mfaCode = document.getElementById('mfa_code').value.trim();
            
            if (!username || !password) {
                e.preventDefault();
                alert('Please enter both username and password.');
                return;
            }
            
            // Check if MFA is required but not provided
            const mfaGroup = document.getElementById('mfaGroup');
            if (mfaGroup.style.display === 'block' && !mfaCode) {
                e.preventDefault();
                alert('MFA code is required.');
                return;
            }
        });
        
        // Auto-focus on username field
        document.getElementById('username').focus();
    </script>
</body>
</html>
