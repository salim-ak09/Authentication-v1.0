<?php
$page_title = 'Login';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Redirect if already logged in
if (is_logged_in()) {
    redirect('dashboard.php'); // Redirect to dashboard (we'll create this later)
}

// Initialize variables
$email = '';
$password = '';
$errors = [];
$max_login_attempts = 5; // Max attempts
$lockout_time = 15 * 60; // Lockout time in seconds (15 minutes)

// Check for error parameters from redirects
if (isset($_GET['error'])) {
    switch ($_GET['error']) {
        case 'telegram_denied':
            $errors[] = 'Login was denied via Telegram.';
            break;
        case 'telegram_expired':
            $errors[] = 'Telegram verification request expired. Please try again.';
            break;
        case 'invalid_request':
            $errors[] = 'Invalid authentication request. Please try again.';
            break;
        case 'security_check_failed':
            $errors[] = 'Security check failed. Please try logging in again.';
            break;
    }
}

// --- Brute Force Check ---
$db = getDbConnection();
$ip_address = get_ip_address();
$is_locked_out = false;

if ($db && $ip_address !== 'UNKNOWN' && $ip_address !== 'INVALID_IP_FORMAT') {
    try {
        $stmt = $db->prepare("SELECT COUNT(*) as attempt_count FROM login_attempts WHERE ip_address = :ip AND timestamp > DATE_SUB(NOW(), INTERVAL :lockout_interval MINUTE)");
        $lockout_minutes = $lockout_time / 60;
        $stmt->bindParam(':ip', $ip_address, PDO::PARAM_STR);
        $stmt->bindParam(':lockout_interval', $lockout_minutes, PDO::PARAM_INT);
        $stmt->execute();
        $result = $stmt->fetch();
        if ($result && $result['attempt_count'] >= $max_login_attempts) {
            $is_locked_out = true;
            $errors[] = 'Too many failed login attempts. Please try again later.';
        }
    } catch (PDOException $e) {
        error_log("Database Error (Login Attempts Check): " . $e->getMessage());
        // Decide how to handle DB error during lockout check (fail open/closed?)
        // For now, let's allow login attempt if DB check fails, but log it.
    }
}
// --- End Brute Force Check ---


// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$is_locked_out) {

    // 1. Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    }

    // 2. Verify reCAPTCHA
    if (getenv('RECAPTCHA_SITE_KEY')) {
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        if (empty($recaptcha_response)) {
            $errors[] = 'reCAPTCHA verification failed. Please complete the reCAPTCHA.';
        } else {
            $verification_result = verify_recaptcha_v2($recaptcha_response);
            if (!$verification_result) {
                $errors[] = 'reCAPTCHA verification failed. Please try again.';
            }
        }
    }

    // 3. Sanitize and retrieve inputs
    if (empty($errors)) {
        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'] ?? ''; // Don't sanitize password

        // 4. Validate inputs
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email format.';
        }
        if (empty($password)) {
            $errors[] = 'Password is required.';
        }
    }

    // 5. Attempt Login if no validation errors
    if (empty($errors)) {
        if ($db) {
            try {
                // Find user by email
                $stmt = $db->prepare("SELECT u.id, u.password, u.full_name, us.enable_2fa_telegram, us.enable_2fa_email, us.enable_2fa_fingerprint, us.notify_on_login
                                      FROM users u
                                      LEFT JOIN user_settings us ON u.id = us.user_id
                                      WHERE u.email = :email LIMIT 1");
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->execute();
                $user = $stmt->fetch();

                if ($user && verify_password($password, $user['password'])) {
                    // --- Login Successful ---

                    // Clear failed login attempts for this IP
                    try {
                        $stmt_clear = $db->prepare("DELETE FROM login_attempts WHERE ip_address = :ip");
                        $stmt_clear->bindParam(':ip', $ip_address, PDO::PARAM_STR);
                        $stmt_clear->execute();
                    } catch (PDOException $e) {
                        error_log("Database Error (Clearing Login Attempts): " . $e->getMessage());
                        // Non-fatal, continue login
                    }

                    // Check if any 2FA method is enabled
                    $two_fa_enabled = $user['enable_2fa_telegram'] || $user['enable_2fa_email'] || $user['enable_2fa_fingerprint'];

                    if ($two_fa_enabled) {
                        // --- Start 2FA Process ---
                        $_SESSION['2fa_user_id'] = $user['id'];
                        $_SESSION['2fa_methods'] = [];
                        if ($user['enable_2fa_telegram']) $_SESSION['2fa_methods'][] = 'telegram';
                        if ($user['enable_2fa_email']) $_SESSION['2fa_methods'][] = 'email';
                        if ($user['enable_2fa_fingerprint']) $_SESSION['2fa_methods'][] = 'fingerprint'; // Placeholder
                        $_SESSION['2fa_initiated_at'] = time(); // Timeout for 2FA process

                        redirect('verify_2fa.php'); // Redirect to 2FA verification page

                    } else {
                        // --- Complete Login (No 2FA) ---
                        session_regenerate_id(true); // Prevent session fixation

                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['user_fullname'] = $user['full_name']; // Store name for display
                        // Remove any potential leftover 2FA flags
                        unset($_SESSION['2fa_user_id'], $_SESSION['2fa_methods'], $_SESSION['2fa_initiated_at']);

                        // Log the successful login
                        // TODO: Add country and device type detection later
                        $user_agent = get_user_agent();
                        try {
                            $stmt_log = $db->prepare("INSERT INTO login_logs (user_id, ip_address, user_agent, country, device_type, timestamp) VALUES (:user_id, :ip, :ua, NULL, NULL, NOW())");
                            $stmt_log->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
                            $stmt_log->bindParam(':ip', $ip_address, PDO::PARAM_STR);
                            $stmt_log->bindParam(':ua', $user_agent, PDO::PARAM_STR);
                            $stmt_log->execute();
                        } catch (PDOException $e) {
                             error_log("Database Error (Login Log): " . $e->getMessage());
                             // Non-fatal
                        }

                        // Send login notification if enabled
                        if ($user['notify_on_login']) {
                            // TODO: Implement notification sending (check telegram_chat_id first, then email)
                            // $message = "Successful login detected from IP: $ip_address, User Agent: $user_agent";
                            // send_notification($user['id'], "Login Alert", $message);
                        }

                        redirect('dashboard.php'); // Redirect to the main dashboard
                    }

                } else {
                    // --- Login Failed (Invalid Email or Password) ---
                    $errors[] = 'Invalid email or password.';
                    // Record failed attempt
                    if ($ip_address !== 'UNKNOWN' && $ip_address !== 'INVALID_IP_FORMAT') {
                        try {
                            $stmt_fail = $db->prepare("INSERT INTO login_attempts (ip_address, email, timestamp) VALUES (:ip, :email, NOW())");
                            $stmt_fail->bindParam(':ip', $ip_address, PDO::PARAM_STR);
                            $stmt_fail->bindParam(':email', $email, PDO::PARAM_STR);
                            $stmt_fail->execute();
                        } catch (PDOException $e) {
                            error_log("Database Error (Login Attempt Log): " . $e->getMessage());
                        }
                    }
                }

                // Send failed login notification (if Telegram Chat ID is available)
                if ($user && !empty($user['telegram_chat_id'])) {
                    $message = "Failed login attempt detected for your account.\nIP Address: " . get_ip_address() . "\nTime: " . date('Y-m-d H:i:s');
                    send_telegram_message($user['telegram_chat_id'], $message);
                } elseif ($user) {
                    $message = "<p>Failed login attempt detected for your account.</p><p>IP Address: " . get_ip_address() . "</p><p>Time: " . date('Y-m-d H:i:s') . "</p>";
                    send_email($email, "Failed Login Attempt", $message);
                }

            } catch (PDOException $e) {
                error_log("Database Error (Login Process): " . $e->getMessage());
                $errors[] = 'An error occurred during login. Please try again later.';
            }
        } else {
            $errors[] = 'Database connection failed. Please try again later.';
        }
    }
    // If errors occurred, the script continues below to display the form with errors
}

?>

<h2>Login</h2>

<?php
// Display errors if any
if (!empty($errors)) {
    echo '<div class="error">';
    foreach ($errors as $error) {
        echo escape_html($error) . '<br>';
    }
    echo '</div>';
}
?>

<?php if (!$is_locked_out): // Only show form if not locked out ?>
<form action="login.php" method="post" id="login-form">
    <!-- CSRF Token -->
    <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
    <!-- reCAPTCHA Token -->
    <div class="g-recaptcha" data-sitekey="<?php echo escape_html(getenv('RECAPTCHA_SITE_KEY')); ?>"></div>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" value="<?php echo escape_html($email); ?>" required>
    </div>

    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
    </div>

    <button type="submit">Login</button>
</form>

<p>
    <a href="forgot_password.php">Forgot Password?</a> |
    <a href="register.php">Don't have an account? Register</a>
</p>

<?php endif; // End lockout check ?>

<?php
require_once __DIR__ . '/../includes/footer.php';
?>
