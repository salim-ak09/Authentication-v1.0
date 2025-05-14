<?php
$page_title = 'Forgot Password';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Redirect if already logged in
if (is_logged_in()) {
    redirect('dashboard.php');
}

$step = $_SESSION['forgot_password_step'] ?? 1;
$errors = [];
$success_message = '';
$db = getDbConnection();
$user_id_for_reset = $_SESSION['forgot_password_user_id'] ?? null;
$reset_method = $_SESSION['forgot_password_method'] ?? null;

// --- Step 1: Select Method ---
if ($step === 1 && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['select_method'])) {
    // Validate CSRF
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } else {
        $method = $_POST['method'] ?? '';
        if ($method === 'email' || $method === 'telegram') {
            $_SESSION['forgot_password_step'] = 2;
            $_SESSION['forgot_password_method'] = $method;
            // Regenerate CSRF token for the next step
            generate_csrf_token();
            redirect('forgot_password.php'); // Redirect to reload for step 2
        } else {
            $errors[] = 'Please select a valid recovery method.';
        }
    }
}

// --- Step 2: Enter Identifier & Send OTP/Token ---
if ($step === 2 && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_code'])) {
    // Validate CSRF
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } else {
        $identifier = sanitize_input($_POST['identifier'] ?? '');
        $method = $_SESSION['forgot_password_method'];

        if (empty($identifier)) {
            $errors[] = ($method === 'email') ? 'Please enter your email address.' : 'Please enter your Telegram Chat ID.';
        } else {
            if (!$db) {
                $errors[] = 'Database connection failed.';
            } else {
                try {
                    // Find user by email or telegram_chat_id
                    $column = ($method === 'email') ? 'email' : 'telegram_chat_id';
                    $stmt = $db->prepare("SELECT id, email, telegram_chat_id, full_name FROM users WHERE {$column} = :identifier LIMIT 1");
                    $stmt->bindParam(':identifier', $identifier, PDO::PARAM_STR);
                    $stmt->execute();
                    $user = $stmt->fetch();

                    if ($user) {
                        // User found, generate OTP and token
                        $user_id_for_reset = $user['id'];
                        $otp = generate_otp();
                        $token = generate_token(); // Secure token for URL/hidden field if needed, OTP is primary here
                        $expiry_minutes = 15;
                        $expires_at = date('Y-m-d H:i:s', time() + ($expiry_minutes * 60));

                        // Store reset request (overwrite previous for this user/method if any)
                        $stmt_delete = $db->prepare("DELETE FROM password_resets WHERE user_id = :user_id AND method = :method");
                        $stmt_delete->bindParam(':user_id', $user_id_for_reset, PDO::PARAM_INT);
                        $stmt_delete->bindParam(':method', $method, PDO::PARAM_STR);
                        $stmt_delete->execute();

                        $stmt_insert = $db->prepare("INSERT INTO password_resets (user_id, method, token, otp, expires_at, created_at) VALUES (:user_id, :method, :token, :otp, :expires_at, NOW())");
                        $stmt_insert->bindParam(':user_id', $user_id_for_reset, PDO::PARAM_INT);
                        $stmt_insert->bindParam(':method', $method, PDO::PARAM_STR);
                        $stmt_insert->bindParam(':token', $token, PDO::PARAM_STR);
                        $stmt_insert->bindParam(':otp', $otp, PDO::PARAM_STR);
                        $stmt_insert->bindParam(':expires_at', $expires_at, PDO::PARAM_STR);
                        $stmt_insert->execute();

                        // Send OTP
                        $subject = "Password Reset Code";
                        $message_body = "<p>Hello " . escape_html($user['full_name']) . ",</p>";
                        $message_body .= "<p>Your password reset code is: <strong>" . $otp . "</strong></p>";
                        $message_body .= "<p>This code will expire in " . $expiry_minutes . " minutes. If you did not request this reset, please ignore this message.</p>";
                        $sent = false;
                        if ($method === 'email') {
                            $sent = send_email($user['email'], $subject, $message_body);
                        } elseif ($method === 'telegram' && $user['telegram_chat_id']) {
                            $sent = send_telegram_message($user['telegram_chat_id'], strip_tags($message_body)); // Send plain text to Telegram
                        }

                        if ($sent) {
                            $_SESSION['forgot_password_step'] = 3;
                            $_SESSION['forgot_password_user_id'] = $user_id_for_reset; // Store user ID for next steps
                            // Regenerate CSRF token
                            generate_csrf_token();
                            redirect('forgot_password.php'); // Redirect to reload for step 3
                        } else {
                            $errors[] = "Failed to send the reset code via {$method}. Please try again later or contact support.";
                        }

                    } else {
                        $errors[] = ($method === 'email') ? 'No account found with that email address.' : 'No account found with that Telegram Chat ID.';
                    }
                } catch (PDOException $e) {
                    error_log("Database Error (Forgot Password Step 2): " . $e->getMessage());
                    $errors[] = 'An error occurred. Please try again later.';
                }
            }
        }
    }
}

// --- Step 3: Confirm OTP ---
if ($step === 3 && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_otp'])) {
     // Validate CSRF
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } elseif (!$user_id_for_reset || !$reset_method) {
        $errors[] = 'Session expired or invalid state. Please start over.';
        // Reset session state
        unset($_SESSION['forgot_password_step'], $_SESSION['forgot_password_user_id'], $_SESSION['forgot_password_method']);
    } else {
        $submitted_otp = sanitize_input($_POST['otp'] ?? '');
        if (empty($submitted_otp)) {
            $errors[] = 'Please enter the OTP.';
        } else {
            if (!$db) {
                $errors[] = 'Database connection failed.';
            } else {
                try {
                    // Verify OTP against the stored value for the user and method
                    $stmt = $db->prepare("SELECT id FROM password_resets WHERE user_id = :user_id AND method = :method AND otp = :otp AND expires_at > NOW()");
                    $stmt->bindParam(':user_id', $user_id_for_reset, PDO::PARAM_INT);
                    $stmt->bindParam(':method', $reset_method, PDO::PARAM_STR);
                    $stmt->bindParam(':otp', $submitted_otp, PDO::PARAM_STR);
                    $stmt->execute();
                    $reset_entry = $stmt->fetch();

                    if ($reset_entry) {
                        // OTP Correct! Move to step 4
                        $_SESSION['forgot_password_step'] = 4;
                        $_SESSION['forgot_password_otp_verified'] = true; // Flag that OTP is verified
                        // Regenerate CSRF token
                        generate_csrf_token();
                        redirect('forgot_password.php'); // Redirect to reload for step 4
                    } else {
                        $errors[] = 'Invalid or expired OTP. Please try again.';
                    }
                } catch (PDOException $e) {
                    error_log("Database Error (Forgot Password Step 3): " . $e->getMessage());
                    $errors[] = 'An error occurred verifying the OTP. Please try again later.';
                }
            }
        }
    }
}

// --- Step 4: Set New Password ---
if ($step === 4 && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_new_password'])) {
    // Validate CSRF
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } elseif (!$user_id_for_reset || !isset($_SESSION['forgot_password_otp_verified']) || !$_SESSION['forgot_password_otp_verified']) {
        $errors[] = 'Session expired or invalid state. Please start the password reset process over.';
        // Reset session state
        unset($_SESSION['forgot_password_step'], $_SESSION['forgot_password_user_id'], $_SESSION['forgot_password_method'], $_SESSION['forgot_password_otp_verified']);
    } else {
        $new_password = $_POST['new_password'] ?? '';
        $confirm_new_password = $_POST['confirm_new_password'] ?? '';

        // Validate passwords
        if (empty($new_password)) {
            $errors[] = 'New Password is required.';
        } elseif (strlen($new_password) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
        }
        if ($new_password !== $confirm_new_password) {
            $errors[] = 'Passwords do not match.';
        }

        if (empty($errors)) {
            if (!$db) {
                $errors[] = 'Database connection failed.';
            } else {
                try {
                    // Hash the new password
                    $hashed_password = hash_password($new_password);

                    // Update user's password
                    $stmt_update = $db->prepare("UPDATE users SET password = :password WHERE id = :user_id");
                    $stmt_update->bindParam(':password', $hashed_password, PDO::PARAM_STR);
                    $stmt_update->bindParam(':user_id', $user_id_for_reset, PDO::PARAM_INT);
                    $stmt_update->execute();

                    // Delete the used password reset entry
                    $stmt_delete = $db->prepare("DELETE FROM password_resets WHERE user_id = :user_id");
                    $stmt_delete->bindParam(':user_id', $user_id_for_reset, PDO::PARAM_INT);
                    $stmt_delete->execute();

                    // Clear session state
                    unset($_SESSION['forgot_password_step'], $_SESSION['forgot_password_user_id'], $_SESSION['forgot_password_method'], $_SESSION['forgot_password_otp_verified']);

                    // Set success message and redirect to login
                    $_SESSION['flash_message'] = ['type' => 'success', 'text' => 'Your password has been successfully reset. Please log in with your new password.'];
                    redirect('login.php');

                } catch (PDOException $e) {
                    error_log("Database Error (Forgot Password Step 4): " . $e->getMessage());
                    $errors[] = 'An error occurred updating your password. Please try again later.';
                }
            }
        }
    }
}

// --- Cancel / Start Over ---
if (isset($_GET['cancel'])) {
    unset($_SESSION['forgot_password_step'], $_SESSION['forgot_password_user_id'], $_SESSION['forgot_password_method'], $_SESSION['forgot_password_otp_verified']);
    redirect('login.php');
}

// Regenerate CSRF token if not already done by a redirect
$csrf_token = generate_csrf_token();
?>

<h2>Forgot Password - Step <?php echo (int)$step; ?> of 4</h2>

<?php
// Display errors/success messages
if (!empty($errors)) {
    echo '<div class="error">';
    foreach ($errors as $error) {
        echo escape_html($error) . '<br>';
    }
    echo '</div>';
}
if (!empty($success_message)) {
    echo '<div class="success">' . escape_html($success_message) . '</div>';
}
?>

<?php // --- Step 1 Form: Select Method --- ?>
<?php if ($step === 1): ?>
    <p>How would you like to receive your password reset code?</p>
    <form action="forgot_password.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
        <div class="form-group">
            <input type="radio" id="method_email" name="method" value="email" required checked>
            <label for="method_email">Email</label>
        </div>
        <div class="form-group">
            <input type="radio" id="method_telegram" name="method" value="telegram" required>
            <label for="method_telegram">Telegram (if registered)</label>
        </div>
        <button type="submit" name="select_method">Continue</button>
    </form>
<?php endif; ?>


<?php // --- Step 2 Form: Enter Identifier --- ?>
<?php if ($step === 2 && $reset_method): ?>
    <p>Please enter your <?php echo ($reset_method === 'email') ? 'email address' : 'Telegram Chat ID'; ?> to receive a reset code.</p>
    <form action="forgot_password.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
        <div class="form-group">
            <label for="identifier"><?php echo ($reset_method === 'email') ? 'Email Address:' : 'Telegram Chat ID:'; ?></label>
            <input type="<?php echo ($reset_method === 'email') ? 'email' : 'text'; ?>" id="identifier" name="identifier" required>
        </div>
        <button type="submit" name="send_code">Send Reset Code</button>
    </form>
<?php endif; ?>


<?php // --- Step 3 Form: Confirm OTP --- ?>
<?php if ($step === 3 && $user_id_for_reset && $reset_method): ?>
    <p>A reset code has been sent via <?php echo escape_html($reset_method); ?>. Please enter the code below.</p>
    <form action="forgot_password.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
        <div class="form-group">
            <label for="otp">Reset Code (OTP):</label>
            <input type="text" id="otp" name="otp" required pattern="\d{6}" title="Enter the 6-digit code">
        </div>
        <button type="submit" name="verify_otp">Verify Code</button>
    </form>
<?php endif; ?>


<?php // --- Step 4 Form: Set New Password --- ?>
<?php if ($step === 4 && $user_id_for_reset && isset($_SESSION['forgot_password_otp_verified']) && $_SESSION['forgot_password_otp_verified']): ?>
    <p>OTP verified. Please enter your new password below.</p>
    <form action="forgot_password.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
        <div class="form-group">
            <label for="new_password">New Password:</label>
            <input type="password" id="new_password" name="new_password" required minlength="8">
        </div>
        <div class="form-group">
            <label for="confirm_new_password">Confirm New Password:</label>
            <input type="password" id="confirm_new_password" name="confirm_new_password" required>
        </div>
        <button type="submit" name="set_new_password">Reset Password</button>
    </form>
<?php endif; ?>

<p style="margin-top: 20px;">
    <?php if ($step > 1): ?>
        <a href="forgot_password.php?cancel=1">Cancel and return to Login</a>
    <?php else: ?>
        <a href="login.php">Return to Login</a>
    <?php endif; ?>
</p>


<?php
require_once __DIR__ . '/../includes/footer.php';
?>
