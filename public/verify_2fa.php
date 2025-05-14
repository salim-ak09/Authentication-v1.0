<?php
$page_title = 'Verify Two-Factor Authentication';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Check if 2FA process was initiated
if (!isset($_SESSION['2fa_user_id']) || !isset($_SESSION['2fa_methods']) || empty($_SESSION['2fa_methods'])) {
    // If not in 2FA process, redirect away (e.g., to login)
    redirect('login.php');
}

// Check for 2FA timeout (e.g., 5 minutes)
$two_fa_timeout = 5 * 60; // seconds
if (isset($_SESSION['2fa_initiated_at']) && (time() - $_SESSION['2fa_initiated_at'] > $two_fa_timeout)) {
    // 2FA process timed out, clear session vars and redirect to login with error
    unset($_SESSION['2fa_user_id'], $_SESSION['2fa_methods'], $_SESSION['2fa_initiated_at'], $_SESSION['2fa_email_otp_sent']);
    $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'Two-factor authentication timed out. Please log in again.'];
    redirect('login.php');
}

$user_id = $_SESSION['2fa_user_id'];
$available_methods = $_SESSION['2fa_methods']; // e.g., ['email', 'telegram']
$errors = [];
$db = getDbConnection();

// --- Helper function to finalize login ---
function finalize_login($user_id, $db) {
    // Regenerate session ID
    session_regenerate_id(true);

    // Fetch user details needed for session
    try {
        $stmt_user = $db->prepare("SELECT full_name, notify_on_login FROM users u LEFT JOIN user_settings us ON u.id = us.user_id WHERE u.id = :id");
        $stmt_user->bindParam(':id', $user_id, PDO::PARAM_INT);
        $stmt_user->execute();
        $user = $stmt_user->fetch();
    } catch (PDOException $e) {
        error_log("Database Error (Fetching user details post-2FA): " . $e->getMessage());
        // Handle error - maybe redirect to login with generic error
        $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'An error occurred after verification. Please try again.'];
        redirect('login.php');
        return; // Should not be reached due to redirect
    }

    if (!$user) {
        // Should not happen if user_id was valid, but handle defensively
        $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'User not found after verification. Please try again.'];
        redirect('login.php');
        return;
    }

    // Set final session variables
    $_SESSION['user_id'] = $user_id;
    $_SESSION['user_fullname'] = $user['full_name'];

    // Clear 2FA session variables
    unset($_SESSION['2fa_user_id'], $_SESSION['2fa_methods'], $_SESSION['2fa_initiated_at'], $_SESSION['2fa_email_otp_sent'], $_SESSION['2fa_telegram_pending_secret']);

    // Log the successful login (similar to login.php, maybe refactor later)
    $ip_address = get_ip_address();
    $user_agent = get_user_agent();
    try {
        $stmt_log = $db->prepare("INSERT INTO login_logs (user_id, ip_address, user_agent, country, device_type, timestamp) VALUES (:user_id, :ip, :ua, NULL, NULL, NOW())");
        $stmt_log->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_log->bindParam(':ip', $ip_address, PDO::PARAM_STR);
        $stmt_log->bindParam(':ua', $user_agent, PDO::PARAM_STR);
        $stmt_log->execute();
    } catch (PDOException $e) {
         error_log("Database Error (Login Log post-2FA): " . $e->getMessage());
    }

    // Send login notification if enabled
    if ($user['notify_on_login']) {
        // TODO: Implement notification sending
    }

    // Redirect to dashboard
    redirect('dashboard.php');
}
// --- End Helper function ---


// --- Handle Email OTP Submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_email_otp'])) {
    // Validate CSRF
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } else {
        $submitted_otp = sanitize_input($_POST['email_otp'] ?? '');
        if (empty($submitted_otp)) {
            $errors[] = 'Please enter the OTP sent to your email.';
        } else {
            // Verify OTP against database
            if ($db) {
                try {
                    $stmt = $db->prepare("SELECT id FROM two_factor_auth WHERE user_id = :user_id AND method = 'email_otp' AND code = :code AND status = 'pending' AND expires_at > NOW()");
                    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt->bindParam(':code', $submitted_otp, PDO::PARAM_STR);
                    $stmt->execute();
                    $auth_entry = $stmt->fetch();

                    if ($auth_entry) {
                        // OTP Valid - Mark as approved and finalize login
                        $stmt_update = $db->prepare("UPDATE two_factor_auth SET status = 'approved' WHERE id = :id");
                        $stmt_update->bindParam(':id', $auth_entry['id'], PDO::PARAM_INT);
                        $stmt_update->execute();

                        echo "<script>console.log('User ID before finalize_login:', $user_id);</script>"; // Add this line
                        finalize_login($user_id, $db); // Function handles redirect on success

                    } else {
                        $errors[] = 'Invalid or expired OTP. Please try again.';
                        // Optional: Increment failure count for this 2FA attempt?
                    }
                } catch (PDOException $e) {
                    error_log("Database Error (Verifying Email OTP): " . $e->getMessage());
                    $errors[] = 'An error occurred verifying the OTP. Please try again later.';
                }
            } else {
                $errors[] = 'Database connection failed.';
            }
        }
    }
}
// --- End Handle Email OTP Submission ---


// --- Handle "Send Email OTP" Request (if not already sent) ---
if (in_array('email', $available_methods) && !isset($_SESSION['2fa_email_otp_sent'])) {
    if ($db) {
        try {
            // Get user's email
            $stmt_email = $db->prepare("SELECT email FROM users WHERE id = :id");
            $stmt_email->bindParam(':id', $user_id, PDO::PARAM_INT);
            $stmt_email->execute();
            $user_email = $stmt_email->fetchColumn();

            if ($user_email) {
                // Generate OTP
                $otp = generate_otp();
                $otp_expiry_minutes = 5; // OTP validity duration

                // Use the timezone from the .env or default to UTC
                $timezone = getenv('TIMEZONE') ?: 'UTC';

                try {
                    $now = new DateTime('now', new DateTimeZone($timezone));
                    $expires_at = clone $now;
                    $expires_at->modify("+{$otp_expiry_minutes} minutes");

                    $created_at = $now->format('Y-m-d H:i:s');
                    $expires_at_formatted = $expires_at->format('Y-m-d H:i:s');
                } catch (Exception $e) {
                    $created_at = date('Y-m-d H:i:s');
                    $expires_at_formatted = date('Y-m-d H:i:s', time() + ($otp_expiry_minutes * 60));
                }

                // Store OTP in database
                $stmt_insert = $db->prepare("INSERT INTO two_factor_auth (user_id, method, code, status, expires_at, created_at) VALUES (:user_id, 'email_otp', :code, 'pending', :expires_at, :created_at)");
                $stmt_insert->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                $stmt_insert->bindParam(':code', $otp, PDO::PARAM_STR);
                $stmt_insert->bindParam(':expires_at', $expires_at_formatted, PDO::PARAM_STR);
                $stmt_insert->bindParam(':created_at', $created_at, PDO::PARAM_STR);
                $stmt_insert->execute();

                // Send OTP via email
                $subject = "Your Login Verification Code";
                $message = "<p>Your verification code is: <strong>" . $otp . "</strong></p>";
                $message .= "<p>This code will expire in " . $otp_expiry_minutes . " minutes.</p>";
                if (send_email($user_email, $subject, $message)) {
                    $_SESSION['2fa_email_otp_sent'] = true; // Flag that OTP has been sent
                } else {
                    $errors[] = 'Failed to send OTP email. Please try again later or contact support.';
                    // Consider cleanup of the inserted DB record if email fails?
                }
            } else {
                $errors[] = 'Could not retrieve user email address.';
            }
        } catch (PDOException $e) {
            error_log("Database Error (Sending Email OTP): " . $e->getMessage());
            $errors[] = 'An error occurred preparing email verification. Please try again later.';
        }
    } else {
        $errors[] = 'Database connection failed.';
    }
}
// --- End Handle "Send Email OTP" Request ---


// --- Handle "Send Telegram Approval" Request (if not already sent) ---
// Note: This requires a callback handler (e.g., telegram_callback.php) to receive the button press from Telegram
if (in_array('telegram', $available_methods) && !isset($_SESSION['2fa_telegram_pending_secret'])) {
     if ($db) {
        try {
            // Get user's telegram chat id
            $stmt_tg = $db->prepare("SELECT telegram_chat_id FROM users WHERE id = :id");
            $stmt_tg->bindParam(':id', $user_id, PDO::PARAM_INT);
            $stmt_tg->execute();
            $chat_id = $stmt_tg->fetchColumn();

            if ($chat_id) {
                $secret = generate_token(16); // Shorter token for callback data
                $expiry_minutes = 5;
                
                // Use the timezone from the .env or default to UTC
                $timezone = getenv('TIMEZONE') ?: 'UTC';
                
                try {
                    $now = new DateTime('now', new DateTimeZone($timezone));
                    $expires_at = clone $now;
                    $expires_at->modify("+{$expiry_minutes} minutes");
                
                    $created_at = $now->format('Y-m-d H:i:s');
                    $expires_at_formatted = $expires_at->format('Y-m-d H:i:s');
                } catch (Exception $e) {
                    $created_at = date('Y-m-d H:i:s');
                    $expires_at_formatted = date('Y-m-d H:i:s', time() + ($expiry_minutes * 60));
                }
                
                // Store request in database
                $stmt_insert = $db->prepare("INSERT INTO two_factor_auth 
                    (user_id, method, secret, status, expires_at, created_at) 
                    VALUES (:user_id, 'telegram_approval', :secret, 'pending', :expires_at, :created_at)");
                
                $stmt_insert->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                $stmt_insert->bindParam(':secret', $secret, PDO::PARAM_STR);
                $stmt_insert->bindParam(':expires_at', $expires_at_formatted, PDO::PARAM_STR);
                $stmt_insert->bindParam(':created_at', $created_at, PDO::PARAM_STR);
                $stmt_insert->execute();
                
                $auth_id = $db->lastInsertId();
                

                // Prepare message and inline keyboard
                $ip_address = get_ip_address();
                $user_agent = get_user_agent(); // Consider shortening UA for message
                $message = "⚠️ Login attempt detected:\n";
                $message .= "IP: " . escape_html($ip_address) . "\n";
                $message .= "Time: " . date('Y-m-d H:i:s T') . "\n";
                // $message .= "Device: " . escape_html($user_agent) . "\n"; // Can be long
                $message .= "Please approve or deny this login attempt.";

                // Callback data format: action:auth_id:secret (e.g., approve:123:abcdef123456)
                $approve_callback = "approve:{$auth_id}:{$secret}";
                $cancel_callback = "cancel:{$auth_id}:{$secret}";
                $revoke_callback = "revoke:{$auth_id}:{$secret}"; // Revoke might mean block this session/IP? Needs definition.

                $reply_markup = [
                    'inline_keyboard' => [
                        [
                            ['text' => '✅ Approve', 'callback_data' => $approve_callback],
                            ['text' => '❌ Cancel', 'callback_data' => $cancel_callback],
                            // ['text' => '🚫 Revoke', 'callback_data' => $revoke_callback] // Define revoke action later
                        ]
                    ]
                ];

                // Send message via Telegram
                $send_result = send_telegram_message($chat_id, $message, $reply_markup);

                if ($send_result === true) {
                    $_SESSION['2fa_telegram_pending_secret'] = $secret; // Store secret to check against callback
                    // User needs to wait for Telegram interaction
                } else {
                    $errors[] = 'Failed to send Telegram approval request: ' . escape_html($send_result);
                    // Clean up DB record?
                }

            } else {
                $errors[] = 'Telegram Chat ID not found for this user.';
            }
        } catch (PDOException $e) {
            error_log("Database Error (Sending Telegram Approval): " . $e->getMessage());
            $errors[] = 'An error occurred preparing Telegram verification. Please try again later.';
        }
    } else {
        $errors[] = 'Database connection failed.';
    }
}
// --- End Handle "Send Telegram Approval" Request ---


// --- Handle Fingerprint (Placeholder) ---
if (in_array('fingerprint', $available_methods)) {
    // This requires significant client-side JavaScript integration with a WebAuthn library
    // or specific fingerprint reader hardware/SDK.
    // The flow would typically involve:
    // 1. Server generates a challenge.
    // 2. Client-side JS uses WebAuthn API (navigator.credentials.get()) with the challenge.
    // 3. User authenticates with fingerprint reader.
    // 4. Browser returns an assertion (signed challenge) to the client-side JS.
    // 5. Client-side JS sends the assertion to the server.
    // 6. Server verifies the assertion signature against the public key stored during registration.
    // 7. If valid, finalize login.
}
// --- End Handle Fingerprint ---


?>

<h2>Verify Your Identity</h2>
<p>An extra layer of security is required for your account.</p>

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

<?php // --- Display Email OTP Form --- ?>
<?php if (in_array('email', $available_methods)): ?>
    <div class="verification-method">
        <h3>Verify via Email OTP</h3>
        <?php if (isset($_SESSION['2fa_email_otp_sent'])): ?>
            <p>An OTP has been sent to your registered email address. Please enter it below.</p>
            <form action="verify_2fa.php" method="post" id="email-otp-form">
                <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
                <div class="form-group">
                    <label for="email_otp">Email OTP:</label>
                    <input type="text" id="email_otp" name="email_otp" required pattern="\d{6}" title="Enter the 6-digit code">
                </div>
                <button type="submit" name="verify_email_otp">Verify Email OTP</button>
            </form>
        <?php else: ?>
            <p>We need to send an OTP to your email address to verify your identity.</p>
            <!-- Optionally add a button to resend if needed, requires more logic -->
        <?php endif; ?>
    </div>
<?php endif; ?>


<?php // --- Display Telegram Info --- ?>
<?php if (in_array('telegram', $available_methods)): ?>
    <div class="verification-method" style="margin-top: 20px;">
        <h3>Verify via Telegram</h3>
        <?php if (isset($_SESSION['2fa_telegram_pending_secret'])): ?>
            <p>A login approval request has been sent to your registered Telegram account. Please check your Telegram app and click 'Approve'.</p>
            <p>Waiting for your response...</p>
            <p id="telegram-status">Status: Pending</p>
            <?php
            $telegram_secret = $_SESSION['2fa_telegram_pending_secret'];

            // --- Check Database ---
            $db = getDbConnection();
            if (!$db) {
                $errors[] = 'Database connection failed.';
            } else {
                try {
                    // Find the auth request matching the secret
                    $stmt = $db->prepare("SELECT status, expires_at FROM two_factor_auth
                                          WHERE secret = :secret
                                          AND method = 'telegram_approval'
                                          ORDER BY id DESC LIMIT 1"); // Get the latest entry for this secret
                    $stmt->bindParam(':secret', $telegram_secret, PDO::PARAM_STR);
                    $stmt->execute();
                    $auth_entry = $stmt->fetch();

                    if ($auth_entry) {
                        // Check if expired even if status is still pending
                        $timezone = getenv('TIMEZONE') ?: 'UTC';
                        $expires_at = new DateTime($auth_entry['expires_at'], new DateTimeZone($timezone));
                        $now = new DateTime('now', new DateTimeZone($timezone));

                        if ($auth_entry['status'] === 'pending' && $expires_at < $now) {
                            $status = 'expired';
                            // Optionally update the status in the DB to 'expired' here
                            $stmt_expire = $db->prepare("UPDATE two_factor_auth SET status = 'expired' WHERE secret = :secret AND status = 'pending'");
                            $stmt_expire->bindParam(':secret', $telegram_secret, PDO::PARAM_STR);
                            $stmt_expire->execute();
                        } else {
                            $status = $auth_entry['status']; // approved, cancelled, revoked, pending
                        }

                        if ($status === 'approved') {
                            finalize_login($user_id, $db);
                            exit(); // Prevent further execution after finalize_login
                        } elseif ($status === 'cancelled' || $status === 'expired' || $status === 'revoked') {
                            $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'Telegram verification failed.'];
                            redirect('login.php');
                        } else {
                            // Pending - Refresh the page after 10 seconds
                            header("Refresh: 10");
                            echo "<p>Status: Pending. Refreshing in 10 seconds...</p>";
                        }
                    } else {
                        $errors[] = 'Invalid Telegram secret.';
                    }

                } catch (PDOException $e) {
                    error_log("Telegram Status Check Error: " . $e->getMessage());
                    $errors[] = 'An error occurred checking Telegram status. Please try again later.';
                }
            }
            ?>
        <?php else: ?>
             <p>We need to send a login approval request to your Telegram account.</p>
             <!-- Message should have been sent automatically if this section is shown -->
        <?php endif; ?>
    </div>
<?php endif; ?>


<?php // --- Display Fingerprint Button (Placeholder) --- ?>
<?php if (in_array('fingerprint', $available_methods)): ?>
    <div class="verification-method" style="margin-top: 20px;">
        <h3>Verify via Fingerprint</h3>
        <p>Use your registered fingerprint to complete login.</p>
        <button type="button" id="verify-fingerprint-btn">Verify with Fingerprint</button>
        <span id="fingerprint-verify-status"></span>
        <!-- Add JS here to interact with WebAuthn API -->
        <script>
            document.getElementById('verify-fingerprint-btn')?.addEventListener('click', async () => {
                const statusEl = document.getElementById('fingerprint-verify-status');
                statusEl.textContent = 'Waiting for fingerprint...';
                try {
                    // 1. Fetch challenge from server
                    // const response = await fetch('get_webauthn_challenge.php?user_id=<?php echo $user_id; ?>');
                    // const challengeData = await response.json();
                    // if (!challengeData.success) throw new Error(challengeData.message);

                    // --- Placeholder ---
                    alert("Fingerprint verification requires client-side WebAuthn implementation.");
                    statusEl.textContent = 'Fingerprint verification not implemented.';
                    // --- End Placeholder ---


                    // 2. Use navigator.credentials.get() with challenge
                    // const credential = await navigator.credentials.get({ publicKey: challengeData.options });

                    // 3. Send assertion back to server for verification
                    // const verifyResponse = await fetch('verify_webauthn_assertion.php', {
                    //     method: 'POST',
                    //     headers: { 'Content-Type': 'application/json' },
                    //     body: JSON.stringify({ assertion: credential /* map fields correctly */ })
                    // });
                    // const verifyResult = await verifyResponse.json();

                    // if (verifyResult.success) {
                    //     statusEl.textContent = 'Fingerprint verified! Logging in...';
                    //     window.location.href = 'dashboard.php'; // Or let server handle redirect
                    // } else {
                    //     throw new Error(verifyResult.message || 'Fingerprint verification failed.');
                    // }

                } catch (err) {
                    console.error('Fingerprint verification error:', err);
                    statusEl.textContent = 'Error: ' + err.message;
                }
            });
        </script>
    </div>
<?php endif; ?>


<p style="margin-top: 30px;">
    <a href="logout.php?cancel_2fa=1">Cancel Login</a>
</p>


<?php
require_once __DIR__ . '/../includes/footer.php';
?>
