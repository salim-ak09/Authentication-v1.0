<?php
$page_title = 'Account Settings';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Authentication check
if (!is_logged_in()) {
    $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'You must be logged in to view this page.'];
    redirect('login.php');
}

$user_id = get_user_id();
$errors = [];
$success_message = '';
$db = getDbConnection();

// --- Fetch Current User Data ---
$user_data = null;
$user_settings = null;
$login_logs = [];
$ip_blacklist = [];
$country_blacklist = [];

if (!$db) {
    $errors[] = "Database connection failed. Cannot load settings.";
} else {
    try {
        // Fetch user profile data
        $stmt_user = $db->prepare("SELECT full_name, email, telegram_chat_id, fingerprint_data FROM users WHERE id = :user_id");
        $stmt_user->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_user->execute();
        $user_data = $stmt_user->fetch();

        // Fetch user settings
        $stmt_settings = $db->prepare("SELECT enable_2fa_telegram, enable_2fa_email, enable_2fa_fingerprint, notify_on_login FROM user_settings WHERE user_id = :user_id");
        $stmt_settings->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_settings->execute();
        $user_settings = $stmt_settings->fetch();
        // Ensure settings exist (might not if registration failed mid-way, though unlikely with transactions)
        if (!$user_settings) {
             // Create default settings if missing
             $stmt_insert_settings = $db->prepare("INSERT INTO user_settings (user_id) VALUES (:user_id) ON DUPLICATE KEY UPDATE user_id=user_id"); // Ignore if exists
             $stmt_insert_settings->bindParam(':user_id', $user_id, PDO::PARAM_INT);
             $stmt_insert_settings->execute();
             // Re-fetch
             $stmt_settings->execute();
             $user_settings = $stmt_settings->fetch();
        }


        // Fetch all login logs
        $stmt_logs = $db->prepare("SELECT id, ip_address, user_agent, country, device_type, timestamp FROM login_logs WHERE user_id = :user_id ORDER BY timestamp DESC");
        $stmt_logs->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_logs->execute();
        $login_logs = $stmt_logs->fetchAll();

        // Fetch IP blacklist
        $stmt_ip = $db->prepare("SELECT id, ip_address, created_at FROM ip_blacklist WHERE user_id = :user_id ORDER BY created_at DESC");
        $stmt_ip->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_ip->execute();
        $ip_blacklist = $stmt_ip->fetchAll();

        // Fetch Country blacklist
        $stmt_country = $db->prepare("SELECT id, country_code, created_at FROM country_blacklist WHERE user_id = :user_id ORDER BY created_at DESC");
        $stmt_country->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_country->execute();
        $country_blacklist = $stmt_country->fetchAll();

    } catch (PDOException $e) {
        error_log("Database Error (Settings Page Load): " . $e->getMessage());
        $errors[] = "Failed to load account data. Please try again later.";
        // Prevent further processing if essential data failed to load
        $user_data = $user_data ?: []; // Ensure arrays exist even if fetch failed
        $user_settings = $user_settings ?: [];
    }
}
// --- End Fetch Data ---


// --- Handle Form Submissions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($errors) && $db) { // Only process if DB connected and no load errors

    // Validate CSRF token for all POST requests
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';

        try {
            // --- Update Profile Action ---
            if ($action === 'update_profile' && $user_data) {
                $new_full_name = sanitize_input($_POST['full_name'] ?? '');
                $new_email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
                $new_telegram_id = sanitize_input($_POST['telegram_chat_id'] ?? '');
                // $new_fingerprint = $_POST['fingerprint_data'] ?? ''; // Needs specific handling

                // Validation
                if (empty($new_full_name)) $errors[] = 'Full Name cannot be empty.';
                if (empty($new_email) || !filter_var($new_email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid Email format.';
                if (!empty($new_telegram_id) && !ctype_digit(ltrim($new_telegram_id, '-'))) $errors[] = 'Invalid Telegram Chat ID format.';

                // Check if email changed and if it's already taken by another user
                if ($new_email !== $user_data['email']) {
                    $stmt_check_email = $db->prepare("SELECT id FROM users WHERE email = :email AND id != :user_id LIMIT 1");
                    $stmt_check_email->bindParam(':email', $new_email, PDO::PARAM_STR);
                    $stmt_check_email->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_check_email->execute();
                    if ($stmt_check_email->fetch()) {
                        $errors[] = 'That email address is already registered by another user.';
                    }
                    // Consider requiring email re-verification if email changes
                }

                if (empty($errors)) {
                    $stmt_update = $db->prepare("UPDATE users SET full_name = :name, email = :email, telegram_chat_id = :tg_id WHERE id = :user_id");
                    $telegram_param = !empty($new_telegram_id) ? $new_telegram_id : null;
                    $stmt_update->bindParam(':name', $new_full_name, PDO::PARAM_STR);
                    $stmt_update->bindParam(':email', $new_email, PDO::PARAM_STR);
                    $stmt_update->bindParam(':tg_id', $telegram_param, PDO::PARAM_STR);
                    $stmt_update->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_update->execute();
                    $success_message = 'Profile updated successfully.';
                    // Refresh data
                    $user_data['full_name'] = $new_full_name;
                    $user_data['email'] = $new_email;
                    $user_data['telegram_chat_id'] = $telegram_param;
                    $_SESSION['user_fullname'] = $new_full_name; // Update session name
                }
            }

            // --- Change Password Action ---
            elseif ($action === 'change_password' && $user_data) {
                $current_password = $_POST['current_password'] ?? '';
                $new_password = $_POST['new_password'] ?? '';
                $confirm_new_password = $_POST['confirm_new_password'] ?? '';

                // Fetch current hash to verify
                $stmt_pass = $db->prepare("SELECT password FROM users WHERE id = :user_id");
                $stmt_pass->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                $stmt_pass->execute();
                $current_hash = $stmt_pass->fetchColumn();

                if (!$current_hash || !verify_password($current_password, $current_hash)) {
                    $errors[] = 'Incorrect current password.';
                }
                if (empty($new_password) || strlen($new_password) < 8) {
                    $errors[] = 'New password must be at least 8 characters long.';
                }
                if ($new_password !== $confirm_new_password) {
                    $errors[] = 'New passwords do not match.';
                }

                if (empty($errors)) {
                    $new_hashed_password = hash_password($new_password);
                    $stmt_update = $db->prepare("UPDATE users SET password = :password WHERE id = :user_id");
                    $stmt_update->bindParam(':password', $new_hashed_password, PDO::PARAM_STR);
                    $stmt_update->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_update->execute();
                    $success_message = 'Password changed successfully.';
                    // Consider logging out other sessions or sending a notification
                }
            }

            // --- Update 2FA Settings Action ---
            elseif ($action === 'update_2fa' && $user_settings) {
                $enable_2fa_email = isset($_POST['enable_2fa_email']) ? 1 : 0;
                $enable_2fa_telegram = isset($_POST['enable_2fa_telegram']) ? 1 : 0;
                // $enable_2fa_fingerprint = isset($_POST['enable_2fa_fingerprint']) ? 1 : 0; // Needs fingerprint setup first

                // Validation: Cannot enable Telegram 2FA if no Telegram ID is set
                if ($enable_2fa_telegram && empty($user_data['telegram_chat_id'])) {
                    $errors[] = 'You must add a Telegram Chat ID to your profile before enabling Telegram 2FA.';
                } else {
                    $stmt_update = $db->prepare("UPDATE user_settings SET enable_2fa_email = :email, enable_2fa_telegram = :telegram WHERE user_id = :user_id");
                    $stmt_update->bindParam(':email', $enable_2fa_email, PDO::PARAM_INT);
                    $stmt_update->bindParam(':telegram', $enable_2fa_telegram, PDO::PARAM_INT);
                    // Add fingerprint binding here when implemented
                    $stmt_update->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_update->execute();
                    $success_message = 'Two-Factor Authentication settings updated.';
                    // Refresh settings data
                    $user_settings['enable_2fa_email'] = $enable_2fa_email;
                    $user_settings['enable_2fa_telegram'] = $enable_2fa_telegram;
                }
            }

            // --- Update Notification Settings Action ---
            elseif ($action === 'update_notifications' && $user_settings) {
                 $notify_on_login = isset($_POST['notify_on_login']) ? 1 : 0;

                 $stmt_update = $db->prepare("UPDATE user_settings SET notify_on_login = :notify WHERE user_id = :user_id");
                 $stmt_update->bindParam(':notify', $notify_on_login, PDO::PARAM_INT);
                 $stmt_update->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                 $stmt_update->execute();
                 $success_message = 'Notification settings updated.';
                 // Refresh settings data
                 $user_settings['notify_on_login'] = $notify_on_login;
            }

            // --- Add IP to Blacklist Action ---
            elseif ($action === 'add_ip_blacklist') {
                $ip_to_block = sanitize_input($_POST['ip_address'] ?? '');
                if (empty($ip_to_block) || filter_var($ip_to_block, FILTER_VALIDATE_IP) === false) {
                    $errors[] = 'Invalid IP address format.';
                } else {
                    // Check if already blacklisted
                    $stmt_check = $db->prepare("SELECT id FROM ip_blacklist WHERE user_id = :user_id AND ip_address = :ip");
                    $stmt_check->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_check->bindParam(':ip', $ip_to_block, PDO::PARAM_STR);
                    $stmt_check->execute();
                    if ($stmt_check->fetch()) {
                        $errors[] = 'This IP address is already blacklisted.';
                    } else {
                        $stmt_insert = $db->prepare("INSERT INTO ip_blacklist (user_id, ip_address, created_at) VALUES (:user_id, :ip, NOW())");
                        $stmt_insert->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                        $stmt_insert->bindParam(':ip', $ip_to_block, PDO::PARAM_STR);
                        $stmt_insert->execute();
                        $success_message = 'IP address blacklisted successfully.';
                        // Refresh blacklist data
                        $stmt_ip->execute(); // Re-run fetch query
                        $ip_blacklist = $stmt_ip->fetchAll();
                    }
                }
            }

             // --- Remove IP from Blacklist Action ---
            elseif ($action === 'remove_ip_blacklist') {
                $blacklist_id = filter_input(INPUT_POST, 'blacklist_id', FILTER_VALIDATE_INT);
                if (!$blacklist_id) {
                    $errors[] = 'Invalid blacklist entry ID.';
                } else {
                    $stmt_delete = $db->prepare("DELETE FROM ip_blacklist WHERE id = :id AND user_id = :user_id");
                    $stmt_delete->bindParam(':id', $blacklist_id, PDO::PARAM_INT);
                    $stmt_delete->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_delete->execute();
                    if ($stmt_delete->rowCount() > 0) {
                        $success_message = 'IP address removed from blacklist.';
                        // Refresh blacklist data
                        $stmt_ip->execute();
                        $ip_blacklist = $stmt_ip->fetchAll();
                    } else {
                        $errors[] = 'Could not find or remove the specified IP blacklist entry.';
                    }
                }
            }

            // --- Add Country to Blacklist Action ---
            elseif ($action === 'add_country_blacklist') {
                $country_to_block = strtoupper(sanitize_input($_POST['country_code'] ?? '')); // Expecting 2-letter code
                if (empty($country_to_block) || strlen($country_to_block) !== 2 || !ctype_alpha($country_to_block)) {
                    $errors[] = 'Invalid Country Code format (must be 2 letters, e.g., US, GB).';
                } else {
                     // Check if already blacklisted
                    $stmt_check = $db->prepare("SELECT id FROM country_blacklist WHERE user_id = :user_id AND country_code = :code");
                    $stmt_check->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_check->bindParam(':code', $country_to_block, PDO::PARAM_STR);
                    $stmt_check->execute();
                    if ($stmt_check->fetch()) {
                        $errors[] = 'This country is already blacklisted.';
                    } else {
                        $stmt_insert = $db->prepare("INSERT INTO country_blacklist (user_id, country_code, created_at) VALUES (:user_id, :code, NOW())");
                        $stmt_insert->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                        $stmt_insert->bindParam(':code', $country_to_block, PDO::PARAM_STR);
                        $stmt_insert->execute();
                        $success_message = 'Country blacklisted successfully.';
                        // Refresh blacklist data
                        $stmt_country->execute(); // Re-run fetch query
                        $country_blacklist = $stmt_country->fetchAll();
                    }
                }
            }

             // --- Remove Country from Blacklist Action ---
            elseif ($action === 'remove_country_blacklist') {
                $blacklist_id = filter_input(INPUT_POST, 'blacklist_id', FILTER_VALIDATE_INT);
                 if (!$blacklist_id) {
                    $errors[] = 'Invalid blacklist entry ID.';
                } else {
                    $stmt_delete = $db->prepare("DELETE FROM country_blacklist WHERE id = :id AND user_id = :user_id");
                    $stmt_delete->bindParam(':id', $blacklist_id, PDO::PARAM_INT);
                    $stmt_delete->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt_delete->execute();
                     if ($stmt_delete->rowCount() > 0) {
                        $success_message = 'Country removed from blacklist.';
                        // Refresh blacklist data
                        $stmt_country->execute();
                        $country_blacklist = $stmt_country->fetchAll();
                    } else {
                        $errors[] = 'Could not find or remove the specified country blacklist entry.';
                    }
                }
            }


        } catch (PDOException $e) {
            error_log("Database Error (Settings Page Update - Action: $action): " . $e->getMessage());
            $errors[] = "An error occurred while updating settings. Please try again later.";
        }
    }
    // Regenerate CSRF token after processing POST
    $csrf_token = generate_csrf_token();
}


// --- Display Page ---
?>

<h2>Account Settings</h2>

<?php
// Display errors/success messages
if (!empty($errors)) {
    echo '<div class="error" style="border: 1px solid red; padding: 10px; margin-bottom: 15px;">';
    foreach ($errors as $error) {
        echo escape_html($error) . '<br>';
    }
    echo '</div>';
}
if (!empty($success_message)) {
    echo '<div class="success" style="border: 1px solid green; padding: 10px; margin-bottom: 15px;">' . escape_html($success_message) . '</div>';
}
?>

<?php if (!$user_data || !$user_settings): ?>
    <p class="error">Could not load user data. Please try refreshing the page or contact support if the problem persists.</p>
<?php else: ?>

    <!-- Profile Information Section -->
    <section id="profile" class="settings-section">
        <h3>Profile Information</h3>
        <form action="settings.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
            <input type="hidden" name="action" value="update_profile">

            <div class="form-group">
                <label for="full_name">Full Name:</label>
                <input type="text" id="full_name" name="full_name" value="<?php echo escape_html($user_data['full_name']); ?>" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" value="<?php echo escape_html($user_data['email']); ?>" required>
            </div>
            <div class="form-group">
                <label for="telegram_chat_id">Telegram Chat ID (Optional):</label>
                <input type="text" id="telegram_chat_id" name="telegram_chat_id" value="<?php echo escape_html($user_data['telegram_chat_id'] ?? ''); ?>" placeholder="e.g., 123456789">
            </div>
            <!-- Fingerprint Management Placeholder -->
            <!-- <div class="form-group">
                <label>Fingerprint:</label>
                <?php if (!empty($user_data['fingerprint_data'])): ?>
                    <span>Registered</span> <button type="button">Remove</button>
                <?php else: ?>
                    <span>Not Registered</span> <button type="button">Register Fingerprint</button>
                <?php endif; ?>
                 <input type="hidden" name="fingerprint_data" value="...">
            </div> -->
            <button type="submit">Update Profile</button>
        </form>
    </section>

    <!-- Change Password Section -->
    <section id="password" class="settings-section" style="margin-top: 30px;">
        <h3>Change Password</h3>
        <form action="settings.php" method="post">
             <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
             <input type="hidden" name="action" value="change_password">
             <div class="form-group">
                <label for="current_password">Current Password:</label>
                <input type="password" id="current_password" name="current_password" required>
            </div>
             <div class="form-group">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required minlength="8">
            </div>
             <div class="form-group">
                <label for="confirm_new_password">Confirm New Password:</label>
                <input type="password" id="confirm_new_password" name="confirm_new_password" required>
            </div>
            <button type="submit">Change Password</button>
        </form>
    </section>

    <!-- 2FA Settings Section -->
    <section id="2fa" class="settings-section" style="margin-top: 30px;">
        <h3>Two-Factor Authentication (2FA)</h3>
        <form action="settings.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
            <input type="hidden" name="action" value="update_2fa">
            <div class="form-group">
                <input type="checkbox" id="enable_2fa_email" name="enable_2fa_email" value="1" <?php echo ($user_settings['enable_2fa_email'] ?? 0) ? 'checked' : ''; ?>>
                <label for="enable_2fa_email">Enable Email OTP Verification</label>
            </div>
             <div class="form-group">
                <input type="checkbox" id="enable_2fa_telegram" name="enable_2fa_telegram" value="1" <?php echo ($user_settings['enable_2fa_telegram'] ?? 0) ? 'checked' : ''; ?> <?php echo empty($user_data['telegram_chat_id']) ? 'disabled' : ''; ?>>
                <label for="enable_2fa_telegram">Enable Telegram Approval</label>
                 <?php if (empty($user_data['telegram_chat_id'])): ?>
                    <small>(Please add your Telegram Chat ID in the profile section first)</small>
                 <?php endif; ?>
            </div>
            <div class="form-group">
                <input type="checkbox" id="enable_2fa_fingerprint" name="enable_2fa_fingerprint" value="1" <?php echo ($user_settings['enable_2fa_fingerprint'] ?? 0) ? 'checked' : ''; ?> disabled>
                <label for="enable_2fa_fingerprint">Enable Fingerprint Verification</label>
                 <small>(Fingerprint verification not implemented)</small>
            </div>
            <p><small>Note: At least one 2FA method must be enabled if you turn any on. You will be prompted for verification via an enabled method upon login.</small></p>
            <button type="submit">Update 2FA Settings</button>
        </form>
    </section>

    <!-- Notification Settings Section -->
    <section id="notifications" class="settings-section" style="margin-top: 30px;">
        <h3>Notification Settings</h3>
         <form action="settings.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
            <input type="hidden" name="action" value="update_notifications">
             <div class="form-group">
                <input type="checkbox" id="notify_on_login" name="notify_on_login" value="1" <?php echo ($user_settings['notify_on_login'] ?? 0) ? 'checked' : ''; ?>>
                <label for="notify_on_login">Send notification (Telegram/Email) on successful login</label>
            </div>
            <button type="submit">Update Notification Settings</button>
        </form>
    </section>

    <!-- Login Logs Section -->
    <section id="login-logs" class="settings-section" style="margin-top: 30px;">
        <h3>Login History</h3>
        <?php if (!empty($login_logs)): ?>
            <table border="1" style="width:100%; border-collapse: collapse; margin-top:10px;">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                        <th>Action</th> <!-- For blacklisting IP -->
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($login_logs as $log): ?>
                        <tr>
                            <td><?php echo escape_html(date('Y-m-d H:i:s', strtotime($log['timestamp']))); ?></td>
                            <td><?php echo escape_html($log['ip_address']); ?></td>
                            <td><?php echo escape_html($log['user_agent']); ?></td>
                            <td>
                                <form action="settings.php#login-logs" method="post" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
                                    <input type="hidden" name="action" value="add_ip_blacklist">
                                    <input type="hidden" name="ip_address" value="<?php echo escape_html($log['ip_address']); ?>">
                                    <button type="submit" class="small-button" onclick="return confirm('Are you sure you want to blacklist this IP address? <?php echo escape_html($log['ip_address']); ?>');">Blacklist IP</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>No login history found.</p>
        <?php endif; ?>
    </section>

    <!-- IP Blacklist Section -->
    <section id="ip-blacklist" class="settings-section" style="margin-top: 30px;">
        <h3>IP Address Blacklist</h3>
        <p>Logins from these IP addresses will be blocked for your account.</p>
         <form action="settings.php#ip-blacklist" method="post" style="margin-bottom: 15px;">
            <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
            <input type="hidden" name="action" value="add_ip_blacklist">
            <div class="form-group" style="display: flex; align-items: center;">
                <label for="ip_address_to_block" style="margin-right: 10px; margin-bottom: 0;">IP Address:</label>
                <input type="text" id="ip_address_to_block" name="ip_address" required style="flex-grow: 1; margin-bottom: 0; margin-right: 10px;">
                <button type="submit">Add to Blacklist</button>
            </div>
        </form>
        <?php if (!empty($ip_blacklist)): ?>
             <table border="1" style="width:100%; border-collapse: collapse; margin-top:10px;">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Date Added</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ip_blacklist as $ip_entry): ?>
                        <tr>
                            <td><?php echo escape_html($ip_entry['ip_address']); ?></td>
                            <td><?php echo escape_html(date('Y-m-d H:i:s', strtotime($ip_entry['created_at']))); ?></td>
                            <td>
                                <form action="settings.php#ip-blacklist" method="post" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
                                    <input type="hidden" name="action" value="remove_ip_blacklist">
                                    <input type="hidden" name="blacklist_id" value="<?php echo escape_html($ip_entry['id']); ?>">
                                    <button type="submit" class="small-button-danger" onclick="return confirm('Are you sure you want to remove this IP from the blacklist?');">Remove</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>No IP addresses are currently blacklisted.</p>
        <?php endif; ?>
    </section>

     <!-- Country Blacklist Section -->
    <section id="country-blacklist" class="settings-section" style="margin-top: 30px;">
        <h3>Country Blacklist</h3>
        <p>Logins originating from these countries will be blocked for your account. (Requires IP-to-Country lookup during login - not yet implemented).</p>
         <form action="settings.php#country-blacklist" method="post" style="margin-bottom: 15px;">
            <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
            <input type="hidden" name="action" value="add_country_blacklist">
            <div class="form-group" style="display: flex; align-items: center;">
                <label for="country_code_to_block" style="margin-right: 10px; margin-bottom: 0;">Country Code (2 Letters):</label>
                <input type="text" id="country_code_to_block" name="country_code" required maxlength="2" pattern="[A-Za-z]{2}" title="Enter 2-letter country code (e.g., US, GB)" style="flex-grow: 1; margin-bottom: 0; margin-right: 10px; text-transform: uppercase;">
                <button type="submit">Add to Blacklist</button>
            </div>
        </form>
        <?php if (!empty($country_blacklist)): ?>
             <table border="1" style="width:100%; border-collapse: collapse; margin-top:10px;">
                <thead>
                    <tr>
                        <th>Country Code</th>
                        <th>Date Added</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($country_blacklist as $country_entry): ?>
                        <tr>
                            <td><?php echo escape_html($country_entry['country_code']); ?></td>
                            <td><?php echo escape_html(date('Y-m-d H:i:s', strtotime($country_entry['created_at']))); ?></td>
                            <td>
                                <form action="settings.php#country-blacklist" method="post" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
                                    <input type="hidden" name="action" value="remove_country_blacklist">
                                    <input type="hidden" name="blacklist_id" value="<?php echo escape_html($country_entry['id']); ?>">
                                    <button type="submit" class="small-button-danger" onclick="return confirm('Are you sure you want to remove this country from the blacklist?');">Remove</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>No countries are currently blacklisted.</p>
        <?php endif; ?>
    </section>

<?php endif; // End check for user_data/user_settings load ?>

<?php
require_once __DIR__ . '/../includes/footer.php';
?>
