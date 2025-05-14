<?php
$page_title = 'Dashboard';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Authentication check: Redirect to login if not logged in
if (!is_logged_in()) {
    $_SESSION['flash_message'] = ['type' => 'error', 'text' => 'You must be logged in to view this page.'];
    redirect('login.php');
}

$user_id = get_user_id();
$user_fullname = $_SESSION['user_fullname'] ?? 'User'; // Get full name from session

$db = getDbConnection();
$login_logs = [];
$settings = [];

if ($db && $user_id) {
    try {
        // Fetch last 5 login logs for the user
        $stmt_logs = $db->prepare("SELECT ip_address, user_agent, country, device_type, timestamp FROM login_logs WHERE user_id = :user_id ORDER BY timestamp DESC LIMIT 5");
        $stmt_logs->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_logs->execute();
        $login_logs = $stmt_logs->fetchAll();

        // Fetch user settings (for display or quick info, full settings on settings.php)
        $stmt_settings = $db->prepare("SELECT enable_2fa_telegram, enable_2fa_email, enable_2fa_fingerprint, notify_on_login FROM user_settings WHERE user_id = :user_id");
        $stmt_settings->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt_settings->execute();
        $settings = $stmt_settings->fetch();

    } catch (PDOException $e) {
        error_log("Database Error (Dashboard): " . $e->getMessage());
        // Display a generic error on the page, but don't halt execution
        echo '<div class="error">Could not retrieve all dashboard data due to a database error.</div>';
    }
}

?>

<h2>Welcome to your Dashboard, <?php echo escape_html($user_fullname); ?>!</h2>

<p>This is your secure area. From here you can manage your account settings and view your activity.</p>

<div class="dashboard-section">
    <h3>Quick Info</h3>
    <ul>
        <li><strong>Email 2FA:</strong> <?php echo ($settings && $settings['enable_2fa_email']) ? '<span style="color:green;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></li>
        <li><strong>Telegram 2FA:</strong> <?php echo ($settings && $settings['enable_2fa_telegram']) ? '<span style="color:green;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></li>
        <!-- <li><strong>Fingerprint 2FA:</strong> <?php echo ($settings && $settings['enable_2fa_fingerprint']) ? '<span style="color:green;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></li> -->
        <li><strong>Login Notifications:</strong> <?php echo ($settings && $settings['notify_on_login']) ? '<span style="color:green;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></li>
    </ul>
    <p><a href="settings.php">Manage your settings</a></p>
</div>


<div class="dashboard-section">
    <h3>Recent Login Activity</h3>
    <?php if (!empty($login_logs)): ?>
        <table border="1" style="width:100%; border-collapse: collapse; margin-top:10px;">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>User Agent</th>
                    <!-- <th>Country</th> -->
                    <!-- <th>Device Type</th> -->
                </tr>
            </thead>
            <tbody>
                <?php foreach ($login_logs as $log): ?>
                    <tr>
                        <td><?php echo escape_html(date('Y-m-d H:i:s', strtotime($log['timestamp']))); ?></td>
                        <td><?php echo escape_html($log['ip_address']); ?></td>
                        <td><?php echo escape_html(substr($log['user_agent'], 0, 70)) . (strlen($log['user_agent']) > 70 ? '...' : ''); ?></td>
                        <!-- <td><?php echo escape_html($log['country'] ?? 'N/A'); ?></td> -->
                        <!-- <td><?php echo escape_html($log['device_type'] ?? 'N/A'); ?></td> -->
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p><a href="settings.php#login-logs">View all login logs</a></p>
    <?php else: ?>
        <p>No recent login activity found.</p>
    <?php endif; ?>
</div>

<p style="margin-top: 20px;">
    <a href="logout.php">Logout</a>
</p>

<?php
require_once __DIR__ . '/../includes/footer.php';
?>
