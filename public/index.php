<?php
$page_title = 'Welcome';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

?>

<h1>Welcome to the Secure Authentication System</h1>

<?php if (is_logged_in()): ?>
    <p>You are currently logged in as <?php echo escape_html($_SESSION['user_fullname'] ?? 'User'); ?>.</p>
    <p>
        <a href="dashboard.php" class="button">Go to Dashboard</a>
        <a href="settings.php" class="button">Account Settings</a>
        <a href="logout.php" class="button">Logout</a>
    </p>
<?php else: ?>
    <p>This system demonstrates a range of authentication features including registration, login, password recovery, two-factor authentication options, and security settings.</p>
    <p>Please log in or register to continue.</p>
    <p>
        <a href="login.php" class="button">Login</a>
        <a href="register.php" class="button">Register</a>
    </p>
<?php endif; ?>

<?php
require_once __DIR__ . '/../includes/footer.php';
?>
