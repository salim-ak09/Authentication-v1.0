<?php
// Start session and load core files
// config.php is included by session.php if needed
require_once __DIR__ . '/../core/session.php';
require_once __DIR__ . '/../core/functions.php';
require_once __DIR__ . '/../core/database.php'; // Include database connection function

// Generate CSRF token for forms
$csrf_token = generate_csrf_token();

// Get App URL and reCAPTCHA site key for use in HTML
$app_url = defined('APP_URL') ? rtrim(APP_URL, '/') : '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? escape_html($page_title) : 'Authentication System'; ?></title>
    <!-- Basic CSS (Consider creating a main.css file) -->
    <link rel="stylesheet" href="<?php echo escape_html($app_url); ?>/css/style.css"> <!-- Link to your CSS file -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        /* Basic inline styles for layout - move to style.css later */
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 900px; margin: auto; background-color: #f4f7f6; }
        .container { background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        nav { background: #333; color: #fff; padding: 10px 0; margin-bottom: 20px; }
        nav ul { list-style: none; padding: 0; text-align: center; }
        nav ul li { display: inline; margin: 0 15px; }
        nav ul li a { color: #fff; text-decoration: none; }
        .error { color: red; font-weight: bold; margin-bottom: 10px; }
        .success { color: green; font-weight: bold; margin-bottom: 10px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="email"], input[type="password"], input[type="submit"], button {
            width: 100%;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box; /* Include padding and border in element's total width and height */
        }
        input[type="submit"], button { background-color: #5cb85c; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover, button:hover { background-color: #4cae4c; }
        .form-group { margin-bottom: 15px; }
        .grecaptcha-badge { visibility: hidden; } /* Hide default badge if using custom trigger */
    </style>
</head>
<body>

<nav>
    <ul>
        <li><a href="<?php echo escape_html($app_url); ?>/index.php">Home</a></li>
        <?php if (is_logged_in()): ?>
            <li><a href="<?php echo escape_html($app_url); ?>/dashboard.php">Dashboard</a></li>
            <li><a href="<?php echo escape_html($app_url); ?>/settings.php">Settings</a></li>
            <li><a href="<?php echo escape_html($app_url); ?>/logout.php">Logout</a></li>
        <?php else: ?>
            <li><a href="<?php echo escape_html($app_url); ?>/login.php">Login</a></li>
            <li><a href="<?php echo escape_html($app_url); ?>/register.php">Register</a></li>
            <li><a href="<?php echo escape_html($app_url); ?>/forgot_password.php">Forgot Password</a></li>
        <?php endif; ?>
    </ul>
</nav>

<div class="container">
    <?php
    // Display session flash messages (if any)
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        $type = $message['type'] === 'success' ? 'success' : 'error'; // Default to error
        echo '<div class="' . $type . '">' . escape_html($message['text']) . '</div>';
        unset($_SESSION['flash_message']); // Clear the message after displaying
    }
    ?>
    <!-- Page content starts here -->
