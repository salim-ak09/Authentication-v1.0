<?php
// Load session functions to destroy it properly
require_once __DIR__ . '/../core/session.php'; // This also starts the session if not started

// Check if this logout is cancelling a 2FA process
$is_cancelling_2fa = isset($_GET['cancel_2fa']) && $_GET['cancel_2fa'] == '1';

// Destroy the session data
destroy_session(); // This function handles unsetting $_SESSION, deleting cookie, and session_destroy()

// Start a new session briefly to set a flash message
start_secure_session();
if ($is_cancelling_2fa) {
    $_SESSION['flash_message'] = ['type' => 'info', 'text' => 'Login process cancelled.'];
} else {
    $_SESSION['flash_message'] = ['type' => 'success', 'text' => 'You have been successfully logged out.'];
}


// Redirect to login page
// Need to load functions for redirect if not already loaded by session.php
if (!function_exists('redirect')) {
    require_once __DIR__ . '/../core/functions.php';
}
redirect('login.php');
?>
