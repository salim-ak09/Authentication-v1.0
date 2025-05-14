<?php
// Ensure config is loaded if not already
if (!defined('SESSION_NAME')) {
    $configPath = __DIR__ . '/../config/config.php';
    if (file_exists($configPath)) {
        require_once $configPath;
    } else {
        error_log("Session config constants not defined and config.php not found.");
        // Define fallback defaults
        define('SESSION_NAME', 'PHPSESSID');
        // Assume HTTPS is not enforced if config is missing
        define('APP_URL', 'http://localhost');
    }
}

/**
 * Starts or resumes a session with secure settings.
 */
function start_secure_session() {
    // Prevent session fixation: Use a new session ID on login/privilege change
    // This function just starts the session, regeneration should happen elsewhere (e.g., post-login)

    $session_name = SESSION_NAME; // Defined in config.php
    $secure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'); // Use secure cookies if HTTPS
    $httponly = true; // Prevent JavaScript access to the session cookie

    // Get session cookie parameters
    $cookieParams = session_get_cookie_params();

    session_set_cookie_params(
        $cookieParams["lifetime"], // Keep original lifetime
        $cookieParams["path"],     // Keep original path
        $cookieParams["domain"],   // Keep original domain
        $secure,
        $httponly
    );

    // Set the session name
    session_name($session_name);

    // Start the session if not already started
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Optional: Regenerate session ID periodically to reduce hijacking risk
    // Be careful with AJAX requests if doing this frequently
    /*
    if (!isset($_SESSION['last_regen'])) {
        $_SESSION['last_regen'] = time();
    } elseif (time() - $_SESSION['last_regen'] > 1800) { // Regenerate every 30 minutes
        session_regenerate_id(true); // true = delete old session file
        $_SESSION['last_regen'] = time();
    }
    */
}

/**
 * Generates and stores a CSRF token in the session.
 *
 * @return string The generated CSRF token.
 */
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validates a submitted CSRF token against the one stored in the session.
 *
 * @param string $submitted_token The CSRF token submitted with the form.
 * @return bool True if the token is valid, false otherwise.
 */
function validate_csrf_token($submitted_token) {
    if (empty($_SESSION['csrf_token']) || empty($submitted_token)) {
        return false;
    }
    // Use hash_equals for timing attack resistance
    return hash_equals($_SESSION['csrf_token'], $submitted_token);
}

/**
 * Destroys the current session.
 */
function destroy_session() {
    // Unset all session variables
    $_SESSION = array();

    // Delete the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    // Destroy the session
    session_destroy();
}

// Start the session when this file is included
start_secure_session();

?>
