<?php
// Simple .env file loader
function loadEnv($path) {
    if (!file_exists($path)) {
        throw new Exception(".env file not found at path: " . $path);
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        // Skip comments
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);

        // Remove quotes if present
        if (strlen($value) > 1 && $value[0] == '"' && $value[strlen($value) - 1] == '"') {
            $value = substr($value, 1, -1);
        }
        if (strlen($value) > 1 && $value[0] == "'" && $value[strlen($value) - 1] == "'") {
            $value = substr($value, 1, -1);
        }

        if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
            putenv(sprintf('%s=%s', $name, $value));
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}

// Load the .env file from the project root
try {
    // __DIR__ is the 'config' directory, so go up one level
    loadEnv(__DIR__ . '/../.env');
} catch (Exception $e) {
    // Fallback or error handling if .env is missing
    // In a real application, you might want to die() or show a user-friendly error
    error_log("Error loading .env file: " . $e->getMessage());
    // Define defaults or handle the error appropriately
    // For now, we'll let it proceed, but database connection will likely fail
}

// Define constants or return config array
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_DATABASE', getenv('DB_DATABASE') ?: 'auth_system');
define('DB_USERNAME', getenv('DB_USERNAME') ?: 'root');
define('DB_PASSWORD', getenv('DB_PASSWORD') ?: '');

define('SMTP_HOST', getenv('SMTP_HOST') ?: '');
define('SMTP_PORT', getenv('SMTP_PORT') ?: '');
define('SMTP_USERNAME', getenv('SMTP_USERNAME') ?: '');
define('SMTP_PASSWORD', getenv('SMTP_PASSWORD') ?: '');
define('SMTP_FROM_EMAIL', getenv('SMTP_FROM_EMAIL') ?: '');
define('SMTP_FROM_NAME', getenv('SMTP_FROM_NAME') ?: '');

define('TELEGRAM_BOT_TOKEN', getenv('TELEGRAM_BOT_TOKEN') ?: '');

define('RECAPTCHA_V3_SITE_KEY', getenv('RECAPTCHA_V3_SITE_KEY') ?: '');
define('RECAPTCHA_V3_SECRET_KEY', getenv('RECAPTCHA_V3_SECRET_KEY') ?: '');

define('APP_URL', getenv('APP_URL') ?: 'http://localhost');
define('SESSION_NAME', getenv('SESSION_NAME') ?: 'PHPSESSID'); // Default PHP session name

// Basic security headers (can be expanded)
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://www.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self' https://www.google.com;"); // Added reCAPTCHA domains
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Error reporting (adjust for production)
error_reporting(E_ALL);
ini_set('display_errors', 1); // Set to 0 in production

// Timezone
date_default_timezone_set('UTC'); // Set your preferred timezone

?>
