<?php
// Ensure config is loaded (though typically included once at the start)
// If this file is included standalone, config might be missing.
if (!defined('DB_HOST')) {
    // Attempt to include config relative to this file's location
    $configPath = __DIR__ . '/../config/config.php';
    if (file_exists($configPath)) {
        require_once $configPath;
    } else {
        // Handle error: Config not found
        error_log("Database config constants not defined and config.php not found.");
        // You might want to die() or throw an exception in a real app
        // For now, define defaults to avoid immediate fatal errors, though connection will fail
        define('DB_HOST', 'localhost');
        define('DB_PORT', '3306');
        define('DB_DATABASE', 'auth_system');
        define('DB_USERNAME', 'root');
        define('DB_PASSWORD', '');
    }
}

/**
 * Establishes a database connection using PDO.
 *
 * @return PDO|null Returns a PDO connection object on success, or null on failure.
 */
function getDbConnection() {
    static $pdo = null; // Static variable to hold the connection

    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_DATABASE . ";charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Throw exceptions on errors
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // Fetch results as associative arrays
            PDO::ATTR_EMULATE_PREPARES   => false,                  // Use native prepared statements
        ];

        try {
            $pdo = new PDO($dsn, DB_USERNAME, DB_PASSWORD, $options);
        } catch (PDOException $e) {
            // Log the error securely, don't expose details to the user in production
            error_log("Database Connection Error: " . $e->getMessage());
            // Optionally: trigger_error("Database connection failed.", E_USER_ERROR);
            // Return null or handle the error as appropriate for your application
            return null;
        }
    }

    return $pdo;
}

// Example usage (optional, can be removed):
/*
$db = getDbConnection();
if ($db) {
    echo "Database connection successful!";
    // Perform queries here
} else {
    echo "Database connection failed.";
}
*/

?>
