<?php
// Ensure core files are loaded if needed (e.g., session for user ID)
if (session_status() == PHP_SESSION_NONE) {
    // Attempt to include session relative to this file's location
    $sessionPath = __DIR__ . '/session.php';
    if (file_exists($sessionPath)) {
        require_once $sessionPath; // This will also attempt to load config
    } else {
        error_log("Session not started and session.php not found from functions.php.");
        // Handle error appropriately
    }
}

/**
 * Basic input sanitization. Escapes HTML characters.
 *
 * @param string $data The input data.
 * @return string Sanitized data.
 */
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data); // Remove backslashes added by magic_quotes_gpc (if enabled, though deprecated)
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8'); // Convert special characters to HTML entities
    return $data;
}

/**
 * Wrapper for htmlspecialchars for consistency.
 *
 * @param string|null $string The string to escape.
 * @return string The escaped string.
 */
function escape_html($string) {
    return htmlspecialchars((string)$string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}


/**
 * Hashes a password using PHP's password_hash function.
 *
 * @param string $password The plain text password.
 * @return string The hashed password.
 */
function hash_password($password) {
    // PASSWORD_ARGON2ID is preferred if available (PHP 7.3+), otherwise BCRYPT
    $algo = PASSWORD_DEFAULT; // Usually BCRYPT, but can be ARGON2ID if server supports it
    if (defined('PASSWORD_ARGON2ID')) {
        $algo = PASSWORD_ARGON2ID;
    }
    return password_hash($password, $algo);
}

/**
 * Verifies a password against a hash.
 *
 * @param string $password The plain text password.
 * @param string $hash The hash to verify against.
 * @return bool True if the password matches the hash, false otherwise.
 */
function verify_password($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Generates a random numeric OTP (One-Time Password).
 *
 * @param int $length The desired length of the OTP.
 * @return string The generated OTP.
 */
function generate_otp($length = 6) {
    if ($length < 4) $length = 4; // Minimum length
    $min = pow(10, $length - 1);
    $max = pow(10, $length) - 1;
    try {
        return (string)random_int($min, $max); // Cryptographically secure random integer
    } catch (Exception $e) {
        // Fallback for environments where random_int might fail (less secure)
        return (string)mt_rand($min, $max);
    }
}

/**
 * Generates a secure random token.
 *
 * @param int $lengthBytes The number of bytes for the token (output length will be 2x).
 * @return string The generated token in hex format.
 */
function generate_token($lengthBytes = 32) {
    try {
        return bin2hex(random_bytes($lengthBytes));
    } catch (Exception $e) {
        // Fallback or error handling
        error_log("Failed to generate secure token: " . $e->getMessage());
        // Simple fallback (less secure)
        return bin2hex(openssl_random_pseudo_bytes($lengthBytes));
    }
}


/**
 * Gets the user's IP address, considering proxies.
 *
 * @return string The user's IP address or 'UNKNOWN' if not found.
 */
function get_ip_address() {
    // Check for shared internet/ISP IP
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    // Check for IPs passing through proxies
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    // Check for the remote address
    else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    }
    // Handle multiple IPs in HTTP_X_FORWARDED_FOR (take the first one)
    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }
    // Validate IP format (optional but recommended)
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return 'INVALID_IP_FORMAT'; // Or return 'UNKNOWN' or log an error
    }
    return $ip;
}

/**
 * Gets the user's browser User Agent string.
 *
 * @return string The User Agent string or 'UNKNOWN'.
 */
function get_user_agent() {
    return $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';
}

/**
 * Redirects the user to a specified URL.
 * Ensures the URL is relative to the application or within the APP_URL domain.
 *
 * @param string $url The relative path (e.g., '/login.php') or full URL within the app domain.
 */
function redirect($url) {
    // Ensure config is loaded for APP_URL
    if (!defined('APP_URL')) {
        $configPath = __DIR__ . '/../config/config.php';
        if (file_exists($configPath)) require_once $configPath;
        else define('APP_URL', ''); // Fallback
    }

    if (filter_var($url, FILTER_VALIDATE_URL)) {
        // If it's a full URL, check if it belongs to our app domain
        if (strpos($url, APP_URL) !== 0) {
            // Redirecting outside the app domain, potentially unsafe. Default to home.
            error_log("Redirect attempt to external URL blocked: " . $url);
            $location = APP_URL ?: '/'; // Redirect to base URL or root
        } else {
            $location = $url;
        }
    } else {
        // Assume it's a relative path, prepend APP_URL
        // Ensure no leading slash if APP_URL already has one, and add one if needed
        $location = rtrim(APP_URL, '/') . '/' . ltrim($url, '/');
    }

    header("Location: " . $location);
    exit(); // Stop script execution after redirect
}

/**
 * Checks if the user is currently logged in.
 * (Basic implementation, relies on a session variable set during login)
 *
 * @return bool True if logged in, false otherwise.
 */
function is_logged_in() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Gets the logged-in user's ID from the session.
 *
 * @return int|null The user ID if logged in, null otherwise.
 */
function get_user_id() {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Placeholder for sending email. Requires an email library (like PHPMailer) or mail().
 * Since composer is disallowed, we'll use mail() for now, but it's unreliable.
 *
 * @param string $to Recipient email address.
 * @param string $subject Email subject.
 * @param string $message Email body (HTML or plain text).
 * @param string $headers Additional email headers (e.g., From, Content-type).
 * @return bool True on success, false on failure.
 */
function send_email($to, $subject, $message, $additional_headers = '') {
    // Load PHPMailer classes (adjust path if needed)
    require_once __DIR__ . '/../lib/PHPMailer/src/Exception.php';
    require_once __DIR__ . '/../lib/PHPMailer/src/PHPMailer.php';
    require_once __DIR__ . '/../lib/PHPMailer/src/SMTP.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true); // Passing `true` enables exceptions

    try {
        //Server settings
        $mail->SMTPDebug = 0; // Enable verbose debug output (set to 2 for detailed debugging)
        $mail->isSMTP(); // Set mailer to use SMTP
        $mail->Host = getenv('SMTP_HOST'); // Specify main and backup SMTP servers
        $mail->SMTPAuth = true; // Enable SMTP authentication
        $mail->Username = getenv('SMTP_USERNAME'); // SMTP username
        $mail->Password = getenv('SMTP_PASSWORD'); // SMTP password
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS; // Enable TLS encryption, `ssl` also accepted
        $mail->Port = getenv('SMTP_PORT'); // TCP port to connect to

        //Recipients
        $mail->setFrom(getenv('SMTP_FROM_EMAIL'), getenv('SMTP_FROM_NAME'));
        $mail->addAddress($to); // Add a recipient

        //Content
        $mail->isHTML(true); // Set email format to HTML
        $mail->Subject = $subject;
        $mail->Body = $message;
        $mail->AltBody = strip_tags($message); // Plain text version for non-HTML mail clients

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("PHPMailer Error: " . $mail->ErrorInfo);
        error_log("PHPMailer Exception: " . $e->getMessage());
        error_log("PHPMailer To: " . $to);
        error_log("PHPMailer Subject: " . $subject);
        return false;
    }
}

/**
 * Placeholder for sending Telegram messages. Requires a Telegram Bot library or cURL calls.
 *
 * @param string $chat_id The recipient's Telegram Chat ID.
 * @param string $message The message text.
 * @param array|null $reply_markup Optional inline keyboard markup.
 * @return bool|string True on success, error message string on failure.
 */
function send_telegram_message($chat_id, $message, $reply_markup = null) {
    if (!defined('TELEGRAM_BOT_TOKEN') || empty(TELEGRAM_BOT_TOKEN)) {
        error_log("Telegram Bot Token is not configured.");
        return "Telegram Bot Token not configured.";
    }

    $bot_token = TELEGRAM_BOT_TOKEN;
    $api_url = "https://api.telegram.org/bot{$bot_token}/sendMessage";

    $params = [
        'chat_id' => $chat_id,
        'text' => $message,
        'parse_mode' => 'HTML' // Or 'MarkdownV2' if preferred
    ];

    if ($reply_markup !== null && is_array($reply_markup)) {
        $params['reply_markup'] = json_encode($reply_markup);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $api_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10); // 10 second timeout

    $response_json = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($curl_error) {
        error_log("Telegram cURL Error: " . $curl_error);
        return "cURL Error: " . $curl_error;
    }

    if ($http_code !== 200) {
        error_log("Telegram API Error: HTTP Code $http_code, Response: $response_json");
        $response_data = json_decode($response_json, true);
        return "API Error: " . ($response_data['description'] ?? 'Unknown error');
    }

    $response_data = json_decode($response_json, true);
    if (!$response_data || !isset($response_data['ok']) || !$response_data['ok']) {
        error_log("Telegram API Error: Response indicates failure. Response: $response_json");
        return "API Error: " . ($response_data['description'] ?? 'Unknown error');
    }

    return true; // Success
}

/**
 * Verifies a Google reCAPTCHA v2 response.
 *
 * @param string $response The reCAPTCHA response from the client-side.
 * @return bool True if verification is successful, false otherwise.
 */
function verify_recaptcha_v2($response) {
    if (!getenv('RECAPTCHA_SECRET_KEY')) {
        error_log("reCAPTCHA v2 Secret Key is not configured.");
        return false; // Cannot verify without secret key
    }
    if (empty($response)) {
        return false; // No response provided
    }

    $secret_key = getenv('RECAPTCHA_SECRET_KEY');
    $ip_address = get_ip_address();

    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret'   => $secret_key,
        'response' => $response,
        'remoteip' => $ip_address,
    ];

    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data),
            'timeout' => 5, // 5 second timeout
        ],
    ];
    $context  = stream_context_create($options);
    $response = @file_get_contents($url, false, $context); // Use @ to suppress warnings on failure

    if ($response === FALSE) {
        error_log("Failed to connect to reCAPTCHA verification server.");
        // Decide how to handle connection errors (fail open or closed?)
        // Failing closed (returning false) is generally safer for security.
        return false;
    }

    $result = json_decode($response, true);

    // Check for success
    if ($result && isset($result['success']) && $result['success'] == true) {
        return true;
    } else {
        // Log failure details if available
        $error_codes = isset($result['error-codes']) ? implode(', ', $result['error-codes']) : 'N/A';
        error_log("reCAPTCHA verification failed. Success: " . ($result['success'] ?? 'N/A') . ", Error Codes: $error_codes");
        return false;
    }
}

?>
