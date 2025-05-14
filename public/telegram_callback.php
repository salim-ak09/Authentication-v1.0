<?php
// This script handles callbacks from Telegram inline keyboards.
// It should be set as the webhook URL for your Telegram bot, OR Telegram polls for updates if no webhook is set.
// For simplicity here, we assume Telegram sends POST requests to this URL upon button clicks.

// Load necessary files
require_once __DIR__ . '/../config/config.php'; // For DB creds, Bot Token
require_once __DIR__ . '/../core/database.php';
require_once __DIR__ . '/../core/functions.php'; // For send_telegram_message (to answer callback)
require_once __DIR__ . '/../core/session.php'; // For session handling if needed

// We don't start the session here as this is a webhook callback from Telegram
// and doesn't need to access the user's session directly

// --- Get Callback Data ---
$callback_data_json = file_get_contents('php://input');
if (!$callback_data_json) {
    http_response_code(400); // Bad Request
    error_log("Telegram Callback: No input data received.");
    exit('No input data.');
}

$callback_update = json_decode($callback_data_json, true);
if (!$callback_update || !isset($callback_update['callback_query'])) {
    http_response_code(400); // Bad Request
    error_log("Telegram Callback: Invalid JSON or missing callback_query. Data: " . $callback_data_json);
    exit('Invalid data.');
}

$callback_query = $callback_update['callback_query'];
$callback_query_id = $callback_query['id'];
$callback_data = $callback_query['data'] ?? null; // e.g., "approve:123:abcdef123456"
$chat_id = $callback_query['message']['chat']['id'] ?? null;
$message_id = $callback_query['message']['message_id'] ?? null;
$user_id_from_telegram = $callback_query['from']['id'] ?? null; // Telegram user ID of the person who clicked

// --- Basic Logging ---
error_log("Telegram Callback Received: Query ID=$callback_query_id, Data=$callback_data, ChatID=$chat_id, UserID=$user_id_from_telegram");

// --- Input Validation ---
if (empty($callback_data) || empty($callback_query_id) || empty($chat_id) || empty($message_id)) {
     error_log("Telegram Callback: Missing essential callback parameters.");
     // Answer callback to prevent infinite loading in Telegram, but indicate error
     answer_telegram_callback($callback_query_id, "Error: Invalid callback data received.");
     exit('Missing parameters.');
}

// --- Parse Callback Data ---
$parts = explode(':', $callback_data, 3);
if (count($parts) !== 3) {
    error_log("Telegram Callback: Invalid callback_data format: " . $callback_data);
    answer_telegram_callback($callback_query_id, "Error: Invalid action format.");
    exit('Invalid action format.');
}
list($action, $auth_id, $secret) = $parts;

// Validate action
$allowed_actions = ['approve', 'cancel', 'revoke']; // Add revoke later if needed
if (!in_array($action, $allowed_actions)) {
    error_log("Telegram Callback: Invalid action: " . $action);
    answer_telegram_callback($callback_query_id, "Error: Unknown action.");
    exit('Invalid action.');
}

// Validate auth_id (should be numeric)
if (!ctype_digit($auth_id)) {
     error_log("Telegram Callback: Invalid auth_id: " . $auth_id);
     answer_telegram_callback($callback_query_id, "Error: Invalid request identifier.");
     exit('Invalid auth ID.');
}

// --- Process Action ---
$db = getDbConnection();
error_log("Telegram Callback: auth_id = " . $auth_id . ", secret = " . $secret); // ADDED LOGGING
if (!$db) {
    error_log("Telegram Callback: Database connection failed.");
    answer_telegram_callback($callback_query_id, "Error: Internal server error. Please try again later.");
    exit('DB connection failed.');
}

try {
    // Find the pending auth request matching the ID and secret
    $stmt = $db->prepare("SELECT id, user_id, status FROM two_factor_auth WHERE id = :auth_id AND method = 'telegram_approval' AND secret = :secret AND expires_at > NOW()");
    $stmt->bindParam(':auth_id', $auth_id, PDO::PARAM_INT);
    $stmt->bindParam(':secret', $secret, PDO::PARAM_STR);
    $stmt->execute();
    $auth_entry = $stmt->fetch();

    if (!$auth_entry) {
        error_log("Telegram Callback: No matching pending auth entry found for ID=$auth_id, Secret=$secret");
        answer_telegram_callback($callback_query_id, "Request not found or expired.");
        // Optionally edit the original message to indicate expiry/invalidity
        edit_telegram_message($chat_id, $message_id, "This login request has expired or is invalid.");
        exit('Auth entry not found or expired.');
    }

    // Check if already processed
    if ($auth_entry['status'] !== 'pending') {
        error_log("Telegram Callback: Auth entry ID=$auth_id already processed with status: " . $auth_entry['status']);
        answer_telegram_callback($callback_query_id, "This request has already been " . $auth_entry['status'] . ".");
        // Optionally edit the original message
        edit_telegram_message($chat_id, $message_id, "Login request already " . $auth_entry['status'] . ".");
        exit('Already processed.');
    }

    // --- Update Status Based on Action ---
    $new_status = null;
    $callback_response_text = '';
    $message_edit_text = '';

    switch ($action) {
        case 'approve':
            $new_status = 'approved';
            $callback_response_text = 'Login Approved!';
            $message_edit_text = "✅ Login Approved by user.";
            break;
        case 'cancel':
            $new_status = 'cancelled';
            $callback_response_text = 'Login Cancelled.';
            $message_edit_text = "❌ Login Cancelled by user.";
            break;
        case 'revoke': // Define revoke logic later
            $new_status = 'revoked';
            $callback_response_text = 'Login Revoked (Action Pending).';
            $message_edit_text = "🚫 Login Revoked by user (Further action may be needed).";
            // TODO: Implement revoke logic (e.g., block IP, invalidate session if possible)
            break;
    }

    if ($new_status) {
        // Update the status in the database
        $stmt_update = $db->prepare("UPDATE two_factor_auth SET status = :status WHERE id = :id");
        $stmt_update->bindParam(':status', $new_status, PDO::PARAM_STR);
        $stmt_update->bindParam(':id', $auth_id, PDO::PARAM_INT);
        $stmt_update->execute();

        // Double-check that the update was successful
        $stmt_check = $db->prepare("SELECT status FROM two_factor_auth WHERE id = :id");
        $stmt_check->bindParam(':id', $auth_id, PDO::PARAM_INT);
        $stmt_check->execute();
        $updated_status = $stmt_check->fetchColumn();

        // Log the result
        error_log("Telegram Callback: Updated status for auth ID=$auth_id. New status in DB: $updated_status");

        // Respond to Telegram
        answer_telegram_callback($callback_query_id, $callback_response_text);

        // Edit the original message to remove buttons and show status
        edit_telegram_message($chat_id, $message_id, $message_edit_text);

        error_log("Telegram Callback: Processed action '$action' for auth ID=$auth_id. New status: $new_status.");
        echo "OK"; // Respond to the webhook request itself

    } else {
        // Should not happen if action is validated
        answer_telegram_callback($callback_query_id, "Error: Could not process action.");
        exit('Could not process action.');
    }

} catch (PDOException $e) {
    error_log("Telegram Callback: Database Error: " . $e->getMessage());
    answer_telegram_callback($callback_query_id, "Error: Internal server error processing request.");
    exit('Database error.');
} catch (Exception $e) {
    error_log("Telegram Callback: General Error: " . $e->getMessage());
    answer_telegram_callback($callback_query_id, "Error: An unexpected error occurred.");
    exit('General error.');
}


/**
 * Sends an answer to a Telegram callback query.
 *
 * @param string $callback_query_id
 * @param string $text Text to show to the user (notification or alert)
 * @param bool $show_alert If true, shows as an alert box instead of top notification
 */
function answer_telegram_callback($callback_query_id, $text, $show_alert = false) {
    if (!defined('TELEGRAM_BOT_TOKEN') || empty(TELEGRAM_BOT_TOKEN)) return;

    $bot_token = TELEGRAM_BOT_TOKEN;
    $api_url = "https://api.telegram.org/bot{$bot_token}/answerCallbackQuery";

    $params = [
        'callback_query_id' => $callback_query_id,
        'text' => $text,
        'show_alert' => $show_alert,
        // 'cache_time' => 5 // Optional: Cache time for the result
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $api_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200) {
        error_log("Telegram answerCallbackQuery failed: HTTP $http_code, Response: $response");
    } else {
        error_log("Telegram answerCallbackQuery success for Query ID $callback_query_id");
    }
}

/**
 * Edits the original Telegram message (e.g., to remove buttons).
 *
 * @param string $chat_id
 * @param int $message_id
 * @param string $text New text for the message
 * @param array|null $reply_markup Optional: New reply markup (e.g., null to remove buttons)
 */
function edit_telegram_message($chat_id, $message_id, $text, $reply_markup = null) {
     if (!defined('TELEGRAM_BOT_TOKEN') || empty(TELEGRAM_BOT_TOKEN)) return;

    $bot_token = TELEGRAM_BOT_TOKEN;
    $api_url = "https://api.telegram.org/bot{$bot_token}/editMessageText";

    $params = [
        'chat_id' => $chat_id,
        'message_id' => $message_id,
        'text' => $text,
        'parse_mode' => 'HTML' // Or match the original parse mode
    ];

    if ($reply_markup !== null) {
        $params['reply_markup'] = json_encode($reply_markup);
    } else {
         // To remove buttons, send an empty inline keyboard
         $params['reply_markup'] = json_encode(['inline_keyboard' => []]);
    }


    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $api_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200) {
        error_log("Telegram editMessageText failed: HTTP $http_code, Response: $response");
    } else {
         error_log("Telegram editMessageText success for Msg ID $message_id in Chat ID $chat_id");
    }
}

?>
