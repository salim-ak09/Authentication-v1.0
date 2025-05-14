<?php
// Replace with your bot token and webhook URL
define('TELEGRAM_BOT_TOKEN', '');
define('WEBHOOK_URL', 'URL_here/templates/security/authantication(mega)/public/telegram_callback.php');

// Telegram API URL to set the webhook
$api_url = "https://api.telegram.org/bot" . TELEGRAM_BOT_TOKEN . "/setWebhook";

// Webhook parameters
$params = [
    'url' => WEBHOOK_URL
];

// Initialize cURL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Output the result
if ($http_code === 200) {
    echo "Webhook set successfully: " . $response;
} else {
    echo "Failed to set webhook. HTTP Code: $http_code. Response: $response";
}
?>