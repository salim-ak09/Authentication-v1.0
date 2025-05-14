<?php
$page_title = 'Register';
require_once __DIR__ . '/../includes/header.php'; // Includes session, functions, database

// Initialize variables
$full_name = '';
$email = '';
$telegram_chat_id = '';
$fingerprint_data = ''; // Placeholder - actual implementation needs specific library/hardware
$password = '';
$confirm_password = '';
$errors = [];

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $errors[] = 'Invalid request. Please try again.';
        // Optionally log this attempt
    }

    // 2. Verify reCAPTCHA
    if (getenv('RECAPTCHA_SITE_KEY')) {
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        if (empty($recaptcha_response)) {
            $errors[] = 'reCAPTCHA verification failed. Please complete the reCAPTCA.';
        } else {
            $verification_result = verify_recaptcha_v2($recaptcha_response);
            if (!$verification_result) {
                $errors[] = 'reCAPTCHA verification failed. Please try again.';
            }
        }
    }

    // 3. Sanitize and retrieve inputs (only if CSRF and reCAPTCHA are valid or not checked initially)
    if (empty($errors)) {
        $full_name = sanitize_input($_POST['full_name'] ?? '');
        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL); // Use filter_var for email sanitization
        $telegram_chat_id = sanitize_input($_POST['telegram_chat_id'] ?? '');
        // $fingerprint_data = $_POST['fingerprint_data'] ?? ''; // How to sanitize/handle this? Needs specific implementation.
        $password = $_POST['password'] ?? ''; // Don't sanitize password before hashing
        $confirm_password = $_POST['confirm_password'] ?? '';

        // 4. Validate inputs
        if (empty($full_name)) {
            $errors[] = 'Full Name is required.';
        }
        if (empty($email)) {
            $errors[] = 'Email is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid Email format.';
        }
        if (!empty($telegram_chat_id) && !ctype_digit(ltrim($telegram_chat_id, '-'))) { // Basic check for numeric ID (can be negative for groups)
             $errors[] = 'Invalid Telegram Chat ID format (should be numeric).';
        }
        if (empty($password)) {
            $errors[] = 'Password is required.';
        } elseif (strlen($password) < 8) { // Basic complexity check
            $errors[] = 'Password must be at least 8 characters long.';
        }
        if ($password !== $confirm_password) {
            $errors[] = 'Passwords do not match.';
        }

        // 5. Check if email already exists (only if other validations passed)
        if (empty($errors)) {
            $db = getDbConnection();
            if ($db) {
                try {
                    $stmt = $db->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
                    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                    $stmt->execute();
                    if ($stmt->fetch()) {
                        $errors[] = 'Email address is already registered.';
                    }
                } catch (PDOException $e) {
                    error_log("Database Error: " . $e->getMessage());
                    $errors[] = 'An error occurred during registration. Please try again later.';
                }
            } else {
                $errors[] = 'Database connection failed. Please try again later.';
            }
        }
    }

    // 6. Process registration if no errors
    if (empty($errors)) {
        $db = getDbConnection(); // Get connection again (or reuse if kept open)
        if ($db) {
            try {
                $db->beginTransaction();

                // Hash the password
                $hashed_password = hash_password($password);

                // Insert user
                $stmt = $db->prepare("INSERT INTO users (full_name, email, password, telegram_chat_id, fingerprint_data, created_at, updated_at) VALUES (:full_name, :email, :password, :telegram_chat_id, :fingerprint_data, NOW(), NOW())");
                $stmt->bindParam(':full_name', $full_name, PDO::PARAM_STR);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->bindParam(':password', $hashed_password, PDO::PARAM_STR);
                // Handle potentially empty optional fields
                $telegram_param = !empty($telegram_chat_id) ? $telegram_chat_id : null;
                $fingerprint_param = !empty($fingerprint_data) ? $fingerprint_data : null; // Placeholder
                $stmt->bindParam(':telegram_chat_id', $telegram_param, PDO::PARAM_STR);
                $stmt->bindParam(':fingerprint_data', $fingerprint_param, PDO::PARAM_STR); // Placeholder

                $stmt->execute();
                $user_id = $db->lastInsertId();

                // Insert default settings for the user
                $stmt_settings = $db->prepare("INSERT INTO user_settings (user_id) VALUES (:user_id)");
                $stmt_settings->bindParam(':user_id', $user_id, PDO::PARAM_INT);
                $stmt_settings->execute();

                $db->commit();

                // 7. Send Notifications (Placeholder)
                $registration_message = "Welcome, " . escape_html($full_name) . "! Your registration was successful.";
                if ($telegram_param) {
                    send_telegram_message($telegram_param, $registration_message);
                    // Log success/failure of Telegram message
                } else {
                    send_email($email, "Registration Successful", "<p>" . $registration_message . "</p>");
                    // Log success/failure of email
                }

                // 8. Set success message and redirect
                $_SESSION['flash_message'] = ['type' => 'success', 'text' => 'Registration successful! Please log in.'];
                redirect('login.php'); // Use the redirect function

            } catch (PDOException $e) {
                $db->rollBack();
                error_log("Database Error during registration: " . $e->getMessage());
                $errors[] = 'An error occurred during registration processing. Please try again later.';
            }
        } else {
             $errors[] = 'Database connection failed during processing. Please try again later.';
        }
    }
    // If errors occurred, the script continues below to display the form with errors
}

?>

<h2>Register</h2>

<?php
// Display errors if any
if (!empty($errors)) {
    echo '<div class="error">';
    foreach ($errors as $error) {
        echo escape_html($error) . '<br>';
    }
    echo '</div>';
}
?>

<form action="register.php" method="post" id="register-form">
    <!-- CSRF Token -->
    <input type="hidden" name="csrf_token" value="<?php echo escape_html($csrf_token); ?>">
    <div class="g-recaptcha" data-sitekey="<?php echo escape_html(getenv('RECAPTCHA_SITE_KEY')); ?>"></div>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    <div class="form-group">
        <label for="full_name">Full Name:</label>
        <input type="text" id="full_name" name="full_name" value="<?php echo escape_html($full_name); ?>" required>
    </div>

    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" value="<?php echo escape_html($email); ?>" required>
    </div>

    <div class="form-group">
        <label for="telegram_chat_id">Telegram Chat ID (Optional):</label>
        <input type="text" id="telegram_chat_id" name="telegram_chat_id" value="<?php echo escape_html($telegram_chat_id); ?>" placeholder="e.g., 123456789">
    </div>

    <div class="form-group">
        <label for="fingerprint_data">Fingerprint (Optional):</label>
        <button type="button" id="scan-fingerprint">Scan Fingerprint</button>
        <input type="hidden" id="fingerprint_data" name="fingerprint_data">
        <span id="fingerprint-status"></span>
    </div>

    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required minlength="8">
    </div>

    <div class="form-group">
        <label for="confirm_password">Confirm Password:</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
    </div>

    <button type="submit">Register</button>
</form>


<?php
require_once __DIR__ . '/../includes/footer.php';
?>
