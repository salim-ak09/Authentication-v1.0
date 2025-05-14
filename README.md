# Authentication System

This is a basic authentication system with the following features:

*   User registration and login
*   Password reset
*   Two-factor authentication (email OTP and Telegram approval)
*   User settings
*   Login logs

## Technologies Used

*   PHP
*   MySQL
*   PHPMailer
*   Telegram Bot API
*   HTML
*   CSS
*   JavaScript

## Installation

1.  Clone the repository.
2.  Create a MySQL database.
3.  Import the `sql/schema.sql` file into the database.
4.  Configure the database connection in `.env`.
5.  Configure the email settings in `.env`.
6.  Configure the Telegram Bot API token in `.env`.
7.  Set the webhook URL for your Telegram bot to `telegram_callback.php`, easy to set webhook from the `setwebhook.php` file.

NOTE: <br>
1- The `setwebhook.php` file is provided for convenience. You can use it to set the webhook for your Telegram bot. However, you should remove the file from your server after you have set the webhook.

2- `.env` file is not provided, you need to create it from the `.env.example` file.

## Usage

1.  Register a new user account.
2.  Login to your account.
3.  Configure your settings, including enabling two-factor authentication.
4.  View your login activity in the dashboard.

## Security

This system implements the following security measures:

*   Password hashing using bcrypt
*   CSRF protection
*   Input sanitization
*   Two-factor authentication
*   xss protection
*   Clickjacking protection
*   Content Security Policy (CSP)
*   SQL injection protection
*   Error handling and logging
*   Rate limiting
*   Session management
*   HTTPS (SSL/TLS)

## Disclaimer

This is a basic authentication system and may not be suitable for production use. It is provided for educational purposes only. Maybe with some updates it can be highly secured and ready for production use.

## License

This project is licensed under the MIT License.

## URLs needed

1- `reCAPTCHA V2` https://www.google.com/recaptcha/admin/create
2- `Bot father (Telegram)` https://telegram.me/BotFather
3- `SMTP` https://www.brevo.com/
4- `PHPMailer` https://github.com/PHPMailer/PHPMailer

NOTE: 
1- you can use any SMTP service you want, but you need to configure it in the `.env` file.
2- you can use any reCAPTCHA service you want, but you need to configure it in the `.env` file.
3- you can use any Telegram bot you want, but you need to configure it in the `.env` file.
4- the phpmailer lib are removed from the project, you can download it from the link above and put it in the `lib` folder.
5- we dont provide sql file , if u need it contact me.