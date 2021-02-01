with open('secret_key.txt', 'r') as file:
    SECRET_KEY = file.readline().strip()
SESSION_PERMANENT = False
SESSION_TYPE = "filesystem"
MAIL_SERVER = "smtp.gmail.com"  # configured to work with gmail
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your email address"
MAIL_PASSWORD = "your email password"
MAIL_DEFAULT_SENDER = ("sender name", "sender email")
LOGGING_FILE_LOCATION = 'logs/application.log'
SESSION_COOKIE_SAMESITE = 'Lax'
