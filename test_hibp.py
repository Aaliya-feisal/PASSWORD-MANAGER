# test_hibp.py
from helper import check_password_breach, check_email_breach

# Test with a known breached password and email
breached_password = "password123"
breached_email = "test@example.com"

# Check the password
if check_password_breach(breached_password):
    print(f"The password '{breached_password}' has been found in a data breach.")
else:
    print(f"The password '{breached_password}' is safe.")

# Check the email
if check_email_breach(breached_email):
    print(f"The email '{breached_email}' has been found in a data breach.")
else:
    print(f"The email '{breached_email}' is safe.")
