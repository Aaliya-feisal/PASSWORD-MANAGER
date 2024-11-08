# email_breach_check.py
from app import db
from helper import check_email_breach
from flask_mail import Message
from app import mail

def send_breach_notification(email):
    msg = Message("Security Alert: Email Found in Breach", recipients=[email])
    msg.body = f"Your email {email} was found in a data breach. Please consider updating your passwords."
    mail.send(msg)

def periodic_email_breach_check():
    users = db.execute("SELECT id, email FROM users")
    for user in users:
        if check_email_breach(user['email']):
            send_breach_notification(user['email'])

if __name__ == "__main__":
    periodic_email_breach_check()
