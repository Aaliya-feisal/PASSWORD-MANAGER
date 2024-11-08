from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from helper import login_required, encryption, decryption

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("login-password")

        searchUser = db.execute("SELECT id, password FROM users WHERE email = ?", email)

        encryptedPassword = None
        for i in searchUser:
            encryptedPassword = i['password']
            id = i["id"]

         # Decrypt the stored password for comparison
        if encryptedPassword is not None:
            decryptedPassword = decryption(encryptedPassword)

        if len(searchUser) != 1 or password != decryptedPassword:
            flash("Email or Password incorrect.", "error")
        else:
            session["user_id"] = id
            session["email"] = email

            return redirect("/")

    return render_template('auth/login.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form.get("registration-email")
        password = request.form.get("register-password")
        confirm = request.form.get("confirm")

        check = 0
        for i in db.execute("SELECT email FROM users WHERE email = ?", email):
            if email == i["email"]:
                check = 1

        if check == 1:
            flash("Email already registered.", "error")
        elif len(password) < 8:
            flash("Password must be greater than 7 characters long.", "error")
        elif password != confirm:
            flash("Passwords doesn't match.", "error")
        else:
            encryptedPassword = encryption(password)

            db.execute("INSERT INTO users (email, password) VALUES (?, ?)", email, encryptedPassword)
            
            flash("Account Created Successfully.")

            session["email"] = email

            return redirect(url_for("auth.login"))

    return redirect(url_for("auth.login"))


@auth.route("/logout")
@login_required
def logout():

    session.clear()

    return redirect(url_for("auth.login"))