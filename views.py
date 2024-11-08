from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app import db
from helper import login_required, encryption, decryption, check_password_breach, check_email_breach
import logging
logging.basicConfig(level=logging.INFO)

views = Blueprint("views", __name__)

@views.route("/")
@login_required
def index():
    passwords = db.execute("SELECT id, name, username, email, password, timestamp FROM secrets WHERE user_id = ? ORDER BY timestamp DESC", session["user_id"])
    return render_template("index.html", passwords=passwords)

@views.route("/test-log")
def test_log():
    logging.info("This is a test log message")
    return "Check your console for the log message"

@views.route("/add-item", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("add-username")
        email = request.form.get("email")
        password = request.form.get("add-password")

        # Check for duplicate name and add entry
        if db.execute("SELECT 1 FROM secrets WHERE user_id = ? AND name = ?", session["user_id"], name):
            flash("Name already in use.", "error")
        else:
            passwordEncrypted = encryption(password)
            db.execute("INSERT INTO secrets (name, username, email, password, timestamp, user_id) VALUES (?, ?, ?, ?, datetime('now'), ?)", name, username, email, passwordEncrypted, session["user_id"])
            flash("Item added Successfully.")
            return redirect(url_for("views.index"))

    return redirect(url_for("views.index"))

@views.route("/update-item/<int:id>", methods=["GET", "POST"])
@login_required
def update(id):
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        encryptedPassword = encryption(password)
        db.execute("UPDATE secrets SET name = ?, username = ?, email = ?, password = ?, timestamp = datetime('now') WHERE id = ? AND user_id = ?", name, username, email, encryptedPassword, id, session["user_id"])
        flash("Item Updated Successfully")
        return redirect(url_for("views.index"))

    secrets = db.execute("SELECT name, username, email, password, timestamp FROM secrets WHERE id=? AND user_id=?", id, session["user_id"])
    decryptedPassword = decryption(secrets[0]["password"])
    return render_template("update.html", secrets=secrets, decryptedPassword=decryptedPassword)

@views.route("/vault-item/<int:id>", methods=["GET", "POST"])
@login_required
def secret(id):
    secrets = db.execute("SELECT id, name, username, email, password, timestamp FROM secrets WHERE id=? AND user_id=?", id, session["user_id"])

    if not secrets:
        flash("The requested item was not found or you don't have access.", "error")
        return redirect(url_for("views.index"))

    decryptedPassword = decryption(secrets[0]["password"])
    return render_template("secret.html", secrets=secrets, decryptedPassword=decryptedPassword)

@views.route("/delete/<int:id>", methods=["GET", "POST"])
@login_required
def delete(id):
    if request.method == "POST":
        db.execute("DELETE FROM secrets WHERE id=? AND user_id=?", id, session["user_id"])
        flash("Item Deleted Successfully")
        return redirect(url_for("views.index"))
    return None

@views.route("/account", methods=["GET", "POST"])
@login_required
def account():
    informationCurrentUser = db.execute("SELECT id, email, password FROM users WHERE id = ?", session["user_id"])
    decryptedPassword = decryption(informationCurrentUser[0]["password"]) if informationCurrentUser else None
    return render_template("account.html", informationCurrentUser=informationCurrentUser, decryptedPassword=decryptedPassword, email_user=session["email"], breach_alert=False)

@views.route("/update-account", methods=["GET", "POST"])
@login_required
def updateAccount():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        breach_alert = False

        # Check email conflict and update
        existing_user = db.execute("SELECT id FROM users WHERE email = ?", email)
        if existing_user and existing_user[0]["id"] != session["user_id"]:
            flash("Email already registered", "error")
            return redirect(url_for('views.account'))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
        elif password != confirm:
            flash("Passwords don't match.", "error")
        else:
            encryptedPassword = encryption(password)
            db.execute("UPDATE users SET email = ?, password = ? WHERE id = ?", email, encryptedPassword, session["user_id"])
            flash("User Updated Successfully.")
            return redirect(url_for('views.account'))

    informationCurrentUser = db.execute("SELECT email, password FROM users WHERE id = ?", session["user_id"])
    decryptedPassword = decryption(informationCurrentUser[0]["password"])
    return render_template("update-account.html", informationCurrentUser=informationCurrentUser, decryptedPassword=decryptedPassword)

@views.route("/delete-account/<int:id>", methods=["GET", "POST"])
@login_required
def deleteAccount(id):
    if request.method == "POST":
        db.execute("DELETE FROM users WHERE id = ?", id)
        db.execute("DELETE FROM secrets WHERE user_id = ?", id)
        session.clear()
        return redirect(url_for("auth.login"))
    return None

@views.route("/reauthenticate", methods=["POST", "GET"], endpoint="reauthenticate")
@login_required
def reauthenticate():
    print("Reauthenticate route accessed")  # Temporary print for debugging
    if request.method == "GET":
        logging.info("GET request to /reauthenticate")
        return "Reauthenticate endpoint is accessible", 200

    logging.info("POST request to /reauthenticate")
    data = request.get_json()
    logging.info("Received data: %s", data)

    entered_password = data.get("password")
    user_data = db.execute("SELECT password FROM users WHERE id = ?", session["user_id"])
    actual_password = decryption(user_data[0]["password"]) if user_data else None

    if actual_password == entered_password:
        logging.info("Password reauthentication successful")
        return jsonify({"authenticated": True})
    else:
        logging.info("Password reauthentication failed")
        return jsonify({"authenticated": False}), 401




@views.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        nameSite = request.form.get("search")
        itemSearched = db.execute("SELECT * FROM secrets WHERE user_id = ? AND (name = ? OR email = ?)", session["user_id"], nameSite, nameSite)
        if not itemSearched:
            flash("No items were found that match your search pattern", "error")
            return redirect(url_for("views.index"))
        return render_template("searched.html", itemSearched=itemSearched, nameSite=nameSite)
    return None

@views.route("/check-email-breach")
@login_required
def async_check_email_breach():
    email = request.args.get("email")
    breached = check_email_breach(email)
    return jsonify({"breached": breached})

@views.route("/check-password-breach")
@login_required
def async_check_password_breach():
    password = request.args.get("password")
    breached = check_password_breach(password)
    return jsonify({"breached": breached})
