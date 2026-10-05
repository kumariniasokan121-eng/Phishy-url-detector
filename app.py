import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, detect_phishing

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///url.db")


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute(
            "SELECT * FROM user WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
@login_required
def index():
    return render_template("url_detector.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Please provide username!", 400)
        if not password:
            return apology("Please provide password!", 400)
        if not confirmation:
            return apology("Please retype the password!", 400)
        if password != confirmation:
            return apology("Password not matching", 400)

        rows = db.execute("SELECT * FROM user WHERE username = :username",
                          username = username)
        if len(rows) != 0:
            return apology("Username already taken", 400)

        hashed = generate_password_hash(password)
        try:
            new_user = db.execute("INSERT INTO user (username, hash) VALUES (:username, :hash)",
                    username = username,
                    hash = hashed)
        except:
            return apology("Username has already been taken", 400)

        session["user_id"] = new_user
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/url_detector", methods=["GET", "POST"])
def url_detector():

    if request.method == "POST":
        url = request.form.get("URL")

        if not url:
            return apology("Must provide URL", 400)

        rows = db.execute("SELECT * FROM detect WHERE url = ?", url)
        if len(rows) > 0:
            result = "PHISHY URL!"
            score = 0
            reasons = ["Previously identified as PHISHY url..."]

        else:
            result, score, reasons = detect_phishing(url)
            if result == "PHISHY URL!":
                db.execute("INSERT INTO detect (url) VALUES (?)", url)

        return render_template("url_detector.html", result = result, url = url, score = score, reasons = reasons)

    else:
        return render_template("url_detector.html")

