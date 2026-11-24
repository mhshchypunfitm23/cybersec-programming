from flask import Flask, request, render_template, redirect, make_response, session
from markupsafe import escape
from werkzeug.security import check_password_hash
import os
import secrets
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")
FAILED_LOGINS = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/echo")
def echo():
    msg = escape(request.args.get("msg", ""))
    return f"<h1>Echo</h1><p>{msg}</p>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    sql = "SELECT id, title, body FROM posts WHERE title LIKE ? OR body LIKE ?"
    like_pattern = f"%{q}%"
    rows = cur.execute(sql, (like_pattern, like_pattern)).fetchall()
    return render_template("search.html", q=q, rows=rows, sql="Parameterized SQL Query")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if FAILED_LOGINS.get(username, 0) >= 5:
            logging.warning(f"Account locked due to brute-force: {username}")
            return render_template("login.html", error="Account temporarily locked (too many attempts)")

        conn = get_db()
        cur = conn.cursor()
        row = cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password"], password):
            FAILED_LOGINS[username] = 0
            session["user_id"] = row["id"]
            logging.info(f"Successful login for user: {username}")
            return make_response(redirect("/profile"))

        FAILED_LOGINS[username] = FAILED_LOGINS.get(username, 0) + 1
        logging.warning(f"Failed login attempt for user: {username}")
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", user=user)

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=False)
