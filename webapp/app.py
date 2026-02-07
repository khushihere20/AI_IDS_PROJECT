from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from encoders import encode_dataframe
import joblib, json, os, sqlite3, re
import pandas as pd
import random
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = "enterprise_ids_secret"
app.config["UPLOAD_FOLDER"] = "uploads"
DB = "users.db"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ================= EMAIL CONFIG =================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "yourprojectmail@gmail.com"
EMAIL_PASSWORD = "your_gmail_app_password"

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("Email error:", e)

# ================= CAPTCHA =================
def generate_captcha():
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    session["captcha_answer"] = str(a + b)
    session["captcha_question"] = f"{a} + {b}"

# ================= DATABASE INIT =================
def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        """)

init_db()

# ================= PASSWORD STRENGTH =================
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[^A-Za-z0-9]", password)
    )

# ================= LOAD ML MODEL =================
model = joblib.load("../model/ids_model.pkl")
label_encoder = joblib.load("../model/label_encoder.pkl")

with open("../training/feature_columns.json") as f:
    FEATURES = json.load(f)["features"]

# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not is_strong_password(password):
            error = "Password must be strong"
        else:
            try:
                with sqlite3.connect(DB) as conn:
                    conn.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, generate_password_hash(password))
                    )
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username already exists"

    return render_template("register.html", error=error)

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    session.setdefault("attempts", 0)
    session.setdefault("lock_until", None)

    attempts = session["attempts"]
    show_captcha = attempts >= 3
    risk = "High" if attempts >= 5 else "Medium" if attempts >= 3 else "Low"

    if show_captcha and "captcha_question" not in session:
        generate_captcha()

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if show_captcha:
            if request.form.get("captcha") != session.get("captcha_answer"):
                return render_template("login.html", error="Invalid CAPTCHA",
                                       attempts=attempts, risk=risk,
                                       show_captcha=True,
                                       captcha_question=session["captcha_question"])

        with sqlite3.connect(DB) as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user[2], password):
            session.clear()
            session["user"] = username
            return redirect(url_for("index"))

        session["attempts"] += 1
        error = "Invalid credentials"

    return render_template("login.html", error=error,
                           attempts=session["attempts"],
                           risk=risk,
                           show_captcha=show_captcha,
                           captcha_question=session.get("captcha_question"))

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= DASHBOARD (CSV FIX HERE) =================
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    result = table = chart_data = soc = error = None

    if request.method == "POST" and "csv_file" in request.files:
        file = request.files["csv_file"]
        path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(path)

        try:
            df = pd.read_csv(path)
            df = encode_dataframe(df[FEATURES])
            preds = model.predict(df)
            attacks = label_encoder.inverse_transform(preds)
            df["Attack Type"] = attacks

            chart_data = df["Attack Type"].value_counts().to_dict()
            intrusions = (df["Attack Type"] != "normal").sum()

            soc = {
                "total": len(df),
                "intrusions": intrusions,
                "risk": "High" if intrusions / len(df) > 0.5 else "Medium"
            }

            table = df.head(20).to_html(classes="table table-striped", index=False)
            result = "CSV Analysis Completed"

        except Exception as e:
            error = str(e)

    return render_template("index.html",
                           user=session["user"],
                           result=result,
                           table=table,
                           chart_data=chart_data,
                           soc=soc,
                           error=error)

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)