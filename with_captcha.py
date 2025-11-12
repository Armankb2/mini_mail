# mini_mail.py - full corrected app
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, send_from_directory
import mysql.connector as m
from datetime import datetime
import random
import string
import os
from werkzeug.utils import secure_filename

# -------------------- CONFIG --------------------
DB_HOST = "localhost"
DB_USER = "thejeswar"
DB_PASSWORD = "student"
ADMIN_DEFAULT_PASSWORD = "root1234"   # used for initial admin row
SECRET_KEY = "".join(random.choices(string.ascii_letters + string.digits, k=24))

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -------------------- UPLOADS --------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "mov", "pdf", "txt", "docx"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # filename can be "user_id/filename.ext"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(file_path):
        # split directory and serve properly
        folder = os.path.dirname(filename)
        fname = os.path.basename(filename)
        if folder:
            return send_from_directory(os.path.join(app.config["UPLOAD_FOLDER"], folder), fname)
        else:
            return send_from_directory(app.config["UPLOAD_FOLDER"], fname)
    return "File not found", 404


# -------------------- DB helpers --------------------
def connect_server():
    return m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD)


def initialize_system():
    """
    Create required databases/tables:
      - mail (userdetails, admins, all_messages, user_activity)
      - per-user DBs are created on signup
    """
    con = connect_server()
    cur = con.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS mail")
    cur.execute("USE mail")

    # user table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS userdetails (
            name VARCHAR(30),
            mobile_no VARCHAR(20),
            user_ID VARCHAR(50) PRIMARY KEY,
            pin INT
        )
    """)

    # admin table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            admin_id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(100) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # insert default admin if none
    cur.execute("SELECT COUNT(*) FROM admins")
    cnt = cur.fetchone()[0]
    if cnt == 0:
        cur.execute("INSERT INTO admins (username, password) VALUES (%s, %s)", ("admin", ADMIN_DEFAULT_PASSWORD))

    # global message table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS all_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            message_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            sender VARCHAR(50),
            receiver VARCHAR(50),
            direction ENUM('sent','received'),
            message TEXT,
            attachment VARCHAR(255)
        )
    """)

    # user activity table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_activity (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(50),
            action ENUM('login','logout','signup','message_sent','message_received'),
            details TEXT
        )
    """)

    con.commit()
    cur.close()
    con.close()


# -------------------- Logging functions --------------------
def log_message_global(sender, receiver, direction, message, attachment=None):
    try:
        con = m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database="mail")
        cur = con.cursor()
        cur.execute("""
            INSERT INTO all_messages (sender, receiver, direction, message, attachment)
            VALUES (%s, %s, %s, %s, %s)
        """, (sender, receiver, direction, message, attachment))
        con.commit()
        cur.close()
        con.close()
    except Exception as e:
        print("Error logging global message:", e)


def log_user_activity(user_id, action, details=""):
    try:
        con = m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database="mail")
        cur = con.cursor()
        cur.execute("INSERT INTO user_activity (user_id, action, details) VALUES (%s,%s,%s)",
                    (user_id, action, details))
        con.commit()
        cur.close()
        con.close()
    except Exception as e:
        print("Error logging user activity:", e)
# ---------- CAPTCHA helpers ----------
def generate_captcha_code(length=5):
    """Return a random alphanumeric captcha string."""
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def init_captcha_session():
    """Initialize captcha in session (code + attempts)."""
    session['captcha_code'] = generate_captcha_code()
    session['captcha_attempts'] = 0

def verify_captcha(entered, case_sensitive=False):
    """Verify entered captcha against session-stored code. Increments attempts."""
    if 'captcha_code' not in session:
        return False, "CAPTCHA not initialized."
    # increment attempts
    session['captcha_attempts'] = session.get('captcha_attempts', 0) + 1
    code = session['captcha_code']
    if not case_sensitive:
        ok = entered.strip().lower() == code.lower()
    else:
        ok = entered.strip() == code
    return ok, None



# -------------------- Templates & CSS --------------------
BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mini Mail</title>
  <style>
    :root { --primary: #0b78e3; --muted: #6b7280; --card: #fff; --bg: #f3f6fb; }
    body {font-family: Inter, Arial, sans-serif; background: var(--bg); margin: 0;}
    .nav {background: var(--primary); color: #fff; padding: 12px 18px; display:flex; gap:12px; align-items:center;}
    .nav a {color:#fff; text-decoration:none; font-weight:600;}
    .wrap {max-width:1000px; margin:30px auto; padding:18px;}
    .card {background:var(--card); padding:18px; border-radius:10px; box-shadow:0 6px 18px rgba(15,23,42,0.06);}
    input, textarea {width:100%; padding:10px; margin-top:6px; margin-bottom:12px; border-radius:6px; border:1px solid #e6eef8;}
    button {background:var(--primary); color:#fff; border:none; padding:10px 14px; border-radius:8px; cursor:pointer;}
    table {width:100%; border-collapse:collapse; margin-top:12px;}
    th, td {padding:8px; border-bottom:1px solid #efefef; text-align:left;}
    th {color:var(--muted); font-size:13px;}
    .small {font-size:12px; color:var(--muted);}
    .actions {display:flex; gap:8px;}
    .alert {background:#eaf4ff; padding:10px; border-left:4px solid var(--primary); margin-bottom:12px;}
  </style>
</head>
<body>
  <div class="nav">
    <a href="{{ url_for('index') }}">🏠 Home</a>
    {% if 'user_id' in session %}
      <a href="{{ url_for('dashboard') }}">📬 Dashboard</a>
      <a href="{{ url_for('view_messages') }}">📥 Messages</a>
      <a href="{{ url_for('logout') }}">🚪 Logout</a>
    {% else %}
      <a href="{{ url_for('login') }}">🔑 Login</a>
      <a href="{{ url_for('signup') }}">🧾 Sign Up</a>
    {% endif %}
    <a href="{{ url_for('admin_login') }}">🛠 Admin</a>
    <div style="flex:1"></div>
    <div class="small">Mini Mail — local dev</div>
  </div>

  <div class="wrap">
    <div class="card">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          {% for msg in messages %}<div class="alert">{{ msg }}</div>{% endfor %}
        {% endif %}
      {% endwith %}
      {{ content|safe }}
    </div>
  </div>
</body>
</html>
"""

INDEX_PAGE = "<h2>Mini Mail</h2><p class='small'>A lightweight local messaging demo — upload attachments, track activity.</p>"

SIGNUP_PAGE = """
<h3>Create Account</h3>
<form method="post">
  <label>Name</label><input name="name" required>
  <label>Phone</label><input name="phone" required>
  <label>User ID</label><input name="user_id" required>
  <label>PIN (4 digits)</label><input name="pin" required maxlength="4">
  <label>Confirm PIN</label><input name="confirm" required maxlength="4">
  <button type="submit">Create</button>
</form>
"""

LOGIN_PAGE = """
<h3>Login</h3>
<form method="post">
  <label>User ID</label><input name="user_id" required>
  <label>PIN</label><input name="pin" required>
  <label>CAPTCHA</label>
  <div style="font-family:monospace; font-size:18px; padding:8px; background:#f1f5f9; display:inline-block; border-radius:6px; margin-bottom:6px;">{{ captcha_code }}</div>
  <input name="captcha" placeholder="Enter the CAPTCHA shown above" required>
  <button type="submit">Login</button>
</form>
"""


DASHBOARD_PAGE = """
<h3>Welcome, {{ name }}</h3>
<div class="actions">
  <a href="{{ url_for('send_message') }}"><button>✉️ Send</button></a>
  <a href="{{ url_for('view_messages') }}"><button>📥 View</button></a>
</div>
"""

SEND_PAGE = """
<h3>Send Message</h3>
<form method="post" enctype="multipart/form-data">
  <label>To (User ID)</label><input name="to_id" required>
  <label>Message</label><textarea name="message" rows="5" required maxlength="1000"></textarea>
  <label>Attachment (optional)</label><input type="file" name="attachment">
  <button type="submit">Send</button>
</form>
"""

VIEW_PAGE = """
<h3>Your Messages</h3>
<h4>Received</h4>
<table>
<tr><th>Date</th><th>From</th><th>Message</th><th>Attachment</th></tr>
{% for r in received %}
<tr>
  <td>{{ r[0] }}</td>
  <td>{{ r[1] }}</td>
  <td>{{ r[2] }}</td>
  <td>{% if r[3] %}<a href="/uploads/{{ r[3] }}" target="_blank">📎 View</a>{% else %}-{% endif %}</td>
</tr>
{% endfor %}
</table>

<h4>Sent</h4>
<table>
<tr><th>Date</th><th>To</th><th>Message</th><th>Attachment</th></tr>
{% for s in sent %}
<tr>
  <td>{{ s[0] }}</td>
  <td>{{ s[1] }}</td>
  <td>{{ s[2] }}</td>
  <td>{% if s[3] %}<a href="/uploads/{{ s[3] }}" target="_blank">📎 View</a>{% else %}-{% endif %}</td>
</tr>
{% endfor %}
</table>
"""

ADMIN_LOGIN_PAGE = """
<h3>Admin Login</h3>
<form method="post">
  <label>Username</label><input name="username" required>
  <label>Password</label><input name="password" type="password" required>
  <button type="submit">Login</button>
</form>
"""

ADMIN_DASH_PAGE = """
<h3>Admin Dashboard ({{ admin }})</h3>

<h4>Users</h4>
<table>
<tr><th>Name</th><th>Mobile</th><th>User ID</th><th>PIN</th></tr>
{% for u in users %}
<tr><td>{{ u[0] }}</td><td>{{ u[1] }}</td><td>{{ u[2] }}</td><td>{{ u[3] }}</td></tr>
{% endfor %}
</table>

<h4>Global Messages</h4>
<table>
<tr><th>Date</th><th>Sender</th><th>Receiver</th><th>Dir</th><th>Message</th><th>Attachment</th></tr>
{% for m in messages %}
<tr>
  <td>{{ m[1] }}</td>
  <td>{{ m[2] }}</td>
  <td>{{ m[3] }}</td>
  <td>{{ m[4] }}</td>
  <td style="max-width:300px; white-space:pre-wrap;">{{ m[5] }}</td>
  <td>{% if m[6] %}<a href="/uploads/{{ m[6] }}" target="_blank">📎</a>{% else %}-{% endif %}</td>
</tr>
{% endfor %}
</table>

<h4>User Activity</h4>
<table>
<tr><th>When</th><th>User</th><th>Action</th><th>Details</th></tr>
{% for a in activity %}
<tr><td>{{ a[1] }}</td><td>{{ a[2] }}</td><td>{{ a[3] }}</td><td>{{ a[4] }}</td></tr>
{% endfor %}
</table>
"""

# -------------------- render helper --------------------
def render(content, **kwargs):
    return render_template_string(BASE, content=render_template_string(content, **kwargs))


# -------------------- ROUTES --------------------
@app.route('/')
def index():
    return render(INDEX_PAGE)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        user_id = request.form.get('user_id', '').strip()
        pin = request.form.get('pin', '').strip()
        confirm = request.form.get('confirm', '').strip()

        if not all([name, phone, user_id, pin, confirm]):
            flash("All fields required")
            return redirect(url_for('signup'))
        if not pin.isdigit() or len(pin) != 4 or pin != confirm:
            flash("PIN must be 4 digits and match confirmation")
            return redirect(url_for('signup'))

        con = connect_server()
        cur = con.cursor()
        cur.execute("USE mail")
        cur.execute("SELECT user_ID FROM userdetails WHERE user_ID=%s", (user_id,))
        if cur.fetchone():
            cur.close()
            con.close()
            flash("User ID already exists")
            return redirect(url_for('signup'))

        cur.execute("INSERT INTO userdetails (name, mobile_no, user_ID, pin) VALUES (%s,%s,%s,%s)",
                    (name, phone, user_id, int(pin)))
        con.commit()

        # create per-user DB and tables
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{user_id}`")
        cur.execute(f"USE `{user_id}`")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages_sent(
                id INT AUTO_INCREMENT PRIMARY KEY,
                date DATETIME,
                sent_to VARCHAR(50),
                sent_message TEXT,
                attachment VARCHAR(255)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages_received(
                id INT AUTO_INCREMENT PRIMARY KEY,
                date DATETIME,
                received_from VARCHAR(50),
                received_message TEXT,
                attachment VARCHAR(255)
            )
        """)
        con.commit()
        cur.close()
        con.close()

        # log signup
        log_user_activity(user_id, "signup", f"Account created for {name}")
        flash("Account created — you may now log in")
        return redirect(url_for('login'))

    return render(SIGNUP_PAGE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ensure captcha is initialized on every GET
    if request.method == 'GET':
        init_captcha_session()
        return render(LOGIN_PAGE, captcha_code=session.get('captcha_code', ''))

    # POST: validate captcha first
    user_id = request.form.get('user_id', '').strip()
    pin = request.form.get('pin', '').strip()
    entered_captcha = request.form.get('captcha', '').strip()

    # basic presence checks
    if not user_id or not pin or not entered_captcha:
        flash("All fields (user id, pin, captcha) are required")
        init_captcha_session()  # regenerate for next try
        return redirect(url_for('login'))

    # verify captcha
    ok, err = verify_captcha(entered_captcha, case_sensitive=False)
    if not ok:
        attempts = session.get('captcha_attempts', 0)
        MAX_ATTEMPTS = 5
        if attempts >= MAX_ATTEMPTS:
            # regenerate code and reset attempts to avoid brute force
            init_captcha_session()
            flash(f"Too many incorrect CAPTCHA attempts. A new CAPTCHA was generated.")
            return redirect(url_for('login'))
        else:
            flash(f"Incorrect CAPTCHA. Attempts: {attempts}/{MAX_ATTEMPTS}")
            return redirect(url_for('login'))

    # CAPTCHA passed — proceed with normal DB login
    con = connect_server()
    cur = con.cursor()
    cur.execute("USE mail")
    cur.execute("SELECT name, pin FROM userdetails WHERE user_ID=%s", (user_id,))
    row = cur.fetchone()
    cur.close()
    con.close()
    if not row:
        flash("User not found")
        # regenerate captcha for next try
        init_captcha_session()
        return redirect(url_for('login'))
    if str(row[1]) != str(pin):
        flash("Incorrect PIN")
        # regenerate captcha for next try
        init_captcha_session()
        return redirect(url_for('login'))

    # successful login
    session['user_id'] = user_id
    session['user_name'] = row[0]
    # clear captcha from session on success
    session.pop('captcha_code', None)
    session.pop('captcha_attempts', None)
    log_user_activity(user_id, "login", f"{user_id} logged in")
    flash("Logged in")
    return redirect(url_for('dashboard'))



@app.route('/logout')
def logout():
    if 'user_id' in session:
        uid = session['user_id']
        log_user_activity(uid, "logout", f"{uid} logged out")
    session.clear()
    flash("Logged out")
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login")
        return redirect(url_for('login'))
    return render(DASHBOARD_PAGE, name=session.get('user_name', session['user_id']))


@app.route('/send', methods=['GET', 'POST'])
def send_message():
    if 'user_id' not in session:
        flash("Please login")
        return redirect(url_for('login'))

    if request.method == 'POST':
        sender = session['user_id']
        receiver = request.form.get('to_id', '').strip()
        message = request.form.get('message', '').strip()
        file = request.files.get('attachment')

        if not receiver or not message:
            flash("Receiver and message required")
            return redirect(url_for('send_message'))

        # verify receiver exists
        con = connect_server()
        cur = con.cursor()
        cur.execute("USE mail")
        cur.execute("SELECT user_ID FROM userdetails WHERE user_ID=%s", (receiver,))
        if not cur.fetchone():
            cur.close()
            con.close()
            flash("Receiver not found")
            return redirect(url_for('send_message'))
        cur.close()
        con.close()

        # handle file
        filename_rel = None
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("File type not allowed")
                return redirect(url_for('send_message'))
            safe = secure_filename(file.filename)
            user_dir = os.path.join(app.config["UPLOAD_FOLDER"], sender)
            os.makedirs(user_dir, exist_ok=True)
            path = os.path.join(user_dir, safe)
            file.save(path)
            filename_rel = f"{sender}/{safe}"

        now = datetime.now()

        # insert into sender DB
        con1 = m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=sender)
        cur1 = con1.cursor()
        cur1.execute("INSERT INTO messages_sent (date, sent_to, sent_message, attachment) VALUES (%s,%s,%s,%s)",
                     (now, receiver, message, filename_rel))
        con1.commit()
        cur1.close()
        con1.close()

        # insert into receiver DB
        con2 = m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=receiver)
        cur2 = con2.cursor()
        cur2.execute("INSERT INTO messages_received (date, received_from, received_message, attachment) VALUES (%s,%s,%s,%s)",
                     (now, sender, message, filename_rel))
        con2.commit()
        cur2.close()
        con2.close()

        # add global logs
        log_message_global(sender, receiver, "sent", message, filename_rel)
        log_user_activity(sender, "message_sent", f"sent to {receiver}")
        log_user_activity(receiver, "message_received", f"from {sender}")

        flash("Message sent")
        return redirect(url_for('dashboard'))

    return render(SEND_PAGE)


@app.route('/view')
def view_messages():
    if 'user_id' not in session:
        flash("Please login")
        return redirect(url_for('login'))

    uid = session['user_id']
    con = m.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=uid)
    cur = con.cursor()
    cur.execute("SELECT date, received_from, received_message, attachment FROM messages_received ORDER BY date DESC")
    received = cur.fetchall()
    cur.execute("SELECT date, sent_to, sent_message, attachment FROM messages_sent ORDER BY date DESC")
    sent = cur.fetchall()
    cur.close()
    con.close()
    return render(VIEW_PAGE, received=received, sent=sent)


# -------------------- ADMIN ROUTES --------------------
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        con = connect_server()
        cur = con.cursor()
        cur.execute("USE mail")
        cur.execute("SELECT admin_id FROM admins WHERE username=%s AND password=%s", (username, password))
        row = cur.fetchone()
        cur.close()
        con.close()
        if row:
            session['is_admin'] = True
            session['admin_username'] = username
            flash("Admin logged in")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials")
            return redirect(url_for('admin_login'))
    return render(ADMIN_LOGIN_PAGE)


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Admin login required")
        return redirect(url_for('admin_login'))

    con = connect_server()
    cur = con.cursor()
    cur.execute("USE mail")
    cur.execute("SELECT name, mobile_no, user_ID, pin FROM userdetails")
    users = cur.fetchall()

    cur.execute("SELECT * FROM all_messages ORDER BY message_date DESC LIMIT 500")
    messages = cur.fetchall()

    cur.execute("SELECT * FROM user_activity ORDER BY timestamp DESC LIMIT 500")
    activity = cur.fetchall()

    cur.close()
    con.close()
    return render(ADMIN_DASH_PAGE, admin=session.get('admin_username', 'admin'), users=users, messages=messages, activity=activity)


# -------------------- START --------------------
if __name__ == "__main__":
    initialize_system()
    # run app
    app.run(host="0.0.0.0", port=5001, debug=True)