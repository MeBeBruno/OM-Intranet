# app.py
import os
import secrets
import re
import base64
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, flash,
    get_flashed_messages, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import pyotp

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv()  # expects .env in project root

# ── App & Config ─────────────────────────────────────────────────────────────
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'devkey123')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    f"sqlite:///{os.path.join(basedir, 'intranet.db')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB upload limit

# ── Database & Models ─────────────────────────────────────────────────────────
db = SQLAlchemy(app)

class RegistrationCode(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    code      = db.Column(db.String(32), unique=True, nullable=False)
    max_uses  = db.Column(db.Integer, default=1)
    used      = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    is_admin  = db.Column(db.Boolean, default=False)
    def use(self):
        self.used += 1
        if self.used >= self.max_uses:
            self.is_active = False

class User(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(16), unique=True, nullable=False)
    password_hash  = db.Column(db.String(128), nullable=False)
    display_name   = db.Column(db.String(32), nullable=True)
    profile_pic    = db.Column(db.LargeBinary, nullable=True)
    bio            = db.Column(db.String(500), nullable=True)
    pronouns       = db.Column(db.String(32), nullable=True)
    twofa_enabled  = db.Column(db.Boolean, default=False)
    twofa_secret   = db.Column(db.String(32), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin       = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

# ── Initialize DB & initial admin code ────────────────────────────────────────
with app.app_context():
    db.create_all()
    no_admins = User.query.filter_by(is_admin=True).count() == 0
    no_admin_codes = RegistrationCode.query.filter_by(is_admin=True, is_active=True).count() == 0
    if no_admins and no_admin_codes:
        init_code = secrets.token_hex(8)
        db.session.add(RegistrationCode(code=init_code, max_uses=1, is_admin=True))
        db.session.commit()
        print(f"📌 Initial admin registration code: {init_code}")

# ── Validation patterns ────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-z](?!.*[.-]{2})[a-z0-9.-]{1,14}[a-z0-9]$')
PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$')
def valid_username(u): return USERNAME_RE.match(u)
def valid_password(pw): return PASSWORD_RE.match(pw)

# ── Decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get('user_id')
        if not uid or not User.query.get(uid):
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        u = User.query.get(session.get('user_id'))
        if not u or not u.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapped

# ── Tools for Dashboard ───────────────────────────────────────────────────────
TOOLS = [
    ("Dokumentenablage", "Dateien verwalten", "#"),
    ("Chat-Forum",       "Kommunikation",      "#"),
    ("Terminplanung",    "Kalender & Meetings","#"),
    ("Wissensdatenbank", "Artikel & FAQs",     "#")
]

# ── Page Renderer ─────────────────────────────────────────────────────────────
def render_page(title, body_html):
    uid = session.get('user_id')
    u = User.query.get(uid) if uid else None
    if uid and not u:
        session.clear()
        u = None

    msgs = get_flashed_messages(with_categories=True)
    flash_html = "".join(
        f"<div class='alert alert-{'danger' if cat=='danger' else 'success'}'>{msg}</div>"
        for cat, msg in msgs
    )

    links = []
    if u:
        links += [('Dashboard', url_for('dashboard')), ('Profil', url_for('profile'))]
        if u.is_admin:
            links += [('Users', url_for('users')), ('Admin', url_for('admin'))]
        links.append((f"Logout ({u.username})", url_for('logout')))
    else:
        links += [('Login', url_for('login')), ('Register', url_for('register'))]

    nav_items = "".join(
        f"<li class='nav-item'><a class='nav-link{' active' if request.path==path else ''}' href='{path}'>{text}</a></li>"
        for text, path in links
    )

    return f"""<!doctype html>
<html lang="de"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title} – Intranet</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <style>
    body {{ background:#f8f9fa; }}
    .card:hover {{ transform: translateY(-5px); transition: .2s; }}
    .scroll-container {{ max-height:300px; overflow:auto; padding-right:1rem; }}
    .profile-pic {{ width:150px; height:150px; object-fit:cover; border-radius:50%; }}
  </style>
</head><body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container-fluid">
    <a class="navbar-brand" href="{url_for('dashboard')}"><i class="fas fa-home"></i> Intranet</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbars">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbars">
      <ul class="navbar-nav ms-auto">{nav_items}</ul>
    </div>
  </div>
</nav>
<main class="container my-4">
  <h1 class="mb-4">{title}</h1>
  {flash_html}
  {body_html}
</main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    cards = "".join(f"""
      <div class="col-md-6 col-lg-4">
        <div class="card mb-4 shadow-sm h-100">
          <div class="card-body d-flex flex-column">
            <h5 class="card-title"><i class="fas fa-toolbox me-2"></i>{label}</h5>
            <p class="card-text">{desc}</p>
            <a href="{link}" class="btn btn-outline-primary mt-auto">Öffnen</a>
          </div>
        </div>
      </div>""" for label, desc, link in TOOLS)
    return render_page("Dashboard", f"<div class='row'>{cards}</div>")

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    u = User.query.get(session['user_id'])

    # Update profile info
    if request.method=='POST' and 'update_profile' in request.form:
        u.display_name = request.form.get('display_name','').strip()[:32] or None
        u.pronouns     = request.form.get('pronouns','').strip()[:32] or None
        bio = request.form.get('bio','').strip()
        u.bio = bio[:500] if bio else None
        file = request.files.get('profile_pic')
        if file and file.filename:
            u.profile_pic = file.read()
        db.session.commit()
        flash("Profil gespeichert","success")
        return redirect(url_for('profile'))

    # Setup 2FA
    if request.method=='POST' and 'setup_2fa' in request.form:
        if not u.twofa_secret:
            u.twofa_secret = pyotp.random_base32()
            db.session.commit()
        flash("Scanne den QR‑Code und bestätige mit einem TOTP-Code","info")
        return redirect(url_for('profile'))

    # Confirm 2FA
    if request.method=='POST' and 'confirm_2fa' in request.form:
        token = request.form.get('token','').strip()
        totp = pyotp.TOTP(u.twofa_secret or '')
        if totp.verify(token):
            u.twofa_enabled = True
            db.session.commit()
            flash("2FA aktiviert","success")
        else:
            flash("Ungültiger 2FA-Code","danger")
        return redirect(url_for('profile'))

    # Render profile page
    pic_html = ""
    if u.profile_pic:
        b64 = base64.b64encode(u.profile_pic).decode()
        pic_html = f"<img src='data:image/png;base64,{b64}' class='profile-pic mb-3'>"

    if u.twofa_enabled:
        twofa_html = "<p>2FA ist aktiviert.</p>"
    else:
        if u.twofa_secret:
            uri = pyotp.totp.TOTP(u.twofa_secret).provisioning_uri(u.username, issuer_name="Intranet")
            qr  = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={uri}"
            twofa_html = f"""
            <h5>2FA einrichten</h5>
            <img src="{qr}"><br>
            <form method="post" class="row g-3 mt-2">
              <input type="hidden" name="confirm_2fa">
              <div class="col-auto"><input name="token" class="form-control" placeholder="TOTP-Code"></div>
              <div class="col-auto"><button class="btn btn-primary">Bestätigen</button></div>
            </form>"""
        else:
            twofa_html = """
            <form method="post"><input type="hidden" name="setup_2fa">
              <button class="btn btn-outline-secondary">2FA einrichten</button>
            </form>"""

    body = f"""
<div class="row">
  <div class="col-md-4 text-center">
    {pic_html}
    <form method="post" enctype="multipart/form-data">
      <input type="hidden" name="update_profile">
      <div class="mb-2"><input name="display_name" class="form-control" placeholder="Display Name" value="{u.display_name or ''}"></div>
      <div class="mb-2"><input name="pronouns"     class="form-control" placeholder="Pronomen"      value="{u.pronouns    or ''}"></div>
      <div class="mb-2"><textarea name="bio" class="form-control" placeholder="Bio (max 500)">{u.bio or ''}</textarea></div>
      <div class="mb-3"><input name="profile_pic" type="file" class="form-control"></div>
      <button class="btn btn-success">Speichern</button>
    </form>
  </div>
  <div class="col-md-8">
    <h5>Account</h5>
    <p><strong>Username:</strong> {u.username}</p>
    <p><strong>Erstellt:</strong> {u.created_at.strftime('%Y-%m-%d %H:%M')}</p>
    {twofa_html}
  </div>
</div>
"""
    return render_page("Profil", body)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        code_str = request.form.get('code','').strip()
        username = request.form.get('username','').strip()
        pw       = request.form.get('password','')
        pw2      = request.form.get('confirm','')
        rc = RegistrationCode.query.filter_by(code=code_str, is_active=True).first()
        if not rc:
            flash("Ungültiger Code","danger")
        elif not valid_username(username):
            flash("Username ungültig","danger")
        elif User.query.filter_by(username=username).first():
            flash("Username vergeben","danger")
        elif pw != pw2:
            flash("Passwörter stimmen nicht","danger")
        elif not valid_password(pw):
            flash("Passwortregeln nicht erfüllt","danger")
        else:
            user = User(username=username, is_admin=rc.is_admin)
            user.set_password(pw)
            db.session.add(user)
            rc.use()
            db.session.commit()
            session['user_id'] = user.id
            flash("Registrierung ok","success")
            return redirect(url_for('dashboard'))
    form = """
<form class="row g-3" method="post">
  <div class="col-md-3"><input name="code"     class="form-control" placeholder="Reg-Code"></div>
  <div class="col-md-3"><input name="username" class="form-control" placeholder="Username"></div>
  <div class="col-md-3"><input name="password" type="password" class="form-control" placeholder="Passwort"></div>
  <div class="col-md-3"><input name="confirm"  type="password" class="form-control" placeholder="Wdh. Passwort"></div>
  <div class="col-12"><button class="btn btn-success">Registrieren</button></div>
</form>
"""
    return render_page("Registrieren", form)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        pw       = request.form.get('password','')
        u = User.query.filter_by(username=username).first()
        if not u or not u.check_password(pw):
            flash("Login fehlgeschlagen","danger")
        else:
            session['user_id'] = u.id
            flash("Willkommen","success")
            return redirect(url_for('dashboard'))
    form = """
<form class="row g-3" method="post">
  <div class="col-md-6"><input name="username" class="form-control" placeholder="Username"></div>
  <div class="col-md-6"><input name="password" type="password" class="form-control" placeholder="Passwort"></div>
  <div class="col-12"><button class="btn btn-primary">Login</button></div>
</form>
"""
    return render_page("Login", form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/users', methods=['GET','POST'])
@login_required
@admin_required
def users():
    if request.method == 'POST':
        mu = int(request.form.get('max_uses',1))
        nc = secrets.token_hex(8)
        db.session.add(RegistrationCode(code=nc, max_uses=mu, is_admin=False))
        db.session.commit()
        flash(f"Neuer Code: {nc}","success")
        return redirect(url_for('users'))

    codes_rows = "".join(f"""
      <tr><td>{c.code}</td><td>{c.used}/{c.max_uses}</td>
      <td>{'Admin' if c.is_admin else 'User'}</td>
      <td>{'aktiv' if c.is_active else 'inaktiv'}</td></tr>""" for c in RegistrationCode.query.all())
    codes_section = f"""
<h3>Registrierungs‑Codes</h3>
<div class="scroll-container mb-4">
  <table class="table table-hover">
    <thead><tr><th>Code</th><th>Verw</th><th>Typ</th><th>Status</th></tr></thead>
    <tbody>{codes_rows}</tbody>
  </table>
</div>
<form class="row g-3 mb-4" method="post">
  <div class="col-auto"><input name="max_uses" type="number" class="form-control" value="1" min="1"></div>
  <div class="col-auto"><button class="btn btn-success">Neuen User‑Code</button></div>
</form>
"""
    users_list = "".join(f"""
      <li class='list-group-item d-flex justify-content-between align-items-center'>
        {usr.username}
        <span class='badge bg-{'primary' if usr.is_admin else 'secondary'} rounded-pill'>{'Admin' if usr.is_admin else 'User'}</span>
      </li>""" for usr in User.query.order_by(User.created_at.desc()))
    users_section = f"""
<h3>Alle Nutzer</h3>
<div class="scroll-container">
  <ul class="list-group">{users_list}</ul>
</div>
"""
    return render_page("User‑Verwaltung", codes_section + users_section)

@app.route('/admin')
@login_required
@admin_required
def admin():
    placeholder = "<p>Hier kommen bald erweiterte Admin‑Optionen.</p>"
    return render_page("Admin‑Bereich", placeholder)

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 80))
    app.run(host=host, port=port, debug=True)
