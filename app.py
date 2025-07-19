# app.py
import os
import secrets
import re
import io
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
import qrcode
from PIL import Image

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv()

# ── App & Config ─────────────────────────────────────────────────────────────
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY','devkey123'),
    SQLALCHEMY_DATABASE_URI=os.getenv(
        'DATABASE_URL',
        f"sqlite:///{os.path.join(basedir,'intranet.db')}"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)
db = SQLAlchemy(app)

# ── Models ────────────────────────────────────────────────────────────────────
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
    salt           = db.Column(db.String(32), nullable=False)
    password_hash  = db.Column(db.String(128), nullable=False)
    display_name   = db.Column(db.String(32), nullable=True)
    profile_pic    = db.Column(db.LargeBinary, nullable=True)
    bio            = db.Column(db.String(500), nullable=True)
    pronouns       = db.Column(db.String(32), nullable=True)
    twofa_enabled  = db.Column(db.Boolean, default=False)
    twofa_secret   = db.Column(db.String(32), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin       = db.Column(db.Boolean, default=False)
    contacts       = db.relationship('Contact', backref='user', cascade="all,delete-orphan")
    backup_codes   = db.relationship('BackupCode', backref='user', cascade="all,delete-orphan")
    def set_password(self, pw):
        self.salt = secrets.token_hex(16)
        self.password_hash = generate_password_hash(self.salt + pw)
    def check_password(self, pw):
        return check_password_hash(self.password_hash, self.salt + pw)

class Contact(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type    = db.Column(db.String(32), nullable=False)
    custom  = db.Column(db.String(32), nullable=True)
    value   = db.Column(db.String(128), nullable=False)
    order   = db.Column(db.Integer, nullable=False)

class BackupCode(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_hash  = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active  = db.Column(db.Boolean, default=True)

# ── Initialization ────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    if User.query.filter_by(is_admin=True).count()==0 and \
       RegistrationCode.query.filter_by(is_admin=True, is_active=True).count()==0:
        init_code = secrets.token_hex(8)
        db.session.add(RegistrationCode(code=init_code, max_uses=1, is_admin=True))
        db.session.commit()
        print(f"📌 Initial admin registration code: {init_code}")

# ── Helpers ───────────────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-z](?!.*[.-]{2})[a-z0-9.-]{1,14}[a-z0-9]$')
PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$')
def valid_username(u): return USERNAME_RE.match(u)
def valid_password(pw): return PASSWORD_RE.match(pw)

def login_required(f):
    @wraps(f)
    def wrapped(*a,**k):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*a,**k)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*a,**k):
        u = User.query.get(session.get('user_id'))
        if not u or not u.is_admin:
            abort(403)
        return f(*a,**k)
    return wrapped

TOOLS = [
    ("Dokumentenablage","Dateien verwalten","#"),
    ("Chat-Forum",      "Kommunikation",     "#"),
    ("Terminplanung",   "Kalender & Meetings","#"),
    ("Wissensdatenbank","Artikel & FAQs",    "#")
]

def render_page(title, body):
    u = None
    if session.get('user_id'):
        u = User.query.get(session['user_id'])
        if not u: session.clear()
    msgs = get_flashed_messages(with_categories=True)
    nav = []
    if u:
        nav += [('Dashboard','dashboard'),('Profil','profile')]
        if u.is_admin: nav += [('Users','users'),('Admin','admin')]
        nav.append((f"Logout ({u.username})",'logout'))
    else:
        nav = [('Login','login'),('Register','register')]
    items = ''.join(
        f"<li class='nav-item'><a class='nav-link{' active' if request.endpoint==ep else ''}' href=\"{url_for(ep)}\">{t}</a></li>"
        for t,ep in nav
    )
    flash_html = ''.join(
        f"<div class='alert alert-{'danger' if c=='danger' else 'success'}'>{m}</div>"
        for c,m in msgs
    )
    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>.scroll{{max-height:200px;overflow:auto}}</style>
</head><body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary"><div class="container-fluid">
<a class="navbar-brand" href="{url_for('dashboard')}">Intranet</a>
<button class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#nav"><span class="navbar-toggler-icon"></span></button>
<div class="collapse navbar-collapse" id="nav"><ul class="navbar-nav ms-auto">{items}</ul></div>
</div></nav>
<main class="container my-4"><h1>{title}</h1>{flash_html}{body}</main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>"""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    cards = ''.join(f"<div class='col-md-3'><div class='card mb-3'><div class='card-body'>"
                    f"<h5>{lbl}</h5><p>{desc}</p></div></div></div>"
                    for lbl,desc,_ in TOOLS)
    return render_page("Dashboard", f"<div class='row'>{cards}</div>")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = User.query.filter_by(username=request.form['username'].strip()).first()
        if not u or not u.check_password(request.form['password']):
            flash("Login fehlgeschlagen","danger")
            return redirect(url_for('login'))
        session['pre_2fa'] = u.id
        if u.twofa_enabled:
            return redirect(url_for('twofa'))
        session['user_id'] = u.id
        flash("Willkommen","success")
        return redirect(url_for('dashboard'))
    return render_page("Login", """
<form class="row g-3" method="post">
  <div class="col-md-6"><input name="username" class="form-control" placeholder="Username"></div>
  <div class="col-md-6"><input name="password" type="password" class="form-control" placeholder="Passwort"></div>
  <div class="col-12"><button class="btn btn-primary">Login</button></div>
</form>
""")

@app.route('/twofa', methods=['GET','POST'])
def twofa():
    uid = session.get('pre_2fa')
    if not uid:
        return redirect(url_for('login'))
    u = User.query.get(uid)
    if request.method=='POST':
        token = request.form['token'].strip()
        ok = pyotp.TOTP(u.twofa_secret).verify(token)
        if not ok:
            for bc in u.backup_codes:
                if bc.is_active and check_password_hash(bc.code_hash, token):
                    bc.is_active = False
                    db.session.commit()
                    ok = True
                    break
        if ok:
            session.pop('pre_2fa',None)
            session['user_id'] = u.id
            flash("Erfolgreich eingeloggt","success")
            return redirect(url_for('dashboard'))
        flash("Ungültiger Code","danger")
    return render_page("2FA", """
<form class="row g-3" method="post">
  <div class="col-md-8"><input name="token" class="form-control" placeholder="TOTP- oder Backup-Code"></div>
  <div class="col-md-4"><button class="btn btn-primary">Bestätigen</button></div>
</form>
""")

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    u = User.query.get(session['user_id'])
    if request.method=='POST':
        if 'update_profile' in request.form:
            u.display_name = request.form.get('display_name','')[:32] or None
            u.pronouns     = request.form.get('pronouns','')[:32] or None
            u.bio          = request.form.get('bio','')[:500] or None
            pic = request.files.get('profile_pic')
            if pic and pic.filename:
                img = Image.open(pic.stream).convert('RGB')
                w,h = img.size
                m = min(w,h)
                left = (w-m)//2; top = (h-m)//2
                img = img.crop((left, top, left+m, top+m))
                resample = Image.NEAREST if m<512 else Image.BICUBIC
                img = img.resize((512,512), resample=resample)
                buf = io.BytesIO(); img.save(buf, format='PNG')
                u.profile_pic = buf.getvalue()
            Contact.query.filter_by(user=u).delete()
            idxs = {k.split('_')[-1] for k in request.form if k.startswith('contact_type_')}
            for i in idxs:
                ctype = request.form.get(f'contact_type_{i}','')
                custom = request.form.get(f'contact_custom_{i}','') if ctype=='Andere' else None
                cval = request.form.get(f'contact_val_{i}','').strip()
                if ctype and cval:
                    order = int(i)
                    db.session.add(Contact(user=u, type=ctype, custom=custom, value=cval, order=order))
            db.session.commit()
            flash("Profil gespeichert","success")
            return redirect(url_for('profile'))
        if 'setup_2fa' in request.form:
            if not u.twofa_secret:
                u.twofa_secret = pyotp.random_base32(); db.session.commit()
            flash("Scanne den QR und bestätige","info"); return redirect(url_for('profile'))
        if 'confirm_2fa' in request.form:
            token = request.form['token'].strip()
            if pyotp.TOTP(u.twofa_secret).verify(token):
                u.twofa_enabled = True; db.session.commit(); flash("2FA aktiviert","success")
            else: flash("Ungültiger 2FA-Code","danger")
            return redirect(url_for('profile'))
        if 'gen_backup' in request.form:
            new = secrets.token_urlsafe(12)
            db.session.add(BackupCode(user=u, code_hash=generate_password_hash(new)))
            db.session.commit(); flash(f"Backup-Code: {new}","info")
            return redirect(url_for('profile'))

    # sort contacts by order
    u.contacts.sort(key=lambda c: c.order)
    cnt_html = ''
    for c in u.contacts:
        i = c.order
        sel = lambda opt: 'selected' if c.type==opt else ''
        custom_input = f'<input name="contact_custom_{i}" class="form-control" placeholder="Kategorie" value="{c.custom or ""}">' if c.type=='Andere' else ''
        val_type = 'email' if c.type=='E-Mail' else 'tel' if c.type in ['Mobil','Festnetz'] else 'text'
        cnt_html += f"""
    <div class="input-group mb-2" id="contact_{i}" draggable="true" ondragstart="dragStart(event)" ondrop="drop(event)" ondragover="allowDrop(event)">
      <select name="contact_type_{i}" class="form-select" onchange="onTypeChange(this)">
        <option {sel('Mobil')}>Mobil</option>
        <option {sel('Festnetz')}>Festnetz</option>
        <option {sel('E-Mail')}>E-Mail</option>
        <option {sel('Andere')}>Andere</option>
      </select>
      {custom_input}
      <input name="contact_val_{i}" type="{val_type}" class="form-control" value="{c.value}">
      <button type="button" class="btn btn-danger" onclick="removeContact('{i}')">✕</button>
    </div>"""

    # backup codes
    bc_html = '<ul class="list-group mb-3">'
    for bc in u.backup_codes:
        status = 'aktiv' if bc.is_active else 'inaktiv'
        bc_html += f"""
      <li class="list-group-item d-flex justify-content-between">
        <span>{bc.created_at.strftime('%Y-%m-%d')}</span>
        <span>{status}</span>
        <a href="#" onclick="toggleBC({bc.id})">Toggle</a>
        <a href="#" onclick="delBC({bc.id})">Löschen</a>
      </li>"""
    bc_html += '</ul>'

    pic_html = ''
    if u.profile_pic:
        b64 = base64.b64encode(u.profile_pic).decode()
        pic_html = f"<img src='data:image/png;base64,{b64}' class='img-thumbnail mb-3' style='width:150px;height:150px;'>"

    body = f"""
<form method="post" enctype="multipart/form-data">
  <input type="hidden" name="update_profile">
  {pic_html}
  <div class="mb-2"><input name="display_name" class="form-control" placeholder="Display Name" value="{u.display_name or ''}"></div>
  <div class="mb-2"><input name="pronouns"     class="form-control" placeholder="Pronomen"      value="{u.pronouns    or ''}"></div>
  <div class="mb-2"><textarea name="bio" class="form-control" placeholder="Bio (max 500)">{u.bio or ''}</textarea></div>
  <div class="mb-3"><input name="profile_pic" type="file" accept="image/*" class="form-control"></div>
  <hr>
  <h5>Kontakte <button type="button" class="btn btn-sm btn-outline-primary" onclick="addContact()">＋</button></h5>
  <div id="contacts">{cnt_html}</div>
  <button class="btn btn-success mt-2">Speichern</button>
</form>
<hr>
<h5>2FA <form method="post" style="display:inline"><button name="setup_2fa" class="btn btn-sm btn-outline-secondary">Einrichten</button></form></h5>
"""
    if u.twofa_secret and not u.twofa_enabled:
        uri = pyotp.TOTP(u.twofa_secret).provisioning_uri(u.username, issuer_name="Intranet")
        qr_img = qrcode.make(uri); buf = io.BytesIO(); qr_img.save(buf,format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        body += f"""
<img src="data:image/png;base64,{qr_b64}" class="mb-3"><br>
<form method="post"><input type="hidden" name="confirm_2fa">
  <div class="input-group mb-3">
    <input name="token" class="form-control" placeholder="TOTP-Code">
    <button class="btn btn-primary">Bestätigen</button>
  </div>
</form>
"""
    elif u.twofa_enabled:
        body += "<p>2FA ist aktiviert.</p>"
    body += f"""
<hr>
<h5>Backup-Codes <form method="post" style="display:inline"><button name="gen_backup" class="btn btn-sm btn-outline-secondary">Neu</button></form></h5>
{bc_html}
<script>
// Drag & Drop
let dragged;
function dragStart(e) {{ dragged = e.target; }}
function allowDrop(e) {{ e.preventDefault(); }}
function drop(e) {{
  e.preventDefault();
  if (e.target.id === 'contacts') return;
  const parent = dragged.parentNode;
  parent.insertBefore(dragged, e.target.nextSibling);
}}

// Contacts dynamic
let cnt = {len(u.contacts)};
function addContact() {{
  const div = document.createElement('div');
  div.className = 'input-group mb-2'; div.id = 'contact_' + cnt;
  div.draggable = true; div.ondragstart = dragStart; div.ondrop = drop; div.ondragover = allowDrop;
  div.innerHTML = `
    <select name="contact_type_${{cnt}}" class="form-select" onchange="onTypeChange(this)">
      <option>Mobil</option><option>Festnetz</option>
      <option>E-Mail</option><option>Andere</option>
    </select>
    <input name="contact_custom_${{cnt}}" class="form-control" placeholder="Kategorie" style="display:none;">
    <input name="contact_val_${{cnt}}" type="text" class="form-control" placeholder="Wert">
    <button type="button" class="btn btn-danger" onclick="removeContact('${{cnt}}')">✕</button>`;
  document.getElementById('contacts').append(div);
  cnt++;
}}
function removeContact(i) {{ document.getElementById('contact_' + i).remove(); }}
function onTypeChange(sel) {{
  const div = sel.parentNode;
  const custom = div.querySelector(`[name="contact_custom_${'{'}sel.name.split('_').pop(){'}'}"]`);
  const val = div.querySelector(`[name="contact_val_${'{'}sel.name.split('_').pop(){'}'}"]`);
  if (sel.value === 'Andere') {{
    custom.style.display = 'block';
    val.type = 'text';
  }} else {{
    custom.style.display = 'none';
    if (sel.value === 'E-Mail') val.type = 'email';
    else val.type = 'tel';
  }}
}}

// Backup code AJAX
async function toggleBC(id) {{
  await fetch(`/backup/${{id}}/toggle`, {{ method: 'POST' }});
  location.reload();
}}
async function delBC(id) {{
  await fetch(`/backup/${{id}}`, {{ method: 'DELETE' }});
  location.reload();
}}
</script>
"""
    return render_page("Profil", body)

@app.route('/backup/<int:bc_id>/toggle', methods=['POST'])
@login_required
def toggle_backup(bc_id):
    bc = BackupCode.query.get_or_404(bc_id)
    bc.is_active = not bc.is_active
    db.session.commit()
    return ('', 204)

@app.route('/backup/<int:bc_id>', methods=['DELETE'])
@login_required
def delete_backup(bc_id):
    bc = BackupCode.query.get_or_404(bc_id)
    db.session.delete(bc)
    db.session.commit()
    return ('', 204)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        code_str = request.form['code'].strip()
        username = request.form['username'].strip()
        pw = request.form['password']; pw2 = request.form['confirm']
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
            u = User(username=username, is_admin=rc.is_admin)
            u.set_password(pw)
            db.session.add(u); rc.use(); db.session.commit()
            session['user_id'] = u.id; flash("Registrierung ok","success")
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

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/users', methods=['GET','POST'])
@login_required
@admin_required
def users():
    if request.method=='POST':
        mu = int(request.form['max_uses'])
        nc = secrets.token_hex(8)
        db.session.add(RegistrationCode(code=nc, max_uses=mu, is_admin=False))
        db.session.commit(); flash(f"Neuer Code: {nc}","success")
        return redirect(url_for('users'))
    codes_rows = ''.join(f"<tr><td>{c.code}</td><td>{c.used}/{c.max_uses}</td>"
                         f"<td>{'Admin' if c.is_admin else 'User'}</td>"
                         f"<td>{'aktiv' if c.is_active else 'inaktiv'}</td></tr>"
                         for c in RegistrationCode.query.all())
    users_list = ''.join(f"<li class='list-group-item d-flex justify-content-between'>"
                         f"{usr.username}<span class='badge bg-{'primary' if usr.is_admin else 'secondary'}'>"
                         f"{'Admin' if usr.is_admin else 'User'}</span></li>"
                         for usr in User.query.order_by(User.created_at.desc()))
    body = f"""
<h3>Registrierungs-Codes</h3>
<form class="row g-3 mb-3" method="post">
  <div class="col-auto"><input name="max_uses" type="number" value="1" min="1" class="form-control"></div>
  <div class="col-auto"><button class="btn btn-success">Neuen Code</button></div>
</form>
<div class="scroll mb-3">
  <table class="table"><thead><tr><th>Code</th><th>Verwendungen</th><th>Typ</th><th>Status</th></tr></thead>
  <tbody>{codes_rows}</tbody></table>
</div>
<h3>Alle Nutzer</h3>
<div class="scroll"><ul class="list-group">{users_list}</ul></div>
"""
    return render_page("User-Verwaltung", body)

@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_page("Admin-Bereich", "<p>Erweiterte Admin-Optionen folgen.</p>")

if __name__=='__main__':
    app.run(host=os.getenv('HOST','0.0.0.0'), port=int(os.getenv('PORT',80)), debug=True)
