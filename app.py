import os, json, datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-secure-2026-global'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- МОДЕЛИ ДАННЫХ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_main = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- РАБОТА С ФАЙЛАМИ (JSON) ---
JSON_FILE = 'scams.json'
LOG_FILE = 'activity_log.json'
REPORTS_FILE = 'reports.json'

def load_data(file):
    if not os.path.exists(file): return []
    with open(file, 'r', encoding='utf-8') as f:
        try: return json.load(f)
        except: return []

def save_data(file, data):
    with open(file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def save_log(action):
    logs = load_data(LOG_FILE)
    logs.append({
        "user": current_user.username if current_user.is_authenticated else "System",
        "action": action,
        "time": datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    })
    save_data(LOG_FILE, logs[-100:]) # Только последние 100 действий

# Инициализация БД
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="SCAM.BASE").first():
        hashed_pw = generate_password_hash("qwert123321", method='pbkdf2:sha256')
        db.session.add(User(username="SCAM.BASE", password=hashed_pw, is_main=True))
        db.session.commit()

# --- МАРШРУТЫ ---

@app.route('/')
def index():
    query = request.args.get('q', '').lower()
    all_scams = load_data(JSON_FILE)
    if query:
        filtered = [s for s in all_scams if query in s['url'].lower() or query in s['description'].lower()]
    else:
        filtered = all_scams
    return render_template('index.html', sites=list(reversed(filtered)), query=query)

@app.route('/report', methods=['POST'])
def report_scam():
    reports = load_data(REPORTS_FILE)
    reports.append({
        "id": len(reports) + 1,
        "url": request.form.get('url'),
        "description": request.form.get('description'),
        "time": datetime.datetime.now().strftime("%d.%m.%Y")
    })
    save_data(REPORTS_FILE, reports)
    flash('Жалоба отправлена на модерацию!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            save_log("Вошел в систему")
            return redirect(url_for('admin_panel'))
    return render_template('login.html')

@app.route('/admin')
@login_required
def admin_panel():
    return render_template('admin.html',
                           sites=list(reversed(load_data(JSON_FILE))),
                           admins=User.query.all() if current_user.is_main else [],
                           logs=list(reversed(load_data(LOG_FILE))),
                           reports=load_data(REPORTS_FILE))

@app.route('/add_site', methods=['POST'])
@login_required
def add_site():
    scams = load_data(JSON_FILE)
    url = request.form.get('url')
    scams.append({
        "id": len(scams) + 1,
        "url": url,
        "description": request.form.get('description'),
        "added_by": current_user.username
    })
    save_data(JSON_FILE, scams)
    save_log(f"Добавил сайт: {url}")
    return redirect(url_for('admin_panel'))

@app.route('/delete_site/<int:site_id>')
@login_required
def delete_site(site_id):
    scams = load_data(JSON_FILE)
    scams = [s for s in scams if s['id'] != site_id]
    save_data(JSON_FILE, scams)
    save_log(f"Удалил сайт ID: {site_id}")
    return redirect(url_for('admin_panel'))

@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    if not current_user.is_main: return "Error", 403
    name = request.form.get('username')
    new_u = User(username=name, password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256'))
    db.session.add(new_u)
    db.session.commit()
    save_log(f"Создал нового админа: {name}")
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    save_log("Вышел из системы")
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
