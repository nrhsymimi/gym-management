from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from forms import LoginForm, MemberForm, ClassForm, RegisterClassForm
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.permanent_session_lifetime = timedelta(minutes=15)
csrf = CSRFProtect(app)

DATABASE = 'gym.db'

# --- Database Connection ---
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Auth Decorators ---
def login_required(view):
    def wrapped_view(**kwargs):
        if 'username' not in session:
            flash('Please login to continue.', 'error')
            return redirect(url_for('login'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

def staff_required(view):
    def wrapped_view(**kwargs):
        if 'username' not in session or session.get('role') != 'staff':
            flash("Access denied: Staff only.", 'error')
            return redirect(url_for('login'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            return redirect(url_for('dashboard'))

        flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/add_member', methods=['GET', 'POST'])
@staff_required
def add_member():
    form = MemberForm()
    if form.validate_on_submit():
        with get_db() as conn:
            conn.execute("INSERT INTO members (name, status) VALUES (?, ?)",
                         (form.name.data, form.status.data))
        flash('Member added successfully!', 'success')
        return redirect(url_for('view_members'))
    return render_template('add_member.html', form=form)

@app.route('/register_member', methods=['GET', 'POST'])
@staff_required
def register_member():
    form = MemberForm()
    if form.validate_on_submit():
        with get_db() as conn:
            conn.execute("INSERT INTO members (name, status) VALUES (?, ?)",
                         (form.name.data, form.status.data))
        flash('Member registered successfully.', 'success')
        return redirect(url_for('view_members'))
    return render_template('register_member.html', form=form)

@app.route('/view_members')
@login_required
def view_members():
    with get_db() as conn:
        members = conn.execute("SELECT * FROM members").fetchall()
    return render_template('view_members.html', members=members)

@app.route('/add_class', methods=['GET', 'POST'])
@staff_required
def add_class():
    form = ClassForm()
    if form.validate_on_submit():
        class_name = form.class_name.data
        class_time = form.class_time.data

        with get_db() as conn:
            conn.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)",
                         (class_name, class_time))

        flash('Class added successfully!', 'success')
        return redirect(url_for('view_classes'))

    return render_template('add_class.html', form=form)

@app.route('/view_classes')
@login_required
def view_classes():
    with get_db() as conn:
        classes = conn.execute("SELECT * FROM classes").fetchall()
    return render_template('view_classes.html', classes=classes)

@app.route('/member_classes/<int:member_id>')
@login_required
def member_classes(member_id):
    with get_db() as conn:
        member = conn.execute("SELECT * FROM members WHERE id = ?", (member_id,)).fetchone()
        classes = conn.execute("""
            SELECT c.class_name, c.class_time FROM member_classes mc
            JOIN classes c ON mc.class_id = c.id
            WHERE mc.member_id = ?
        """, (member_id,)).fetchall()
    return render_template('member_classes.html', member=member, classes=classes)

@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
@login_required
def register_class(member_id):
    form = RegisterClassForm()

    with get_db() as conn:
        member = conn.execute("SELECT * FROM members WHERE id = ?", (member_id,)).fetchone()
        all_classes = conn.execute("SELECT * FROM classes").fetchall()

        form.class_id.choices = [(c['id'], f"{c['class_name']} ({c['class_time']})") for c in all_classes]

        if form.validate_on_submit():
            conn.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)",
                         (member_id, form.class_id.data))
            flash('Class registered successfully!', 'success')
            return redirect(url_for('member_classes', member_id=member_id))

    return render_template('register_class.html', form=form, member=member)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Initialize Database ---
def init_db():
    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
            c.execute("CREATE TABLE members (id INTEGER PRIMARY KEY, name TEXT, status TEXT)")
            c.execute("CREATE TABLE classes (id INTEGER PRIMARY KEY, class_name TEXT, class_time TEXT)")
            c.execute("CREATE TABLE member_classes (id INTEGER PRIMARY KEY, member_id INTEGER, class_id INTEGER)")

            hashed_pw = generate_password_hash('karim')  # Default password for staff user
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ('pakkarim', hashed_pw, 'staff'))

# --- Run App ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
