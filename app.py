import os
import csv
import io
import sqlite3
from datetime import datetime, date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, abort

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'clinic.db')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'development-only-change-this-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','nurse')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_no TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            grade_level TEXT NOT NULL,
            section TEXT DEFAULT '',
            birth_date TEXT DEFAULT '',
            guardian_name TEXT DEFAULT '',
            guardian_contact TEXT DEFAULT '',
            allergies TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            visit_date TEXT NOT NULL,
            visit_time TEXT NOT NULL,
            complaint TEXT NOT NULL,
            action_taken TEXT DEFAULT '',
            referred_to TEXT DEFAULT '',
            recorded_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            visit_id INTEGER REFERENCES visits(id) ON DELETE SET NULL,
            recorded_at TEXT NOT NULL,
            temperature REAL,
            systolic INTEGER,
            diastolic INTEGER,
            pulse INTEGER,
            respiratory_rate INTEGER,
            height_cm REAL,
            weight_kg REAL,
            notes TEXT DEFAULT '',
            recorded_by TEXT NOT NULL
        );
        ''')
        # Demo-only accounts. Change these passwords before any real deployment.
        if not con.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            con.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',
                        ('admin', generate_password_hash('Clinic@12345'), 'admin', datetime.now().isoformat(timespec='seconds')))
            con.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',
                        ('nurse', generate_password_hash('Nurse@12345'), 'nurse', datetime.now().isoformat(timespec='seconds')))


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def now_stamp():
    return datetime.now().isoformat(timespec='seconds')


@app.context_processor
def inject_globals():
    return {'today': date.today().isoformat(), 'current_time': datetime.now().strftime('%H:%M'), 'current_user': session.get('username'), 'current_role': session.get('role')}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with db() as con:
            user = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session.update(user_id=user['id'], username=user['username'], role=user['role'])
            return redirect(url_for('dashboard'))
        flash('Incorrect username or password.', 'error')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    response = redirect(url_for('login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    flash('You have successfully logged out.', 'success')
    return response


@app.route('/')
@login_required
def dashboard():
    with db() as con:
        students = con.execute('SELECT COUNT(*) n FROM students').fetchone()['n']
        visits_today = con.execute('SELECT COUNT(*) n FROM visits WHERE visit_date=?', (date.today().isoformat(),)).fetchone()['n']
        total_visits = con.execute('SELECT COUNT(*) n FROM visits').fetchone()['n']
        recent = con.execute('''SELECT v.id,v.visit_date,v.visit_time,v.complaint,v.action_taken,s.student_no,s.full_name
                                FROM visits v JOIN students s ON s.id=v.student_id
                                ORDER BY v.visit_date DESC,v.visit_time DESC,v.id DESC LIMIT 7''').fetchall()
        daily = con.execute('''SELECT visit_date,COUNT(*) total FROM visits
                               WHERE visit_date >= date('now','-6 days') GROUP BY visit_date ORDER BY visit_date''').fetchall()
        complaints = con.execute('''SELECT complaint,COUNT(*) total FROM visits GROUP BY complaint ORDER BY total DESC LIMIT 6''').fetchall()
    return render_template('dashboard.html', students=students, visits_today=visits_today,
                           total_visits=total_visits, recent=recent,
                           daily_labels=[r['visit_date'] for r in daily], daily_values=[r['total'] for r in daily],
                           complaint_labels=[r['complaint'] for r in complaints], complaint_values=[r['total'] for r in complaints])


@app.route('/students')
@login_required
def students():
    q = request.args.get('q', '').strip()
    with db() as con:
        if q:
            rows = con.execute('''SELECT * FROM students WHERE student_no LIKE ? OR full_name LIKE ?
                                  ORDER BY full_name''', (f'%{q}%', f'%{q}%')).fetchall()
        else:
            rows = con.execute('SELECT * FROM students ORDER BY full_name').fetchall()
    return render_template('students.html', students=rows, q=q)


@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if request.method == 'POST':
        fields = {k: request.form.get(k, '').strip() for k in
                  ['student_no','full_name','grade_level','section','birth_date','guardian_name','guardian_contact','allergies','notes']}
        if not fields['student_no'] or not fields['full_name'] or not fields['grade_level']:
            flash('Student number, full name, and grade level are required.', 'error')
            return render_template('student_form.html', student=fields)
        try:
            with db() as con:
                con.execute('''INSERT INTO students(student_no,full_name,grade_level,section,birth_date,guardian_name,
                               guardian_contact,allergies,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',
                            (*[fields[k] for k in ['student_no','full_name','grade_level','section','birth_date','guardian_name','guardian_contact','allergies','notes']], now_stamp()))
            flash('Student record added.', 'success')
            return redirect(url_for('students'))
        except sqlite3.IntegrityError:
            flash('That student number already exists.', 'error')
    return render_template('student_form.html', student={})


@app.route('/students/<int:student_id>')
@login_required
def student_detail(student_id):
    with db() as con:
        student = con.execute('SELECT * FROM students WHERE id=?', (student_id,)).fetchone()
        if not student: abort(404)
        visits = con.execute('SELECT * FROM visits WHERE student_id=? ORDER BY visit_date DESC,visit_time DESC', (student_id,)).fetchall()
        vitals = con.execute('SELECT * FROM vitals WHERE student_id=? ORDER BY recorded_at DESC LIMIT 10', (student_id,)).fetchall()
    return render_template('student_detail.html', student=student, visits=visits, vitals=vitals)


@app.route('/visits/add', methods=['GET', 'POST'])
@login_required
def add_visit():
    with db() as con:
        roster = con.execute('SELECT id,student_no,full_name FROM students ORDER BY full_name').fetchall()
    if request.method == 'POST':
        student_id = request.form.get('student_id', type=int)
        visit_date = request.form.get('visit_date', '')
        visit_time = request.form.get('visit_time', '')
        complaint = request.form.get('complaint', '').strip()
        action = request.form.get('action_taken', '').strip()
        referred = request.form.get('referred_to', '').strip()
        if not student_id or not visit_date or not visit_time or not complaint:
            flash('Student, date, time, and reason for visit are required.', 'error')
            return render_template('visit_form.html', students=roster)
        with db() as con:
            exists = con.execute('SELECT 1 FROM students WHERE id=?', (student_id,)).fetchone()
            if not exists: abort(400)
            cur = con.execute('''INSERT INTO visits(student_id,visit_date,visit_time,complaint,action_taken,referred_to,recorded_by,created_at)
                                 VALUES(?,?,?,?,?,?,?,?)''', (student_id,visit_date,visit_time,complaint,action,referred,session['username'],now_stamp()))
            visit_id = cur.lastrowid
        flash('Clinic visit recorded.', 'success')
        return redirect(url_for('add_vitals', student_id=student_id, visit_id=visit_id))
    return render_template('visit_form.html', students=roster)


@app.route('/vitals/add', methods=['GET', 'POST'])
@login_required
def add_vitals():
    student_id = request.args.get('student_id', type=int) or request.form.get('student_id', type=int)
    visit_id = request.args.get('visit_id', type=int) or request.form.get('visit_id', type=int)
    with db() as con:
        roster = con.execute('SELECT id,student_no,full_name FROM students ORDER BY full_name').fetchall()
        selected = con.execute('SELECT * FROM students WHERE id=?', (student_id,)).fetchone() if student_id else None
        if student_id and not selected: abort(404)
    if request.method == 'POST':
        def num(name, cast=float):
            raw = request.form.get(name, '').strip()
            return cast(raw) if raw else None
        try:
            vals = (student_id, visit_id, now_stamp(), num('temperature'), num('systolic', int), num('diastolic', int),
                    num('pulse', int), num('respiratory_rate', int), num('height_cm'), num('weight_kg'),
                    request.form.get('notes','').strip(), session['username'])
            if not student_id: raise ValueError
            with db() as con:
                con.execute('''INSERT INTO vitals(student_id,visit_id,recorded_at,temperature,systolic,diastolic,pulse,
                               respiratory_rate,height_cm,weight_kg,notes,recorded_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''', vals)
            flash('Vital signs saved.', 'success')
            return redirect(url_for('student_detail', student_id=student_id))
        except (ValueError, TypeError):
            flash('Check the student selection and numeric vital-sign values.', 'error')
    return render_template('vitals_form.html', students=roster, selected=selected, student_id=student_id, visit_id=visit_id)


@app.route('/reports')
@login_required
def reports():
    with db() as con:
        visits = con.execute('''SELECT v.visit_date,v.visit_time,s.student_no,s.full_name,v.complaint,v.action_taken,v.referred_to,v.recorded_by
                                FROM visits v JOIN students s ON s.id=v.student_id
                                ORDER BY v.visit_date DESC,v.visit_time DESC''').fetchall()
    return render_template('reports.html', visits=visits)


@app.route('/reports/export')
@login_required
def export_reports():
    with db() as con:
        rows = con.execute('''SELECT v.visit_date,v.visit_time,s.student_no,s.full_name,v.complaint,v.action_taken,v.referred_to,v.recorded_by
                              FROM visits v JOIN students s ON s.id=v.student_id ORDER BY v.visit_date DESC,v.visit_time DESC''').fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Visit Date','Visit Time','Student No.','Student Name','Complaint','Action Taken','Referred To','Recorded By'])
    writer.writerows([tuple(r) for r in rows])
    return Response('\ufeff' + output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=clinic_visits_report.csv'})


@app.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        role = request.form.get('role','nurse')
        if not username or len(password) < 10 or role not in ('admin','nurse'):
            flash('Enter a username, a password of at least 10 characters, and a valid role.', 'error')
        else:
            try:
                with db() as con:
                    con.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',
                                (username,generate_password_hash(password),role,now_stamp()))
                flash('User account created.', 'success')
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
        return redirect(url_for('users'))
    with db() as con:
        rows = con.execute('SELECT id,username,role,created_at FROM users ORDER BY username').fetchall()
    return render_template('users.html', users=rows)


@app.errorhandler(403)
def forbidden(_):
    return render_template('error.html', code=403, message='You do not have permission to view this page.'), 403


@app.errorhandler(404)
def not_found(_):
    return render_template('error.html', code=404, message='The requested page or record could not be found.'), 404


init_db()

if __name__ == '__main__':
    app.run(debug=True)
