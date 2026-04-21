from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import Markup
import sqlite3
import os
app = Flask(__name__)
app.secret_key = os.getenv("Your Secret key")

# -------------------------------------------- Database Creation --------------------------------------------
def init_db():
    conn = sqlite3.connect('user_detail.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

# ----------------------------------------------- Home ------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' not in session:         # not logged in → kick to log in
        return redirect(url_for('login'))
    return render_template('index.html', id=session['user_id'])

# ------------------------------------------------ REGISTER -------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return "Missing email or password!"

        conn = sqlite3.connect('user_detail.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return "User already exists!"

        cursor.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, password, 'user')
        )
        conn.commit()
        conn.close()

        return redirect('/login')   # after register → go to log in

    return render_template('register.html', mode='register')

# ----------------------------------------- LOGIN (Exploitable) ---------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return "Missing email or password!"

        conn = sqlite3.connect('user_detail.db')
        conn.row_factory = sqlite3.Row   # access columns by name
        cursor = conn.cursor()

        cursor.execute(f"SELECT * FROM users WHERE email ='{email}'")
        user = cursor.fetchone()
        conn.close()

        if not user:
            return "User does not exist!"

        if user['password'] != password:
            return "Wrong password!"

        # ✅ Save to session — this is what "logged in" means
        session['user_id'] = user['id']
        session['email']   = user['email']
        session['role']    = user['role'] 

        return redirect(url_for('index')) 

    return render_template('login.html', mode='login')


# -------------------------------------------------- LOGOUT -------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------------------------------------------- XSS --------------------------------------------------
@app.route('/xss', methods=['GET', 'POST'])
def xss():
    if 'user_id' not in session:         # protect this route too
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_level = request.form.get('level')
        payload = request.form.get('payload')

        if current_level == "1":
            result = Markup(payload)
            return render_template('xss.html', result=result, level=current_level)

        elif current_level == "2":
            result = Markup(payload)
            return render_template('xss.html', result=result, level=current_level)

        elif current_level == "3":
            filtered = payload.replace("script", "")
            result = Markup(filtered)
            return render_template('xss.html', result=result, level=current_level)

        elif current_level == "4":
            result = Markup(payload)
            return render_template('xss.html', result=result, level=current_level)

        elif current_level == "5":
            result = Markup(payload)
            return render_template('xss.html', result=result, level=current_level)

    return render_template('xss.html')


# ----------------------------------------------------- IDOR ---------------------------------------------------------------------

@app.route('/profile')
def base_profile():
    # 1. If they aren't logged in, send them to the login page
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 2. Grab their specific ID from the active session
    current_user_id = session['user_id']

    # 3. Redirect them to the parameterized route, filling in their ID automatically
    return redirect(url_for('profile', user_id=current_user_id))


@app.route('/profile/<int:user_id>')
def profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('user_detail.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()


    if not user:
        return "User does not exist! Try another ID"

    return render_template('profile.html', user=user, is_own=( user_id == session['user_id'] ))

# -------------------------------------------------- File Upload --------------------------------------------

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:        # ← add this
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']

        if file.filename == '':
            return "No File Selected!"

        save_path = os.path.join('static', 'uploads', file.filename)
        file.save(save_path)
        uploaded_file = file.filename

        return render_template("upload.html", uploaded_file=uploaded_file)
    return render_template("upload.html")

if __name__ == '__main__':
    init_db()
    app.run(debug=False)