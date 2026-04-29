from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'cheie_slaba_de_test'

app.config.update(
    SESSION_COOKIE_HTTPONLY=False
)

# VULNERABILITATE 4.5: Sesiuni nesigure (fara HttpOnly, fara SameSite in configuratii)

def get_db_connection():
    connectionDB = sqlite3.connect('authx.db')
    connectionDB.row_factory = sqlite3.Row
    return connectionDB

# VULNERABILITATE 4.2: Stocare nesigura a parolelor
def weak_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # VULNERABILITATE 4.1: Password Policy slab (Nu verificam cat de lunga sau complexa e parola)
        hashed_password = weak_md5_hash(password)
        
        connectionDB = get_db_connection()
        try:
            connectionDB.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                         (email, hashed_password, 'USER'))
            connectionDB.commit()
            flash('Cont creat cu succes!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email-ul exista deja!')
        finally:
            connectionDB.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        connectionDB = get_db_connection()
        user = connectionDB.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        # VULNERABILITATE 4.4: User Enumeration (Dam mesaje diferite daca nu exista user-ul sau daca e parola gresita)
        if user is None:
            flash('Acest utilizator nu exista in baza de date!')
            connectionDB.close()
            return render_template('login.html')
        
        # VULNERABILITATE 4.3: Brute force / Lipsa rate limiting (Nu blocam contul indiferent de cate ori greseste parola)
        if user['password_hash'] != weak_md5_hash(password):
            flash('Parola este incorecta!')
            connectionDB.close()
            return render_template('login.html')
            
        session['user_id'] = user['id']
        session['email'] = user['email']
        connectionDB.close()
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        connectionDB = get_db_connection()
        user = connectionDB.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # VULNERABILITATE 4.6: Token de resetare complet nesigur si predictibil (email + cuvantul 'reset')
            reset_token = f"{email}_reset"
            
            connectionDB.execute('INSERT INTO password_resets (user_id, token) VALUES (?, ?)', (user['id'], reset_token))
            connectionDB.commit()
            
            flash(f'Link de resetare: http://127.0.0.1:5000/reset_password/{reset_token}', 'success')
        else:
            flash('Email inexistent!')
            
        connectionDB.close()
    return render_template('forgot.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    connectionDB = get_db_connection()
    reset_entry = connectionDB.execute('SELECT * FROM password_resets WHERE token = ?', (token,)).fetchone()
    
    if not reset_entry:
        return "Token invalid!"
        
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = weak_md5_hash(new_password)
        
        connectionDB.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, reset_entry['user_id']))
        # VULNERABILITATE 4.6: Token reutilizabil (Nu stergem token-ul din baza de date dupa ce a fost folosit)
        connectionDB.commit()
        connectionDB.close()
        
        flash('Parola a fost resetata cu succes!', 'success')
        return redirect(url_for('login'))
        
    connectionDB.close()
    return render_template('reset.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)