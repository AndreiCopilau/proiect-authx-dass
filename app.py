from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# FIX 4.5 Sesiuni Securizate : previne furtul cookie-ului și atacurile CSRF
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

def get_db_connection():
    connectionDB = sqlite3.connect('authx.db')
    connectionDB.row_factory = sqlite3.Row
    return connectionDB

def log_audit(connection, user_id, action, resource):
    connection.execute(
        'INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)',
        (user_id, action, resource, request.remote_addr)
    )

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Verificarea sesiunii active
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # FIX 4.1 Password Policy: vValidare lungime
        if len(password) < 8:
            flash('Eroare: Parola trebuie să aibă minim 8 caractere!')
            return render_template('register.html')
        
        # FIX 4.2 Stocare sigură folosind scrypt: include Salt automat și e rezistent la brute-force
        hashed_password = generate_password_hash(password, method='scrypt')
        
        connectionDB = get_db_connection()
        try:
            connectionDB.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                         (email, hashed_password, 'USER'))
            connectionDB.commit()
            
            new_user = connectionDB.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            log_audit(connectionDB, new_user['id'], 'USER_REGISTERED', 'auth')
            
            flash('Cont creat cu succes!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            # Prevenim User Enumeration la inregistrare
            flash('A apărut o eroare la crearea contului. Dacă ai deja cont, te rugăm să te autentifici.')
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
        
        # FIX 4.3 Verificăm dacă contul este blocat: Brute-Force Protection
        if user and user['locked'] == 1:
            log_audit(connectionDB, user['id'], 'ATTEMPT_ON_LOCKED_ACCOUNT', 'auth')
            connectionDB.commit() 
            connectionDB.close()
            flash('Cont blocat!')
            return render_template('login.html')

        # FIX 4.4 User Enumeration: Mesaj unic si generic
        if not user or not check_password_hash(user['password_hash'], password):
            if user:
                # FIX 4.3 Rate Limiting & Account Lockout
                failed_logins = user['failed_logins'] + 1
                if failed_logins >= 5:
                    connectionDB.execute('UPDATE users SET locked = 1, failed_logins = ? WHERE id = ?', (failed_logins, user['id']))
                    log_audit(connectionDB, user['id'], 'ACCOUNT_LOCKED', 'auth')
                else:
                    connectionDB.execute('UPDATE users SET failed_logins = ? WHERE id = ?', (failed_logins, user['id']))
                    log_audit(connectionDB, user['id'], 'FAILED_LOGIN', 'auth')
                connectionDB.commit()

            connectionDB.close()
            flash('Email sau parolă incorectă!')
            return render_template('login.html')
            
        # Dupa logare cu succes resetam contorul de greșeli
        connectionDB.execute('UPDATE users SET failed_logins = 0 WHERE id = ?', (user['id'],))
        log_audit(connectionDB, user['id'], 'SUCCESSFUL_LOGIN', 'auth')
        connectionDB.commit()
        
        session['user_id'] = user['id']
        session['email'] = user['email']
        connectionDB.close()
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    # FIX 4.5 Invalidarea corectă a sesiunii la deconectare
    if 'user_id' in session:
        connectionDB = get_db_connection() 
        log_audit(connectionDB, session['user_id'], 'USER_LOGOUT', 'auth')
        
        connectionDB.commit()
        connectionDB.close()
    session.clear() 
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        connectionDB = get_db_connection()
        user = connectionDB.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # FIX 4.6 Token Cryptografic sigur si expirare in 15 minute
            reset_token = secrets.token_hex(32)
            expires_at = datetime.now() + timedelta(minutes=15)
            
            connectionDB.execute('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', 
                                 (user['id'], reset_token, expires_at.strftime('%Y-%m-%d %H:%M:%S')))
            
            log_audit(connectionDB, user['id'], 'PASSWORD_RESET_REQUESTED', 'auth')
            connectionDB.commit()
            
            flash(f'Link de resetare securizat (simulat): http://127.0.0.1:5000/reset_password/{reset_token}')
        else:
            # FIX 4.4 Anti-Enumeration: nu confirmăm dacă emailul există sau nu.
            flash('Dacă adresa de email există în sistem, un link de resetare a fost generat.')
            
        connectionDB.close()
    return render_template('forgot.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    connectionDB = get_db_connection()
    # FIX 4.6 Cautam doar token-uri care NU au fost inca folosite (One-time use)
    reset_entry = connectionDB.execute('SELECT * FROM password_resets WHERE token = ? AND used = 0', (token,)).fetchone()
    
    if not reset_entry:
        connectionDB.close()
        return "Token invalid sau deja folosit!"
        
    # FIX 4.6 Verificam dacă token-ul a expirat
    expires_at = datetime.strptime(reset_entry['expires_at'], '%Y-%m-%d %H:%M:%S')
    if datetime.now() > expires_at:
        return "Acest token de resetare a expirat!"
        
    if request.method == 'POST':
        new_password = request.form['new_password']
        
        # FIX 4.1 Validare lungime parola si la resetare
        if len(new_password) < 8:
            flash('Eroare: Parola trebuie să aibă minim 8 caractere!')
            connectionDB.close()
            return render_template('reset.html', token=token)
            
        hashed_password = generate_password_hash(new_password, method='scrypt')
        
        # Actualizam parola
        connectionDB.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, reset_entry['user_id']))
        
        # FIX 4.6 Invalidam token-ul pentru a nu mai putea fi reutilizat
        connectionDB.execute('UPDATE password_resets SET used = 1 WHERE id = ?', (reset_entry['id'],))
        
        log_audit(connectionDB, reset_entry['user_id'], 'PASSWORD_CHANGED_SUCCESSFULLY', 'auth')
        
        connectionDB.commit()
        connectionDB.close()
        
        flash('Parola a fost resetată cu succes! Te poți autentifica.', 'success')
        return redirect(url_for('login'))
        
    connectionDB.close()
    return render_template('reset.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)