from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

users = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return "User already exists!", 400
        
        mfa_secret = pyotp.random_base32()
        users[username] = {"password": password, "mfa_secret": mfa_secret}
        return redirect(url_for('login'))
    
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Register">
        </form>
    '''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('mfa'))
        else:
            return "Invalid Credentials!", 403
    
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    secret = users[username]['mfa_secret']
    totp = pyotp.TOTP(secret)
    
    if request.method == 'POST':
        token = request.form['token']
        if totp.verify(token):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            return "Invalid MFA token!", 403
    
    return f'''
        <p>Scan this QR Code with Google Authenticator:</p>
        <img src="{totp.provisioning_uri(username, issuer_name='MyApp')}" alt="QR Code">
        <form method="post">
            MFA Token: <input type="text" name="token"><br>
            <input type="submit" value="Verify">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'authenticated' in session:
        return f"Welcome, {session['username']}! You are logged in."
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
