from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.mfa_secret:
                return redirect(url_for('verify_mfa', username=username))
            else:
                login_user(user)
                return redirect(url_for('setup_mfa'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/setup_mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    if current_user.mfa_secret:
        flash('MFA is already set up.', 'info')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        secret = pyotp.random_base32()
        current_user.mfa_secret = secret
        db.session.commit()
        
        totp = pyotp.TOTP(secret)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri(current_user.username, issuer_name="YourApp"))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('setup_mfa.html', secret=secret, qr_code=img_str)
    
    return render_template('setup_mfa.html')

@app.route('/verify_mfa/<username>', methods=['GET', 'POST'])
def verify_mfa(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(token):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid MFA token. Please try again.', 'danger')
    
    return render_template('verify_mfa.html', username=username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
