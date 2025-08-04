import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bcrypt
from config import Config
from models import db, User, Clipboard
from models import db, User, Clipboard, FileShare
from forms import RegistrationForm, LoginForm, ClipboardForm
from forms import FileShareForm
import shutil
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask import send_file

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        userid = form.userid.data.strip().lower()
        if not userid or '@' in userid or '.' in userid:
            flash('Enter only your Cognizant UserID (no @ or domain).', 'danger')
            return render_template('register.html', form=form)
        email = f"{userid}@cognizant.com"
        existing_user = User.query.filter_by(username=userid).first()
        if existing_user:
            flash('UserID already exists. Please login or use a different Cognizant account.', 'danger')
            return render_template('register.html', form=form)
        hashed = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        user = User(username=userid, password_hash=hashed.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        # Create user folder (if not exists)
        user_folder = os.path.join(os.path.dirname(__file__), 'uploads', userid)
        os.makedirs(user_folder, exist_ok=True)
        # Create empty clipboard for new user
        clipboard = Clipboard(user_id=user.id, content='')
        db.session.add(clipboard)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            return redirect(url_for('clipboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/clipboard', methods=['GET', 'POST'])
@login_required
def clipboard():
    form = ClipboardForm()
    clipboard = Clipboard.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST' and form.validate_on_submit():
        clipboard.content = form.content.data
        clipboard.last_updated = datetime.utcnow()
        db.session.commit()
        flash('Clipboard saved!', 'success')
        return redirect(url_for('clipboard'))
    elif request.method == 'GET':
        form.content.data = clipboard.content if clipboard else ''
    last_saved = clipboard.last_updated.strftime('%Y-%m-%d %H:%M:%S') if clipboard and clipboard.last_updated else 'Never'
    return render_template('clipboard.html', form=form, last_saved=last_saved, username=current_user.username)

@app.route('/clipboard/load', methods=['GET'])
@login_required
def load_clipboard():
    clipboard = Clipboard.query.filter_by(user_id=current_user.id).first()
    return {'content': clipboard.content if clipboard else ''}

if __name__ == '__main__':
    # For local development only: create tables and run Flask dev server
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

# --- FILESHARE FEATURE ---
import pathlib
@app.route('/fileshare', methods=['GET', 'POST'])
@login_required
def fileshare():
    form = FileShareForm()
    upload_folder = os.path.join(os.path.dirname(__file__), 'uploads', str(current_user.id))
    os.makedirs(upload_folder, exist_ok=True)

    # Clean up expired files
    now = datetime.utcnow()
    expired_files = FileShare.query.filter(FileShare.user_id==current_user.id, FileShare.expiry_time < now).all()
    for ef in expired_files:
        try:
            if os.path.exists(ef.filepath):
                os.remove(ef.filepath)
        except Exception:
            pass
        db.session.delete(ef)
    db.session.commit()

    if form.validate_on_submit() and 'file' in request.files:
        files = request.files.getlist('file')
        uploaded = 0
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                save_path = os.path.join(upload_folder, filename)
                file.save(save_path)
                expiry_time = datetime.utcnow() + timedelta(hours=24)
                fs = FileShare(user_id=current_user.id, filename=filename, filepath=save_path, expiry_time=expiry_time)
                db.session.add(fs)
                uploaded += 1
        if uploaded:
            db.session.commit()
            flash(f'{uploaded} file(s) uploaded successfully!', 'success')
            return redirect(url_for('fileshare'))

    # List files
    files = FileShare.query.filter_by(user_id=current_user.id).order_by(FileShare.upload_time.desc()).all()
    return render_template('fileshare.html', form=form, files=files)

@app.route('/fileshare/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = FileShare.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    if file.expiry_time < datetime.utcnow():
        flash('File has expired.', 'danger')
        return redirect(url_for('fileshare'))
    return send_file(file.filepath, as_attachment=True, download_name=file.filename)

@app.route('/fileshare/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = FileShare.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    try:
        if os.path.exists(file.filepath):
            os.remove(file.filepath)
    except Exception:
        pass
    db.session.delete(file)
    db.session.commit()
    flash('File deleted.', 'info')
    return redirect(url_for('fileshare'))

# For Render/Gunicorn: just expose 'app' (no need for main block)
