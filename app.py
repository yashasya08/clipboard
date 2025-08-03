from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bcrypt
from config import Config
from models import db, User, Clipboard
from forms import RegistrationForm, LoginForm, ClipboardForm

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
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html', form=form)
        hashed = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        user = User(username=form.username.data, password_hash=hashed.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
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
    with app.app_context():
        db.create_all()
    app.run(debug=True)
