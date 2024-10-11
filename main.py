from flask import (
    Flask,
    request,
    render_template,
    redirect,
    abort,
    send_from_directory,
    url_for,
    flash
)
import random
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import time
import hmac
import hashlib
from username_generator import generate_username

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lapismyt-lol.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

tg_bot_token = os.getenv('TG_BOT_TOKEN')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    telegram_id = db.Column(db.String(100), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    tags = db.Column(db.String(100))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref=db.backref('articles', lazy=True))


with app.app_context():
    db.create_all()

admin = Admin(app)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Article, db.session))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/projects')
def projects():
    return render_template('projects.html')


@app.route('/tools')
def tools():
    return render_template('tools.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/create_article', methods=['GET', 'POST'])
@login_required
def create_article():
    if not current_user.is_admin:
        flash('You do not have permission to create articles.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        tags = request.form.get('tags', '')

        article = Article(title=title, content=content, category=category, tags=tags, author=current_user)
        db.session.add(article)
        db.session.commit()

        flash('Article created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create_article.html')


@app.route('/login')
def login():
    return render_template('login.html')
    # telegram_token = request.args.get('auth_token')
    # if telegram_token:
    #     # Здесь нужно добавить валидацию токена через Telegram API
    #     telegram_id = ...  # Получить telegram_id из валидации
    #     username = ...     # Получить username
    #
    #     user = User.query.filter_by(telegram_id=telegram_id).first()
    #     if not user:
    #         user = User(telegram_id=telegram_id, username=username)
    #         db.session.add(user)
    #         db.session.commit()
    #
    #     login_user(user)
    #     flash('You have successfully logged in!', 'success')
    #     return redirect(url_for('index'))
    # else:
    #     flash('Login failed.', 'danger')
    #     return redirect(url_for('index'))


@app.route('/telegram_oauth')
def telegram_oauth():
    bot_token = tg_bot_token
    hash_string = request.args.get('hash')
    user_id = request.args.get('user_id')
    username = request.args.get('username', 'undefined')
    auth_date = request.args.get('auth_date')
    data_check_string = ['{}={}'.format(k, v)
                         for k, v in request.args.items() if k != 'hash']
    data_check_string = '\n'.join(sorted(data_check_string))
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    built_hash = hmac.new(secret_key,
                          msg=data_check_string.encode(),
                          digestmod=hashlib.sha256).hexdigest()
    current_timestamp = int(time.time())
    auth_timestamp = int(auth_date)
    if current_timestamp - auth_timestamp > 86400:
        return redirect(url_for('login'))
    if built_hash != hash_string:
        return redirect(url_for('login'))
    user = User.query.filter_by(telegram_id=user_id).first()
    if not user:
        if username == 'undefined':
            while True:
                username = generate_username()
                tuser = User.query.filter_by(username=username).first()
                if isinstance(tuser, None):
                    break
        user = User(telegram_id=str(user_id), username=username, is_admin=(True if str(user_id) == str(os.getenv('ALWAYS_ADMIN')) else False))
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run('0.0.0.0', 80, debug=True)
