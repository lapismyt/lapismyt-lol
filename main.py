from flask import (
    Flask,
    request,
    render_template,
    redirect,
    abort,
    send_from_directory,
    url_for,
    flash,
    get_flashed_messages
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
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib import sqla
import time
import hmac
import hashlib
from username_generator import generate_username
import werkzeug
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from waitress import serve
from telebot import TeleBot
from flask_sitemapper import Sitemapper
from markdown import markdown

load_dotenv()

sitemapper = Sitemapper()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.init_app(app)

tg_bot_token = os.getenv('TG_BOT_TOKEN')

csrf = CSRFProtect(app)

bot = TeleBot(tg_bot_token)

likes = db.Table('likes',
                 db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                 db.Column('article_id', db.Integer, db.ForeignKey('article.id'), primary_key=True)
                 )

sitemapper.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    telegram_id = db.Column(db.String(100), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    articles = db.relationship('Article', backref='author', lazy=True)
    liked_articles = db.relationship('Article', secondary=likes, lazy='subquery',
                                     backref=db.backref('likers', lazy=True))


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(100))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def likes(self):
        return len(self.likers)


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_active and current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


class MyModelView(sqla.ModelView):
    def is_accessible(self):
        return current_user.is_active and current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


with app.app_context():
    db.create_all()

admin = Admin(app, name='lapismyt.lol')
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Article, db.session))


# @app.before_request
# def check_req():
#     host = request.host
#     if host in ['www.aeza.website', 'aeza.website'] and not request.path.startswith('/.well-known/acme-challenge/'):
#         return redirect("https://aeza.net/?ref=491405", code=301)

@app.route('/.well-known/acme-challenge/<path:filename>')
def serve_challenge(filename):
    challenge_dir = '/var/www/lapismyt.lol/.well-known/acme-challenge'
    file_path = os.path.join(challenge_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(challenge_dir, filename)
    else:
        abort(404)

@app.route('/local/<path:filename>')
def local_dwn(filename):
    challenge_dir = '/var/www/lapismyt.lol'
    file_path = os.path.join(challenge_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(challenge_dir, filename)
    else:
        abort(404)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/projects', methods=['GET', 'POST'])
def projects():
    return render_template('projects.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/tools', methods=['GET', 'POST'])
def tools():
    return render_template('tools.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/terms')
def terms():
    return render_template('terms-of-use.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy-policy.html')


@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static', 'robots.txt')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')


@app.route('/static/<path:static_file>')
def sitemap(static_file):
    return send_from_directory('static', secure_filename(static_file))


@app.route('/send-message', methods=['GET', 'POST'])
def send_message():
    if not (current_user.is_active and current_user.is_authenticated and current_user.is_admin):
        flash('You do not have permission to do this!', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        batch_size = 128
        messages_sent = 0
        if not request.form.get('text', None):
            return redirect(url_for('index'))
        offset = 0
        while True:
            users = User.query.offset(offset).limit(batch_size).all()
            if not users:
                break
            for user in users:
                try:
                    bot.send_message(user.telegram_id, request.form.get('text', ''), parse_mode='HTML')
                    messages_sent += 1
                except:
                    pass
            offset += batch_size
        flash(f'{messages_sent} messages sent successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('send-message.html')


@sitemapper.include(lastmod='2024-10-14', changefreq='monthly')
@app.route('/articles/page/<int:page>', methods=['GET', 'POST'])
@app.route('/articles', methods=['GET', 'POST'])
def list_articles(page=1):
    per_page = request.args.get('per_page', 5, type=int)
    articles = Article.query.order_by(Article.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('articles.html', articles=articles)


@app.route('/articles/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_article(id):
    article = Article.query.get_or_404(id)

    if not current_user.is_admin:
        flash('You do not have permission to edit this article.', 'danger')
        return redirect(url_for('view_article', id=article.id))

    if request.method == 'POST':
        article.title = request.form['title']
        article.content = request.form['content']
        article.tags = request.form['tags']
        db.session.commit()
        flash('Article updated successfully!', 'success')
        return redirect(url_for('view_article', id=article.id))

    return render_template('edit_article.html', article=article)


@app.route('/articles/new', methods=['GET', 'POST'])
@login_required
def create_article():
    if not current_user.is_admin:
        flash('You do not have permission to create an article.', 'danger')
        return redirect(url_for('list_articles'))

    if request.method == 'POST':
        title = request.form['title']
        content = markdown(request.form['content'])
        tags = request.form['tags']
        article = Article(title=title, content=content, tags=tags, author_id=current_user.id)
        db.session.add(article)
        db.session.commit()
        flash('Article created successfully!', 'success')
        return redirect(url_for('list_articles'))

    return render_template('edit_article.html', article=None)


def generate_article_ids():
    articles = Article.query.all()
    return {'id': [artcl.id for artcl in articles]}


@sitemapper.include(url_variables=generate_article_ids, lastmod='2024-10-14')
@app.route('/articles/<int:id>', methods=['GET', 'POST'])
def view_article(id):
    article = Article.query.get_or_404(id)
    return render_template('article.html', article=article)


@app.route('/like_article/<int:article_id>', methods=['GET', 'POST'])
@login_required
def like_article(article_id):
    article = Article.query.get_or_404(article_id)
    if not (current_user.is_active and current_user.is_authenticated):
        return redirect(url_for('login', next=url_for('view_article', id=article_id)))

    if current_user in article.likers:
        article.likers.remove(current_user)
        flash('You unliked the article.', 'success')
    else:
        article.likers.append(current_user)
        flash('You liked the article.', 'success')

    db.session.commit()
    return redirect(url_for('view_article', id=article_id))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if not (current_user.is_active and current_user.is_authenticated and current_user.is_admin):
        return redirect(url_for('login', next=url_for('upload_file')))
    message = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            message = f'File successfully uploaded at {url_for("download_file", filename=filename, _external=True)}.'

    return render_template('upload.html', message=message)


@app.route('/uploads/<path:filename>', methods=['GET', 'POST'])
def download_file(filename):
    safe_filename = secure_filename(filename)
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)
    except FileNotFoundError:
        abort(404)


@app.route('/delete_article/<int:article_id>', methods=['GET', 'POST'])
@login_required
def delete_article(article_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete articles.', 'danger')
        return redirect(url_for('view_article', article_id=article_id))

    article = Article.query.get_or_404(article_id)
    db.session.delete(article)
    db.session.commit()

    flash('Article has been deleted.', 'success')
    return redirect(url_for('index'))


@sitemapper.include(lastmod='2024-10-14')
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


@app.route('/telegram_oauth', methods=['GET', 'POST'])
def telegram_oauth():
    bot_token = tg_bot_token
    hash_string = request.args.get('hash')
    user_id = request.args.get('id')
    username = request.args.get('username', 'undefined')
    auth_date = request.args.get('auth_date')
    data_check_string = ['{}={}'.format(k, v)
                         for k, v in request.args.items() if k != 'hash' and k != 'next']
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
        is_admin = False
        if str(user_id) == str(os.getenv('ALWAYS_ADMIN')):
            is_admin = True
        user = User(telegram_id=str(user_id), username=username, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(request.args.get('next', url_for('index')))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route("/sitemap.xml")
def sitemap_xml():
    return sitemapper.generate(gzip=True)


@app.errorhandler(werkzeug.exceptions.NotFound)
def handle_bad_request(e):
    return render_template('not_found.html'), 400


if __name__ == '__main__':
    # app.run('0.0.0.0', 80, debug=True)
    serve(app, host='0.0.0.0', port=int(os.getenv('PORT')), threads=1)
