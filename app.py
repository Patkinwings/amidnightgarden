from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import os
import markdown2
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import logging
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__, 
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['DEBUG'] = True

csrf = CSRFProtect(app)

logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# MongoDB setup
uri = "mongodb+srv://markspathways:jungdala@cluster0.whf8u94.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tls=true&tlsAllowInvalidCertificates=true"
client = MongoClient(uri, server_api=ServerApi('1'), serverSelectionTimeoutMS=5000)

db = client.get_database('jungdala_db')
articles_collection = db.articles
users_collection = db.users

def check_db_connection():
    try:
        client.admin.command('ping')
        app.logger.info("Pinged your deployment. You successfully connected to MongoDB!")
        return True
    except Exception as e:
        app.logger.error(f"Failed to connect to MongoDB: {e}")
        return False

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    if not check_db_connection():
        return None
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return render_template('index.html', articles=[], page=1, per_page=5, total=0)

    app.logger.debug("Rendering index template")
    page = request.args.get('page', 1, type=int)
    per_page = 5
    skip = (page - 1) * per_page
    
    try:
        articles = list(articles_collection.find().skip(skip).limit(per_page))
        total = articles_collection.count_documents({})
    except Exception as e:
        app.logger.error(f"Error fetching articles: {e}")
        articles = []
        total = 0
    
    app.logger.debug(f"Articles: {articles}")
    app.logger.debug(f"Page: {page}, Per page: {per_page}, Total: {total}")
    
    return render_template('index.html', articles=articles, page=page, per_page=per_page, total=total)

@app.route('/article/<article_id>')
def view_article(article_id):
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return redirect(url_for('index'))

    article = articles_collection.find_one({'_id': ObjectId(article_id)})
    if article:
        content_html = markdown2.markdown(article['content'])
        return render_template('article.html', article=article, content=content_html)
    flash("Article not found", 'error')
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('admin.html')
        
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    content += f"\n\n![{filename}](/static/uploads/{filename})"
                except Exception as e:
                    flash(f'Error uploading file: {str(e)}', 'error')
                    return render_template('admin.html')
        
        article = {
            'title': title,
            'content': content
        }
        articles_collection.insert_one(article)
        flash('Article created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/edit/<article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return redirect(url_for('index'))

    article = articles_collection.find_one({'_id': ObjectId(article_id)})
    if not article:
        flash('Article not found', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('edit.html', article=article)
        
        articles_collection.update_one(
            {'_id': ObjectId(article_id)},
            {'$set': {'title': title, 'content': content}}
        )
        flash('Article updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', article=article)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return render_template('login.html', error="Database connection error")

    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    
    form = FlaskForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = users_collection.find_one({'username': username})
        if user_data:
            user = User(user_data)
            if user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/delete/<article_id>')
@login_required
def delete_article(article_id):
    if not check_db_connection():
        flash("Unable to connect to the database", 'error')
        return redirect(url_for('index'))

    result = articles_collection.delete_one({'_id': ObjectId(article_id)})
    if result.deleted_count:
        flash('Article deleted successfully!', 'success')
    else:
        flash('Error deleting the article', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"404 error: {str(e)}")
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return "An error occurred", 500

@app.route('/about')
def about():
    return render_template('about.html')

def create_admin(username, password):
    if not check_db_connection():
        app.logger.error("Unable to connect to the database")
        return

    try:
        existing_user = users_collection.find_one({'username': username})
        if not existing_user:
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            users_collection.insert_one({
                'username': username,
                'password_hash': password_hash
            })
            app.logger.info(f"Admin user '{username}' created successfully.")
        else:
            app.logger.info(f"Admin user '{username}' already exists.")
    except Exception as e:
        app.logger.error(f"Error creating admin user: {str(e)}")

if __name__ == '__main__':
    if check_db_connection():
        create_admin('admin', 'Jungdala')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        app.logger.info("Starting server on http://localhost:5001")
        app.run(debug=True, host='localhost', port=5001)
    else:
        app.logger.error("Failed to connect to the database. Exiting.")