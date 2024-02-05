from flask import Flask, request, jsonify,render_template,redirect,g,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
import feedparser
import requests
from bs4 import BeautifulSoup
from fontTools.ttLib import TTFont


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mljblrre:vYO-z5AMpLJq6ZsW-nz3AHrjhck-PVEn@drona.db.elephantsql.com/mljblrre'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress a warning message
db = SQLAlchemy(app)
CORS(app)
login_manager = LoginManager(app)

# User model for registration and login
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    favorite_food = db.Column(db.String(50))
    role = db.Column(db.String(30))

# Comment model for adding and deleting comments
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    post_url = db.Column(db.Text, db.ForeignKey('post.url'))
    post = db.relationship('Post', lazy=True)
    
class Post(db.Model):
    url = db.Column(db.Text, primary_key=True)
    title = db.Column(db.Text)
    likes = db.Column(db.Integer)

def inspect_font(file_path):
    try:
        font = TTFont(file_path)
        # Print some information about the font
        print(f"Font Family: {font['name'].getFamilyName()}")
        print(f"Font Style: {font['name'].getStyleName()}")
        print(f"Number of Glyphs: {len(font['glyf'])}")
        # Add more information as needed

    except Exception as e:
        print(f"Error inspecting font: {str(e)}")

# Add predefined admin user
def add_admin_user():
    admin_username = "admin"
    admin_password = "admin"
    admin_favorite_food = "admin"
    admin_role = "ADMIN"

    with app.app_context():
        # Check if the admin user already exists
        existing_admin = User.query.filter_by(username=admin_username).first()

        if existing_admin is None:
            # Create the admin user
            admin_user = User(
                username=admin_username,
                password=admin_password,
                favorite_food=admin_favorite_food,
                role=admin_role,
            )

            # Add the admin user to the session and commit the changes
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user added successfully.")
        else:
            print("Admin user already exists.")

# Run this function to add the admin user
add_admin_user()

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
        
# Configure Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/auth-status', methods=['GET'])
def auth_status():
    if current_user.is_authenticated:
        return jsonify({'authenticated': True, 'username': current_user.username})
    else:
        return jsonify({'authenticated': False})

        
@app.route('/delete-comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    
    if comment:
        # Check if the user is an admin or the author of the comment
        if g.user and (g.user.role == 'ADMIN' or g.user.id == comment.user_id):
            db.session.delete(comment)
            db.session.commit()
            return jsonify({'message': 'Comment deleted successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized to delete this comment'}), 403
    else:
        return jsonify({'message': 'Comment not found'}), 404
    
    
@app.route('/searchNews/<news_title>', methods=['GET'])
def search_news(news_title):
    # Query the database for posts with titles similar to the search term
    search_results = Post.query.filter(Post.title.ilike(f'%{news_title}%')).all()

    # Prepare the results for JSON response
    results_list = [{
        'title': post.title,
        'url': post.url,
        'likes': post.likes
    } for post in search_results]

    return jsonify({'search_results': results_list})


# Delete user account endpoint
@app.route('/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)

    if user:
        # Check if the user is an admin or the owner of the account
        if g.user and (g.user.role == 'ADMIN' or g.user.id == user_id):
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User account deleted successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized to delete this user account'}), 403
    else:
        return jsonify({'message': 'User account not found'}), 404

@app.route('/like', methods=['POST'])
def like_post():
    try:
        data = request.get_json()
        post_id = data.get('post_id')
        user_id = data.get('user_id')

        if not post_id or not user_id:
            return jsonify({'message': 'Invalid request. Missing post_id or user_id.'}), 400

        post = Post.query.get(post_id)
        if not post:
            return jsonify({'message': 'Post not found'}), 404

        # Check if the user has already liked the post (if needed)
        # You can add your own logic here, for example, check if the user_id is in post.likes_by_user_ids

        post.likes += 1
        # You may also want to associate the user with the post if needed, like updating a likes_by_user_ids list

        db.session.commit()
        return jsonify({'message': 'Post liked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/rss-feed', methods=['GET'])
def get_rss_feed():
    rss_feed_url = 'https://azertag.az/rss.xml'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(rss_feed_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        feed_data = response.text

        # Parse the RSS feed using feedparser
        feed = feedparser.parse(feed_data)

        if 'entries' in feed:
            entries = feed['entries']
            result = []

            for entry in entries:
                title = entry.get('title', '')
                link = entry.get('link', '')
                description = entry.get('description', '')
                pub_date = entry.get('published', '')

                result.append({
                    'title': title,
                    'link': link,
                    'description': description,
                    'pub_date': pub_date,
                })
                post_url = rss_feed_url
                existing_post = Post.query.get(post_url)

                if existing_post is None:
                    # Create the post
                    new_post = Post(
                        url=post_url,
                        title=title,
                        likes=0  # Initialize likes to 0
                    )
                     # Add the post to the session and commit the changes
                    db.session.add(new_post)
                    db.session.commit()


            return jsonify({'rss_feed': result}), 200
        else:
            return jsonify({'message': 'Error parsing RSS feed'}), 500
    except requests.RequestException as e:
        return jsonify({'message': f'Error fetching RSS feed: {str(e)}'}), 500

@app.route('/resetpass', methods=['POST'])
def resetpass():
    data = request.get_json()
    username = data.get('username')
    password = data.get('newpass')
    favfood = data.get('favfood')

    if not username or not password:
        return jsonify({'message': 'Please provide both username and password'}), 400

    user = User.query.filter_by(username=username, favorite_food=favfood).first()
    if user:
        user.password = password
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401
    

@app.route('/resetPassword')
def resetPasswordPage():
    return render_template('resetpass.html')

@app.route('/')
def index():
    return render_template('homepage.html')

#handle rss feed by url
@app.route('/rss-feed-more/<path:rss_feed_url>', methods=['GET'])
def get_rss_feed_by_url(rss_feed_url):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(rss_feed_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        feed_data = response.text
        # encode to utf-8
        utf8_feed_data = feed_data.encode('utf-8')

        print(utf8_feed_data)
        # Parse the RSS feed using feedparser
        feed = feedparser.parse(feed_data)
        
        # find the title of the feed
        feed_title = utf8_feed_data.split(b'<title>')[1].split(b'</title>')[0]

        # make it human readable
        feed_title = feed_title.decode('utf-8')

        # find and append all "<p>" elements inside of "<div class="news-body">" in the feed
        news_content = ""
        news_body = utf8_feed_data.split(b'<div class="news-body">')[1].split(b'</div>')[0]
        for p in news_body.split(b'<p>'):
            if p != b'':
                news_content += p.split(b'</p>')[0].decode('utf-8') + '\n\n'

        # Parse the HTML string
        soup = BeautifulSoup(news_content, 'html.parser')

        # Get the text content without HTML tags
        text_content = soup.get_text()


        # make it human readable
        news_body = news_body.decode('utf-8')

        result = []

        result.append({
            'title': feed_title,
            'content': news_body,
            'text': text_content,
        })
        
        post_url = rss_feed_url
        existing_post = Post.query.get(post_url)

        if existing_post is None:
            # Create the post
            new_post = Post(
                url=post_url,
                title=feed_title,
                description=news_body,  # You might want to adjust this based on your data model
                likes=0  # Initialize likes to 0
            )

            # Add the post to the session and commit the changes
            db.session.add(new_post)
            db.session.commit()

        return jsonify({'rss_feed': result}), 200

    except requests.RequestException as e:
        return jsonify({'message': f'Error fetching RSS feed: {str(e)}'}), 500

@app.route('/allNews', methods=['GET'])
def get_all_news():
    # Query the database for all news posts
    all_news = Post.query.all()

    # Prepare the results for JSON response
    news_list = [{
        'title': post.title,
        'link': post.url,
        'likes': post.likes  # Convert datetime to ISO format
    } for post in all_news]

    return jsonify({'all_news': news_list})
    

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    favorite_food = data.get('favfood')
    if not username or not password:
        return jsonify({'message': 'Please provide both username and password'}), 400

    try:
        new_user = User(username=username, password=password, favorite_food=favorite_food, role="USER")
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists. Please choose another one'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Please provide both username and password'}), 400

    user = User.query.filter_by(username=username, password=password).first()
    if user:
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/loginPage')
def loginPage():
    return render_template('login.html')

@app.route('/registerPage')
def registerPage():
    return render_template('register.html')

@app.route('/newspage/{link}')
def newsPage(link):
    return render_template('newspage.html',link)
# Add comment endpoint
@app.route('/add-comment', methods=['POST'])
def add_comment():
    data = request.get_json()
    text = data.get('text')
    post_url = data.get('post_url')  # Assuming you are sending 'post_id' from the frontend

    if not text or not post_url:
        return jsonify({'message': 'Please provide text and post_id'}), 400

    try:
        new_comment = Comment(text=text, post_url=post_url)
        db.session.add(new_comment)
        db.session.commit()
        return jsonify({'message': 'Comment added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500


# Get all comments endpoint
@app.route('/comments', methods=['GET'])
def get_comments():
    comments = Comment.query.all()
    if comments:
        result = [{'id': comment.id, 'text': comment.text, 'user_id': comment.user_id} for comment in comments]
        return jsonify({'comments': result}), 200
    else:
        return jsonify({'message': 'No comments found'}), 404

# Get comment by ID endpoint
@app.route('/comments/<path:post_url>', methods=['GET'])
def get_comments_for_post(post_url):
    try:
        comments = Comment.query.filter_by(post_url=post_url).all()
        comments_data = [{'text': comment.text} for comment in comments]
        return jsonify({'comments': comments_data}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500


if __name__ == '__main__':
    
    with app.app_context():
        db.create_all()
    app.run(debug=True)
