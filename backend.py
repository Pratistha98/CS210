from flask import Flask, render_template, url_for, redirect, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, Required, EqualTo
from flask_sqlalchemy import SQLAlchemy
#from sqlalchemy_imageattach.entity import Image, image_attachment
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, logout_user
from flask_login import LoginManager, UserMixin
import os
import sqlite3
import base64
from flask_migrate import Migrate
from datetime import datetime



appdir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = "TvX<Z`%zPzNvt3M:Z]tE7dF*S}5o<pX$1@S6UvRy"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)
migrate = Migrate(app, db)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(15), unique=True, nullable = False)
    email = db.Column(db.String(50), unique=True, nullable = False)
    password = db.Column(db.String(128))


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    password_again = PasswordField("Password again", validators=[Required(), EqualTo('password')])
    remember_me = BooleanField("Remember Me")

class SignupForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    # Muskaan : re-enter password function?

class CreatePost(FlaskForm):
    title = StringField("Email", validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    body = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])

class Post(db.Model):
    __tablename__ = "Posts"
    id = db.Column(db.Integer, primary_key=True, nullable = False, autoincrement = True)
    title = db.Column(db.String(45), nullable = False)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # TODO: image = db.Column


class PostForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired(), Length(min=5, max=200)])
    content = StringField("Content", validators=[InputRequired(), Length(min=5)])

def checklogin():
    if current_user.is_authenticated:
        return True
    else:
        return False
    

@app.route('/')
def home():
    # resets the database:
    # db.drop_all()
    # db.create_all()
    # db.session.commit()
    logged_in = checklogin()
    return render_template("Landing.html", logged_in=logged_in)

@app.route('/login', methods=['GET', 'POST'])  # Check if this works properly
def login(): 
    if current_user.is_authenticated:
        username = current_user.username
        return render_template("LoggedIn.html", username = username)
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not check_password_hash(user.password, form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                return (redirect(url_for('home')))  # make sure redirect is correct
        #error = 'Invalid credentials'
    logged_in = checklogin()   
    return render_template("Login.html", form=form, logged_in=logged_in)  # Update with proper html file

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = User.query.filter_by(username=form.username.data).first()  # make sure this checks for duplicate usernames
        email = User.query.filter_by(email=form.email.data).first()  # make sure this checks for existing users properly
        if username:
            flash('Username Already Taken')
            return (redirect(url_for('signup')))
        if email:
            flash('Email already taken')
            return (redirect(url_for('signup')))
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha512:10000', salt_length=8)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return (redirect(url_for('login')))  # make sure this redirects to the home page
    logged_in = checklogin()   
    return render_template("SignUp.html", form=form, logged_in=logged_in)  # Update with proper html file

@app.route('/create', methods=['GET', 'POST'])
def Create():
    form = PostForm()
    logged_in = checklogin()   
    return render_template("Create.html", logged_in=logged_in)  # Create a new blog post 

@app.route('/blog')
def Blog():
    logged_in = checklogin()   
    return render_template("Blog.html", logged_in=logged_in)  # Open the blog post 

@app.route('/logout')
def logout():
    logout_user()
    logged_in = False
    return redirect(url_for('login'))



"""!!!IDEA: annons can view first page of posts (clicking on a post still 
   forces you to login). When the user clicks to access the second+ page, 
   login will be required.
   
   *As of right now, we can leave it as login required and implement the 
   rest later!!!"""

"""!!!IDEA: use ajax to create an pop up where everything blurs in the background,
   but there is a login form in focus in the middle if a user clicks on an
   individual post or page 2 of /posts!!!"""


'''
Add user to the database
'''
class UserExists(ValueError):
    pass


#--------------------------------------------------------------------------
# Posts
'''
id = db.Column(db.Integer, primary_key=True, nullable = False, autoincrement = True)
    title = db.Column(db.String(45), nullable = False)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id
'''
@app.route('/posts/create', methods=['POST'])
def create():
    form = CreatePost()
    if current_user.is_authenticated:
        username = current_user.username
        title = form.title.data
        body = form.body.data
            
        new_post = Post(id=id, title=title, body=body, username=username)
        db.session.add(new_post)
        db.session.commit()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        return render_template("Create.html")  # Create a new blog post
    flash('User not logged in')
    return redirect(url_for('login')) 

@app.route("/posts")
def posts():
    posts = session.query(Post).all()
    return render_template("posts.html")

@app.route("/posts/<int:pid>")  # login required
def view_post(pid):
    post = session.query(Post).filter_by(id=pid).one()
    return render_template("post.html", post=post)


if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)

"""!!!IDEA: annons can view first page of posts (clicking on a post still 
   forces you to login). When the user clicks to access the second+ page, 
   login will be required.
   
   *As of right now, we can leave it as login required and implement the 
   rest later!!!"""

"""!!!IDEA: use ajax to create an pop up where everything blurs in the background,
   but there is a login form in focus in the middle if a user clicks on an
   individual post or page 2 of /posts!!!"""
