from flask import Flask, render_template, url_for, redirect, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError, TextAreaField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import InputRequired, Email, Length, Required, EqualTo
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, logout_user
from flask_login import LoginManager, UserMixin, login_required
from PIL import Image, ImageOps
import os
import sqlite3
import base64
import secrets
import onetimepass
from flask_migrate import Migrate
from flask_mail import Mail, Message
from datetime import datetime
from time import time
import random
# import jwt

appdir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = "TvX<Z`%zPzNvt3M:Z]tE7dF*S}5o<pX$1@S6UvRy"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MFA_APP_NAME"] = "MFA-Demo"
#For Email
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'blogcsc210@gmail.com'
app.config['MAIL_PASSWORD'] = 'gmemhpokpol123'
mail = Mail(app)
#For Email
Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)
migrate = Migrate(app, db)
mail = Mail(app)

session = {"username" : ""}

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(15), unique=True, nullable = False)
    full_name = db.Column(db.String(128), nullable = False)
    password = db.Column(db.String(60), nullable=False)
    picture = db.Column(db.String(20), nullable=False, default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)


class Post(db.Model):
    __tablename__ = "Posts"
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    title = db.Column(db.String(50), nullable = False)
    description = db.Column(db.String(128))
    time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    picture = db.Column(db.String(50), nullable = True)

class PostForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired()])
    description = TextAreaField("Description", validators=[InputRequired()])
    picture = FileField('Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField("Post")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("LogIn")

class SignupForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=2, max=20)])
    full_name = StringField("Full Name", validators=[InputRequired(), Length(min=5, max=35)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    password_again = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo('password')])
    picture = FileField('Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField("SignUp")

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=20)])
    full_name = StringField("Full Name", validators=[InputRequired(), Length(min=5, max=35)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('No account with that email exists!')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class OTPForm(FlaskForm):
    otp = StringField("OTP", validators=[InputRequired(), Length(min=6, max=6)])
    submit = SubmitField("LogIn")

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
    posts = Post.query.all()
    return render_template("Landing.html", logged_in=logged_in, posts=posts)

@app.route("/posts")
def posts():
    post = Post.query.all()
    return render_template("posts.html")

@app.route("/posts/<int:pid>")  # login required
def view_post(pid):
    post = Post.query.filter_by(id=pid).first()
    return render_template("Blog.html", post=post)

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_profile_picture(form.picture.data)
            current_user.picture = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    picture = url_for('static', filename='user_pictures/' + current_user.picture)
    return render_template('account.html', title='Account', picture=picture, form=form)

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
                # login_user(user, remember=form.remember_me.data)
                return redirect(url_for('otp_request', username=user.username))  # make sure redirect is correct
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
        new_user = User(email=form.email.data, username=form.username.data, full_name = form.full_name.data, password=hashed_password)
        if form.picture.data:
            picture_file = save_profile_picture(form.picture.data)
            new_user.picture = picture_file
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        return redirect(url_for('login'))    #redirecting for two factor authentication
    logged_in = checklogin()   
    return render_template("SignUp.html", form=form, logged_in=logged_in)  

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title=form.title.data, description=form.description.data, time = datetime.now(), user_id = current_user.id)
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            new_post.picture = picture_file
        db.session.add(new_post)
        db.session.commit()
        logged_in = checklogin()
        flash("Posted Successfully", "success")
        return redirect(url_for('home'))  # Create a new blog post  
    logged_in = checklogin()
    return render_template("Create.html", form=form, logged_in=logged_in)

def save_picture(post_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(post_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/post_pictures', picture_fn)
    post_picture.save(picture_path)
    return picture_fn

def save_profile_picture(user_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(user_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/user_pictures', picture_fn)
    output_size = (25, 25)
    i = Image.open(user_picture)
    i = ImageOps.fit(i, (25, 25), Image.ANTIALIAS)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

#----------------------------------------------------------------------------------------------
#Forgot Password
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@210project.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.'''
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('login'))
    flash('User with entered email not found')
    return render_template('forgotpassword.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token", "warning")
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha512:10000', salt_length=8)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been reset.', "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

#----------------------------------------------------------------------------------------------
#2fa    

def send_authorization_email(email, otp_secret):
    msg = Message('OTP for Login', sender='noreply@210project.com', recipients=[email])
    msg.body = '''Your 6 digit One Time Password is:''' + otp_secret
    mail.send(msg)

list = []
@app.route('/otp/<string:username>', methods=['GET', 'POST'])
def otp_request(username):
    email = User.query.filter_by(username=username).first().email
    form = OTPForm()
    otp_secret = str(random.randint(100000, 999999))
    list.append(otp_secret)
    if request.method == 'GET':
        send_authorization_email(email, otp_secret)
        return render_template('two-factor-setup.html', form=form, username=username)
    else:
        if form.validate_on_submit():
            otp = form.otp.data
            if otp == list[0]:
                login_user(User.query.filter_by(email=email).first())
                return redirect(url_for('home'))
            else:
                flash('Invalid OTP. Check your email again')
                logged_in = checklogin()
                return redirect(url_for('login', form=form, logged_in=logged_in))


#--------------------------------------------------------------------------------------------------

@app.route('/blog')
def Blog():
    logged_in = checklogin()   
    return render_template("Blog.html", logged_in=logged_in)  # Open the blog post 

@app.route('/logout')
def logout():
    logout_user()
    logged_in = False
    return redirect(url_for('login'))

@app.route('/profile') 
def profile():
    logged_in = checklogin
    return render_template("Profile.html", logged_in=logged_in)

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