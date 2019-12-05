from flask import Flask, render_template, url_for, redirect, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, Required, EqualTo
from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy_imageattach.entity import Image, image_attachment
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, logout_user
from flask_login import LoginManager, UserMixin
import os
import sqlite3
import base64
import onetimepass
from flask_migrate import Migrate
from flask_mail import Mail, Message
from datetime import datetime
from time import time
import jwt


appdir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = "TvX<Z`%zPzNvt3M:Z]tE7dF*S}5o<pX$1@S6UvRy"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MFA_APP_NAME"] = "MFA-Demo"
app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = 'blogcsc210@gmail.com',
    MAIL_PASSWORD = 'gmemhpokpol123',
))
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
    username = db.Column(db.String(15), unique=True, nullable = False)
    email = db.Column(db.String(50), unique=True, nullable = False)
    password = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

class Post(db.Model):
    __tablename__ = "Posts"
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    title = db.Column(db.String(50), nullable = False)
    body = db.Column(db.String(128))
    #timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    #user_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    # image = db.Column(db.Image)
    # TODO: image = db.Column

class PostForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired()])
    body = StringField("Body", validators=[InputRequired()])

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    remember_me = BooleanField("Remember Me")

class SignupForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    password_again = PasswordField("Password again", validators=[Required(), EqualTo('password')])
    # Muskaan : re-enter password function?

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')

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
        session['username'] = new_user.username
        return redirect(url_for('two_factor_setup'))    #redirecting for two factor authentication
    logged_in = checklogin()   
    return render_template("SignUp.html", form=form, logged_in=logged_in)  

@app.route('/create', methods=['GET', 'POST'])
def create():
    form = PostForm()
    logged_in = checklogin()
    if form.is_submitted():
        new_post = Post(title=form.title.data, body=form.body.data)
        db.session.add(new_post)
        db.session.commit()
        return render_template("Landing.html", form=form, logged_in=logged_in)  # Create a new blog post  
    return render_template("Create.html", form=form, logged_in=logged_in)  


#----------------------------------------------------------------------------------------------
#Forgot Password
def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[URBlog] Reset Your Password',
               sender=app.config['ADMINS'][0],
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt',
                                         user=user, token=token),
               html_body=render_template('email/reset_password.html',
                                         user=user, token=token))

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    flash('User with entered email not found')
    return render_template('forgotpassword.html',
                           title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

#----------------------------------------------------------------------------------------------
#2fa    
@app.route('/twofactor')
def two_factor_setup():
   
   # if 'username' not in session:
    #    return redirect(url_for('home'))
    user = User.query.filter_by(username=session['username']).first()
   # if user is None:
    #    return redirect(url_for('home'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/Creation', methods=['GET', 'POST'])
def Creation():
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

@app.route("/posts")
def posts():
    posts = session.query(Post).all()
    return render_template("posts.html")

@app.route("/posts/<int:pid>")  # login required
def view_post(pid):
    post = session.query(Post).filter_by(id=pid).one()
    return render_template("post.html", post=post)


if __name__ == '__main__':
    
    db.create_all()
    db.session.commit()
    app.run(debug=True, host='localhost', port=5000)

"""!!!IDEA: annons can view first page of posts (clicking on a post still 
   forces you to login). When the user clicks to access the second+ page, 
   login will be required.
   
   *As of right now, we can leave it as login required and implement the 
   rest later!!!"""

"""!!!IDEA: use ajax to create an pop up where everything blurs in the background,
   but there is a login form in focus in the middle if a user clicks on an
   individual post or page 2 of /posts!!!"""