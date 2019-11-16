from flask import Flask, render_template, url_for, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

appdir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = "TvX<Z`%zPzNvt3M:Z]tE7dF*S}5o<pX$1@S6UvRy"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
Bootstrap(app)
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(15), unique=True, nullable = False)
    email = db.Column(db.String(50), unique=True, nullable = False)
    password = db.Column(db.String(128))


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Submit")


class SignupForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
    submit = SubmitField("Submit")
    # Muskaan : re-enter password function?


@app.route('/')
def home():
    return render_template("Landing.html")  # Update with proper html file

'''
End-points
1. def login()
2. def signup()
'''
@app.route('/login', methods=['GET', 'POST'])  # Check if this works properly
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                return redirect(url_for('posts'))  # make sure redirect is correct
        return "<h1>Invalid Username or Password</h1>"
    return render_template("Login.html", form=form)  # Update with proper html file


@app.route('/signup', methods=['GET', 'POST'])  # check if this works properly
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = User.query.filter_by(email=form.username.data).first()  # make sure this checks for duplicate usernames
        email = User.query.filter_by(email=form.email.data).first()  # make sure this checks for existing users properly
        if username:
            return "<h1>Username Taken</h1>"
        if email:
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha512:10000', salt_length=8)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for(''))  # make sure this redirects to the home page
    return render_template("SignUp.html", form=form)  # Update with proper html file


@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for("login"))


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
def register_user(email, password):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute(("INSERT INTO Users (email, password) "
                    "VALUES (?,?)"), (email, hash_password(password)))
        uid = c.lastrowid
        conn.commit()
        return uid
    except sqlite3.IntegrityError:
        raise UserExists()

@app.route("/posts")
def posts():
    return


@app.route("/posts/<int:pid>")  # login required
def view_post(pid):
    return


if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)