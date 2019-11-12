import os
import base64
import functools
import traceback
from passlib.hash import argon2
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields
from marshmallow_sqlalchemy import ModelSchema
from flask_httpauth import HTTPBasicAuth
from itsdangerous import TimedJSONWebSignatureSerializer
from werkzeug.local import LocalProxy


app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"

# determine the directory of the script so that the sqlite database
# file can be referenced with a relative path ("example.db")
appdir = os.path.abspath(os.path.dirname(__file__))
print(os.path.join(appdir, 'example.db'))
# configure app’s database access
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# initialize the SQLAlchemy database adaptor
db = SQLAlchemy(app)

# initialize basic HTTP Authorization for API
auth = HTTPBasicAuth()

###############################################################################
###############################################################################
# Define API Token Authorization Mechanics
###############################################################################
###############################################################################

# verify that login was handled with HTTPBasicAuth
@auth.verify_password
def verify_password(username, password):
	user = User.query.filter_by(username=username).first()
	if user is not None and user.verify_password(password):
		return True
	return False

# get an api token using your username and password
@app.route("/api/v1/token", methods=['GET'])
@auth.login_required
def get_token():
	user = User.query.filter_by(username=auth.username()).first()
	if user is None:
		abort(403)
	timestamp = datetime.utcnow()
	expires = timestamp+timedelta(seconds=3600)
	token = generate_token(3600, api_uid=user.id)
	return jsonify({
		"created": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
		"expires": expires.strftime("%Y-%m-%d %H:%M:%S"),
		"token": token
	}), 200

# create a signed token with the requested fields
def generate_token(expires_in, **kwargs):
	secret = app.config["SECRET_KEY"]
	s = TimedJSONWebSignatureSerializer(secret, expires_in=3600)
	return s.dumps(kwargs).decode('utf-8')

# require an api token to access a resource
def token_required(f):
	@functools.wraps(f)
	def decorated_function(*args, **kwargs):
		if api_user._get_current_object() is None:
			abort(403)
		return f(*args, **kwargs)
	return decorated_function

# Provide logged in api_user using context. The _get_api_user function is 
# called in context when a request handler needs access to the current api 
# user. It is then inferred from their token and returned. This works much 
# like the current_user variable provided by flask_login
def _get_api_user():
	try:
		token = request.get_json()["token"].encode('utf-8')
		secret = app.config["SECRET_KEY"]
		s = TimedJSONWebSignatureSerializer(secret)
		uid = s.loads(token).get("api_uid")
		user = User.query.get(uid)
	except Exception:
		user = None
	return user
api_user = LocalProxy(lambda: _get_api_user())

###############################################################################
###############################################################################
# Define Routes
###############################################################################
###############################################################################

# get all users in the object collection
@app.route("/api/v1/users/", methods=['GET'])
def get_users():
	schema = UserSchema()
	users = [schema.dump(user) for user in User.query.all()]
	return jsonify({
		'api': 'v1',
		'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
		'users': users
	}), 200

# get a specific user object
@app.route("/api/v1/users/<int:uid>", methods=['GET'])
def get_user(uid):
	user = User.query.get_or_404(uid)
	schema = UserSchema()
	return jsonify(schema.dump(user)), 200

# change username and/or password
@app.route("/api/v1/users/<int:uid>", methods=['PUT','PATCH'])
@token_required
def put_user(uid):
	if api_user.id != uid: 
		abort(403)
	schema = UserSchema()
	user = User.query.get_or_404(uid)
	user = schema.load(request.get_json().get('user'), session=db.session,
		instance=user, partial=request.method=='PATCH')
	db.session.add(user)
	db.session.commit()
	return jsonify(schema.dump(user)), 200

# create a new user
@app.route("/api/v1/users/", methods=['POST'])
def post_user():
	schema = UserSchema()
	user = schema.load(request.get_json(), session=db.session)
	db.session.add(user)
	db.session.commit()
	return jsonify(schema.dump(user)), 201

# delete a user
@app.route("/api/v1/users/<int:uid>", methods=['DELETE'])
@token_required
def delete_user(uid):
	if api_user.id != uid:
		abort(403)
	user = User.query.get_or_404(uid)
	schema = UserSchema()
	serialized = schema.dump(user)
	db.session.delete(user)
	db.session.commit()
	return jsonify(serialized), 200

###############################################################################
###############################################################################
# Define Models
###############################################################################
###############################################################################

class User(db.Model):
	__tablename__ = "Users"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.Unicode(255), unique=True, nullable=False)
	password_hash = db.Column(db.String(255))
	@property
	def password(self):
		raise AttributeError("password is write only")
	@password.setter
	def password(self, password):
		self.password_hash = argon2.using(rounds=10).hash(password)
	def verify_password(self, password):
		return argon2.verify(password, self.password_hash)

###############################################################################
###############################################################################
# Define Serializer Schemas
###############################################################################
###############################################################################

class UserSchema(ModelSchema):
	password = fields.Str(load_only=True)
	class Meta:
		model = User
		exclude = ('password_hash',)
		dump_only = ('id',)

# drop any existing tables in the database
db.drop_all()

# create all the tables necessary according to my db.Model subclasses
db.create_all()
