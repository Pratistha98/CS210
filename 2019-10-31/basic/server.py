import os
from datetime import datetime
from flask import Flask, redirect, url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema

app = Flask(__name__)

# determine the directory of the script so that the sqlite database
# file can be referenced with a relative path ("example.db")
appdir = os.path.abspath(os.path.dirname(__file__))
print(os.path.join(appdir, 'example.db'))
# configure app’s database access
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# initialize the SQLAlchemy database adaptor
db = SQLAlchemy(app)

###############################################################################
###############################################################################
# Define Routes
###############################################################################
###############################################################################

# get all posts in the object collection
@app.route("/api/v1/posts/", methods=['GET'])
def get_posts():
	schema = PostSchema()
	posts = [schema.dump(post) for post in Post.query.all()]
	return jsonify({
		'api': 'v1',
		'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
		'posts': posts
	}), 200

# get a specific post object
@app.route("/api/v1/posts/<int:pid>", methods=['GET'])
def get_post(pid):
	post = Post.query.get_or_404(pid)
	schema = PostSchema()
	return jsonify(schema.dump(post)), 200

# create a new post
@app.route("/api/v1/posts/", methods=['POST'])
def post_post():
	schema = PostSchema()
	post = schema.load(request.json, session=db.session)
	db.session.add(post)
	db.session.commit()
	return jsonify(schema.dump(post)), 201

# updating an existing post is intentionally not supported

# delete an existing post
@app.route("/api/v1/posts/<int:pid>", methods=['DELETE'])
def delete_post(pid):
	post = Post.query.get_or_404(pid)
	schema = PostSchema()
	serialized = schema.dump(post)
	db.session.delete(post)
	db.session.commit()
	return jsonify(serialized), 200


###############################################################################
###############################################################################
# Define Models
###############################################################################
###############################################################################

class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Unicode(2048))

###############################################################################
###############################################################################
# Define Serializer Schemas
###############################################################################
###############################################################################

class PostSchema(ModelSchema):
	class Meta:
		model = Post
		dump_only = ('id',)

###############################################################################
###############################################################################
# Fill Database with Example Data
###############################################################################
###############################################################################

# define posts
posts = (
	Post(text=("There is nothing like looking, if you want to find something "
		"You certainly usually find something, if you look, but it is not "
		"always quite the something you were after.")),
	Post(text=("If more of us valued food and cheer and song above hoarded "
		"gold, it would be a merrier world.")),
	Post(text=("Your lullaby would waken a drunken goblin!")),
	Post(text=("And what would you do, if an uninvited dwarf came and hung his "
		"things up in your hall without a word of explanation?")),
	Post(text=("'Go back?' he thought. 'No good at all! Go sideways? "
		"Impossible! Go forward? Only thing to do! On we go!'")),
	Post(text=("That was the most awkward Wednesday he ever remembered.")),
	Post(text=("'What do you mean?' he said. 'Do you wish me a good morning, "
		"or mean that it is a good morning whether I want it or not; or that "
		"you feel good this morning; or that it is a morning to be good on?'"))
)

# drop any existing tables in the database
db.drop_all()

# create all the tables necessary according to my db.Model subclasses
db.create_all()

# add the posts to the database
db.session.add_all(posts)
db.session.commit()