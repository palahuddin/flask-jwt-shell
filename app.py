from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import subprocess
import os
from dotenv import load_dotenv 

load_dotenv()

app = Flask(__name__)


# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
# creates SQLALCHEMY object

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    SQLALCHEMY_DATABASE_URI=os.getenv("SQLALCHEMY_DATABASE_URI"),
    SQLALCHEMY_TRACK_MODIFICATIONS=True
)
db = SQLAlchemy(app)

# Database ORMs
class User(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	public_id = db.Column(db.String(50), unique = True)
	name = db.Column(db.String(100))
	email = db.Column(db.String(70), unique = True)
	password = db.Column(db.String(80))



# decorator for verifying the JWT
def token_required(f):
	@wraps(f)
	def decorated():
		token = None
		# jwt is passed in the request header
		if 'token' in request.headers:
			token = request.headers['token']
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'My API'}), 404

		try:
			# decoding the payload to fetch the stored details
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query\
				.filter_by(public_id = data['public_id'])\
				.first()
		except:
			return jsonify({'message' : 'My API'}), 404
		# returns the current logged in users context to the routes
		return f()

	return decorated

# User Database Route
# this route sends back list of users
@app.route('/exec')
@token_required
def get_status():
	headers = request.headers
	validation = headers.get('Custom-Header')
	if not validation == os.getenv("X_HEADERS"):
		return make_response(
			'Could not verify', 401
		)
	command_start = """
	<YOUR SHELL SCRIPT>
	"""
	command_success = """
	<YOUR SHELL SCRIPT>
	"""
	command_end = """
	<YOUR SHELL SCRIPT>
	"""
	try:
		result_start = subprocess.check_output(
			[command_start], shell=True)
		result_success = subprocess.check_output(
			[command_success], shell=True)
		result_end = subprocess.check_output(
			[command_end], shell=True)
	except subprocess.CalledProcessError as e:
		return "An error occurred while trying to fetch task status updates."

	return 'Success %s' % (result_success)

@app.errorhandler(405)
def internal_server_error(e):
    return jsonify({
				'message' : 'My API'
    }), 404

@app.errorhandler(404)
def not_found(e):
    return jsonify({
				'message' : 'My API'
    }), 404

@app.route('/', methods =['GET'])
def home():
    return jsonify({
				'message' : 'My API'
    }), 404


## Login Signup
# route for logging user in
@app.route('/login', methods =['POST'])
def login():
	app.register_error_handler(404, internal_server_error)
	headers = request.headers
	validation = headers.get('Custom-Header')

	auth = request.form
	headers = request.headers
	validation = headers.get('Custom-Header')

	if not auth or not auth.get('email') or not auth.get('password') or not validation == os.getenv("X_HEADERS"):

		# returns 401 if any email or / and password is missing
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		# returns 401 if user does not exist
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, app.config['SECRET_KEY'])

		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
	# creates a dictionary of the form data
	data = request.form

	# gets name, email and password
	name, email = data.get('name'), data.get('email')
	password = data.get('password')

	# checking for existing user
	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		# database ORM object
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password)
		)
		# insert user
		db.session.add(user)
		db.session.commit()

		return make_response('Successfully registered.', 201)
	else:
		# returns 202 if user already exists
		return make_response('User already exists. Please Log in.', 202)
## EOF

if __name__ == "__main__":
	# setting debug to True enables hot reload
	# and also provides a debugger shell
	# if you hit an error while running the server
	app.run(host="0.0.0.0")
	app.register_error_handler(404, not_found)
