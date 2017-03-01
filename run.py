from flask import Flask, redirect, render_template, request, url_for, jsonify, session
from passlib.hash import sha256_crypt
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, jwt_required,\
    create_access_token, get_jwt_identity, set_access_cookies
import configuration, json

app = Flask(__name__)
app.debug = configuration.DEBUG
app.secret_key = configuration.SECRET_KEY
app.config['MONGO_DBNAME'] = 'hashdb'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/hashdb'

mongo = PyMongo(app)
jwt = JWTManager(app)
#password = sha256_crypt.encrypt("password")
#password2 = sha256_crypt.encrypt("password")
@app.route("/welcome/<u>", methods=['GET','POST'])
def welcome(u):
	usersenc=mongo.db.usersenc
	cur = usersenc.find()
	for document in cur: print(document)
	return render_template('welcome.html', user=u)

@app.route("/register",  methods=['GET', 'POST'])
def register():
	usersenc = mongo.db.usersenc
	if request.method == 'POST':
		username = request.form['username']
		password = sha256_crypt.encrypt(request.form['password'])
		usersenc.insert({'username' : username, 'password' : password})
		return redirect(url_for('welcome', u=username))
	else:
		return render_template('register.html')

@app.route("/login", methods=['GET','POST'])
def login():
	usersenc = mongo.db.usersenc
	if request.method == 'POST':
		username = request.form['username']
		password = sha256_crypt.encrypt(request.form['password'])
		user=usersenc.find({'username' : username})
		for us in user:
			use=us['username']
			print(us['username'])
		access_token = create_access_token(identity=use)
		resp = jsonify({'login': True})
		set_access_cookies(resp, access_token)
		return resp, 200
	else:
		return render_template("login.html")

# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()