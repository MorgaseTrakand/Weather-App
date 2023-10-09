from flask import jsonify, request
from passlib.hash import pbkdf2_sha256
import uuid
from user.db import db

class User:
  
  def signup(self):
    user = {
      "_id": uuid.uuid4().hex,
      "name": request.form.get('name'),
      "email": request.form.get('email'),
      "password": request.form.get('password')
    }
    
    user['password'] = pbkdf2_sha256.encrypt(user['password'])
    if db.users.find_one({"email": user['email']}):
      return jsonify({ "error": "Email address already in use"}), 400

    if db.users.insert_one(user):
      return jsonify(user), 200
    
    return jsonify({ "error": "Signup failed" }), 400
    