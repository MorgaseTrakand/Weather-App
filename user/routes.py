from flask import Flask
from app import app

@app.route('/user/signup', methods=['GET'])
def signup():
  f