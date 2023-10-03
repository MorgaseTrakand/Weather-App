from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
# db = SQLAlchemy(app)

# class Database(db.Model):
#   id = db.Column(db.Integer, primary_key=True)
#   username = db.Column(db.String(20), nullable=False)
#   password = db.Column(db.String(20), nullable=False)
#   date_created = db.Column(db.DateTime, default=datetime.utcnow)
#   location = db.Column(db.String(50), nullable=False)

#   def __repr__(self):
#     return '<Task %r>' % self.id
  
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/')
def login():
    return render_template('login.html')

@app.route('/dashboard/')
def dashboard():
    return render_template('dashboard.html')
    
if __name__ == "__main__":
    app.run(debug=True)