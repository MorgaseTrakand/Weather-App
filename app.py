from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message  
from flask_session import Session 
import random
import string
import datetime
import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # You can choose a different session type
Session(app)

# Set a secret key for your application
app.secret_key = 'your_secret_key'  # Replace with a secure random key

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

app.config['MAIL_SERVER'] = 'smtp.elasticemail.com'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ethandsnyder96@gmail.com'
app.config['MAIL_PASSWORD'] = '0DF27877FF36257060BC877DF6DBE2A78B90' 

mail = Mail(app)

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(20), nullable=False, unique=True)
  username = db.Column(db.String(20), nullable=False, unique=True)
  password = db.Column(db.String(80), nullable=False)
  location = db.Column(db.String(80), nullable=True)
  
class RegisterForm(FlaskForm): 
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
  email = StringField(validators=[InputRequired(), Length(min= 4, max=30)], render_kw={"placeholder": "Email"})
  password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  submit = SubmitField("Register")
  
  # def validate_username(self, username):
  #   existing_user_name = User.query.filter_by(username=username.data).first()
  #   if existing_user_name:
      
  #     raise ValidationError("That username already exists. Please choose a different one")

class forgotPasswordForm(FlaskForm):
  email = StringField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
  submit = SubmitField("Login")


class LoginForm(FlaskForm): 
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
  password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  submit = SubmitField("Login")
  
  # def username_validation(self, username):
  #   entered_username = User.query.filter_by(username=username.data).first()
  #   if not entered_username:  
  #     raise ValidationError("That username does not exist. Please register an account")
  

@app.route('/')
def index():
  return render_template('index.html')

password_reset_tokens = {}
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify the token and expiration
    token_info = password_reset_tokens.get(token)
    if not token_info or token_info['expiration_time'] < datetime.datetime.now():
        flash('Password reset link is invalid or has expired. Please request another reset link.', 'error')

    if request.method == 'POST':
        new_password = request.form.get('new_password')

        user = User.query.filter_by(email=token_info['email']).first()
        user.password = bcrypt.generate_password_hash(new_password)  # Replace with your actual password hashing function
        db.session.commit()

        del password_reset_tokens[token]
        flash('Your password has been successfully reset. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))  # Redirect to the login page

    return render_template('reset_password.html', token=token)

@app.route('/forgotpassword/', methods=['GET', 'POST'])
def forgotpassword():
  form = forgotPasswordForm()
  if request.method == "POST":
    email = User.query.filter_by(email=form.email.data).first()
    if email:
      token = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
      expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)
      password_reset_tokens[email] = {'token': token, 'expiration_time': expiration_time}
      # Send a password reset email
      msg = Message('Password Reset', sender='ethandsnyder96@example.com', recipients=[email])
      msg.body = f"Click the following link to reset your password: {url_for('reset_password', token=token, _external=True)}"
      mail.send(msg)

      flash('Password reset email sent. Check your inbox.', 'success')
      return redirect(url_for('login'))
    else:
      flash('Email address not found in the database. Please enter a valid email.', 'error')

  return render_template('forgotpassword.html', form=form)


@app.route('/dashboard/', methods=['GET', 'POST'])
@login_required
def dashboard():
  return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
  logout_user()
  return redirect('/')

@app.route('/login/', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user:
      if bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for('dashboard'))
    else:
      flash('Invalid username or password. Please try again.', 'error')
      
  return render_template('login.html', form=form)

@app.route('/register/', methods=['GET', 'POST'])  # Add support for POST requests
def register():
  form = RegisterForm()
  
  if form.validate_on_submit():
    email = form.email.data
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(username=form.username.data, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))
  return render_template('register.html', form=form)


if __name__ == '__main__':
  with app.app_context():
    db.create_all()
  app.run(debug=True)

