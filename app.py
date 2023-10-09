from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  # email = db.Column(db.String(20), nullable=False, unique=True)
  username = db.Column(db.String(20), nullable=False, unique=True)
  password = db.Column(db.String(80), nullable=False)
  location = db.Column(db.String(80), nullable=True)
  
class RegisterForm(FlaskForm): 
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
  # email = StringField(validators=[InputRequired(), Length(min= 4, max=30)], render_kw={"placeholder": "Email"})
  password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
  submit = SubmitField("Register")
  
  def validate_username(self, username):
    existing_user_name = User.query.filter_by(username=username.data).first()
    if existing_user_name:
      raise ValidationError("That username already exists. Please choose a different one")
  
  
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
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(username=form.username.data, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))
  return render_template('register.html', form=form)


if __name__ == '__main__':
  with app.app_context():
    db.create_all()
  app.run(debug=True)

