from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from data import Articles
import mysql.connector
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from functools import wraps

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = '123456'
app.secret_key = "super secret key"


# Config Mysql
app.config['MYSQL_HOST'] = 'us-cdbr-iron-east-04.cleardb.net'
app.config['MYSQL_USER'] = 'bc78d0c95bf993'
app.config['MYSQL_PASSWORD'] = '9120cb71'
app.config['MYSQL_DB'] = 'heroku_d530a00f1ad787a'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)


class RegisterForm(Form):
   name = StringField('name', [validators.Length(min=1, max=50)])
   username = StringField('username', [validators.Length(min=4, max=25)])
   email = StringField('email', [validators.Length(min=6, max=50)])
   password = PasswordField('password',[
      validators.DataRequired(),
      validators.EqualTo('confirm', message='Passwords do not match.')
   ])
   confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm(request.form)
   if request.method == 'POST' and form.validate():
      name = form.name.data
      email = form.email.data
      username = form.username.data
      password = sha256_crypt.encrypt(str(form.password.data))

      # Create cursor
      cur = mysql.connection.cursor()

      # Execute query
      cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password)) 

      #commit to DB
      mysql.connection.commit()

      cur.close()

      flash('You are now registered and can login', 'success')

      redirect(url_for('login'))
      return redirect(url_for('login'))
   return render_template('register.html', form = form)

# user login
@app.route('/', methods=['GET', 'POST'])
def login(**kwargs):
   if request.method == 'POST':
      # Get Form Fields
      username = request.form['username']
      password_candidate = request.form['password']

      # Create cursor
      cur = mysql.connection.cursor()

      # Get user by username
      result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
      if result > 0:
         # Get stored hash
         data = cur.fetchone()
         password = data['password']

         # Compare Passwords
         if sha256_crypt.verify(password_candidate, password):
            # Passed
            session['logged_in'] = True
            session['username'] = username

            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))
         else:
            error = 'Invalid login'
            return render_template('login.html', error = error)
         # Close connection
         cur.close()
      else:
         error = 'Username not found'
         return render_template('login.html', error = error)

   return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
   @wraps(f)
   def wrap(*args, **kwargs):
      if 'logged_in' in session:
         return f(*args, **kwargs)
      else:
         flash('Unauthorized, Please Login', 'danger')
      return redirect(url_for('login'))
   return wrap
   

# Logout
@app.route('/logout')
def logout():
   session.clear()
   flash('You are now logged out', 'success')
   return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
   username = session.get('username')
   
   # Create cursor
   cur = mysql.connection.cursor()

   # Get
   result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
   result = cur.fetchone()

   credit = result['credit']
   name = result['name']


   return render_template('dashboard.html',credit = credit, name = name)

if __name__ == '__main__':
    app.run(debug=True)