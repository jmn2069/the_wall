from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
from datetime import datetime
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'login_registration')
EMAIL_REGEX = re.compile(r'^[\w\.+_-]+@[\w\._-]+\.[\w]*$')
app.secret_key = 'thisissecret'

@app.route('/', methods=["GET", "POST"])
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def create():
    errors = []
    query = 'SELECT * FROM users WHERE email = :email'
    email = request.form['email']
    data = {'email' : email}
    try:
        user = mysql.query_db(query, data)
        if user:
            flash('This email has already been registered!')
            return redirect('/')
    except:
        none = True
        # This was entered because there needed to be an except 
    if not request.form['first_name'].isalpha():
        errors.append('First name must contain only letters')
    elif len(request.form['first_name']) < 2:
        errors.append('First name must be at least 2 characters long')

    if not request.form['last_name'].isalpha():
        errors.append('Last name must contain only letters')
    elif len(request.form['last_name']) < 2: 
        errors.append('Last name must be at least 2 characters long')     

    if not EMAIL_REGEX.match(request.form['email']):
        errors.append('Email is not valid')

    if len(request.form['password']) < 8:
        errors.append('Password must contain at least 8 characters')
    elif not request.form['password'] == request.form['re_password']:
        errors.append('The passwords do not match')

    # the above checks all the entered data

    if errors:
        for error in errors:
            flash(error)
        return redirect('/')
    else:
        hashed_pw = bcrypt.generate_password_hash(request.form['password'])
        data ={
            'first_name' : request.form['first_name'],
            'last_name' : request.form['last_name'],
            'email' : request.form['email'],
            'password' : hashed_pw
        }
        query = "INSERT INTO users(first_name, last_name, email, password, created_at, \
        updated_at) VALUES(:first_name, :last_name, :email, :password, NOW(), NOW())"

        new_user_id = mysql.query_db(query, data)
        if new_user_id is not 0:
            session['id'] = new_user_id
        else:
            flash('Unknown error occured')
        return redirect('/success')

@app.route('/success', methods=['POST', 'GET'])
def success():
    if 'id' not in session:
        return redirect('/')
    data = {'id': session['id']}
    current_user = mysql.query_db('SELECT * FROM users WHERE id = :id', data)[0]
    return render_template('success.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    if not EMAIL_REGEX.match(email):
        flash('Email is not valid')
    
    if not len(password) > 7:
        flash('Password is not valid')
    
    if not '_flashes' in session:
        try:
            query = 'SELECT * FROM users WHERE email = :email'
            data = {'email' : email}
            user = mysql.query_db(query, data)
            hashed = user[0]['password']
            logged_in = bcrypt.check_password_hash(hashed, password)
        except:
            flash('Invalid email or password')
            logged_in = False

        if logged_in:
            session['id'] = user[0]['id']
            current_user = mysql.query_db(query, data)[0]
            return redirect('/wall')
        else:
            flash('Invalid email or password')
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/wall', methods=['GET'])
def wall():
    id = session['id']
    query_messages = 'SELECT messages.message, messages.id, first_name, last_name, \
                       messages.created_at FROM messages JOIN users ON messages.user_id = user_id \
                       WHERE users.id = ' + str(id) + ' ORDER BY messages.created_at DESC'
    messages = mysql.query_db(query_messages)

    query_comments = 'SELECT comments.comment, message_id, comments.created_at, first_name, \
                        last_name FROM comments JOIN messages ON messages.id=comments.message_id\
                        JOIN users ON users.id=comments.message_user_id'
    comments = mysql.query_db(query_comments)

    return render_template('wall.html', messages = messages, comments = comments)

@app.route('/post_wall', methods=['POST'])
def post_wall():
    try:    # checks that message isn't too long and overloads db
        data = {
            'message' : request.form['content'],
            'user_id' : int(session['id'])
        }
        query = 'INSERT INTO messages (message, created_at, updated_at, user_id) \
                VALUES (:message, NOW(), NOW(), :user_id)'
        mysql.query_db(query, data)
    except:
        flash('Your message is too long, limit messages and comments to 255 characters')
    return redirect('/wall')

@app.route('/post_comment/<message_id>', methods=['POST'])
def post_comments(message_id):
    try:    # checks that comment isn't too long and overloads db
        query = 'INSERT INTO comments (message_user_id, message_id, comment, created_at, updated_at)\
        VALUES (:user_id, :message_id, :content, NOW(), NOW())'
        data = {
            'user_id' : session['id'],
            'message_id' : message_id,
            'content' : request.form['new_comment']
        }
        mysql.query_db(query, data)
    except:
        flash('Your comment is too long, limit messages and comments to 255 characters')
    return redirect('/wall')

@app.route('/delete_message/<message_id>', methods=['POST'])
def delete_message(message_id):
    # now = datetime.now()
    # date_created = mysql.query_db('SELECT * FROM messages WHERE messages.id = ' + str(message_id))
    # print date_created
    # print now
    # if date_created[0] - now > 30:
    #     print('message is older than 30 mins...')
    # deletes all comments associated with the message being deleted
    query = 'DELETE FROM comments WHERE comments.message_id = ' + str(message_id)
    mysql.query_db(query)
    # deletes the message
    query = 'DELETE FROM messages WHERE messages.id = ' + str(message_id)
    mysql.query_db(query)
    return redirect('/wall')

app.run(debug=True)