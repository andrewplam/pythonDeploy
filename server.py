# import Flask
from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
# the "re" module will let us perform some regular expression operations
import re
from mysqlconnection import connectToMySQL
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# Name_REGEX = re.compile(r'^[a-zA-Z]+$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
    # we are creating an object called bcrypt, 
                         # which is made by invoking the function Bcrypt with our app as an argument
app.secret_key = "keke"

@app.route("/")
def index(): 
    return render_template("index.html")



@app.route('/register', methods=['POST'])
def register():
    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    session['password'] = request.form['password']
    session['password_confirmation'] = request.form['password_confirmation']
    if len(session['first_name']) == 0:
        flash("First name cannot be blank!", 'first_name')
    elif len(session['first_name']) <=2:
        flash("First name must be 2 or more charcters")
    if len(session['last_name']) <1:
        flash("Last name cannot be blank!", 'last_name')
    elif len(session['last_name']) <=2:
        flash("Last name must be 2 or more charcters")
    if len(session['email']) <1:
        flash("Email cannont be blank!", 'email')
    elif not EMAIL_REGEX.match(session['email']):
        flash("Invalid Email Address!", 'email')
    if len(session['password']) <= 1:
        flash("Password cannot be blank!", 'email')
    if session['password_confirmation'] != session['password']:
        flash("Passwords don't match!", 'email')    
    if '_flashes' in session.keys():
        return redirect("/")

    #check db for email validation
    mysql = connectToMySQL("logindb")
    new_data = mysql.query_db("SELECT email FROM user")
    for email in new_data:
        if request.form['email'] == email['email']:
            flash('Email exist')
            return redirect('/')
        else:
            pw_hash = bcrypt.generate_password_hash(request.form['password'])
            print(pw_hash)
            query = "Insert INTO user(first_name,last_name,email,password) VALUES(%(first_name)s,%(last_name)s,%(email)s,%(password_hash)s);"
            mysql = connectToMySQL("logindb")
            data = {
                'first_name':session['first_name'],
                'last_name':session['last_name'],
                'email':session['email'],
                'password_hash':pw_hash
    }
    new_email_id = mysql.query_db(query, data)
    session['id'] = new_email_id
    print('$$$$$$$$$$$$$$$$$$$$$$ This session["id"] : ', session['id'])
    return redirect('/registered')

@app.route('/registered')
def registered():
    return render_template('registered.html')

@app.route('/loggedin')
def loggedin():
    return render_template("loggedin.html")

@app.route('/loginprocess', methods=['POST'])
def login():
    mysql = connectToMySQL("logindb")
    query = "SELECT * FROM user WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if result:
        
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['id'] = result[0]['id']
            session['first_name'] = result[0]['first_name']
            session['last_name'] = result[0]['last_name']
            # never render on a post, always redirect!
            return redirect('/wall')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("You could not be logged in")
    return redirect("/")

#The wall stuff

@app.route('/wall')
def wall():
    # if 'user_id' not in session:
    #     return redirect('/')
    data = {'id': session['id']}
    query = """SELECT user.first_name AS first_name, 
                user2.first_name AS sender_name,  
                message.id AS message_id, 
                message.message AS message, 
                message.user.id AS sender_id, 
                message.user_id1 AS reciever_id, message.created_at AS created_at
                FROM user
                LEFT JOIN message ON message.user_id1 = id
                LEFT JOIN user AS user2 ON user2.id = message.user_id
                WHERE user_id = %(id)s;"""
    mysql = connectToMySQL('logindb')        
    messages_data = mysql.query_db(query, data)
    
    print( messages_data)

    # get the user info from the DB
    query = 'SELECT first_name FROM user WHERE id = %(id)s;'
    data = {'id': session['id']}
    mysql = connectToMySQL('logindb')
    users = mysql.query_db(query, data)

    # Get the lisft o users except the logged in user
    mysql = connectToMySQL('logindb')
    query = 'SELECT id AS receiver_id, first_name AS receiver_name FROM user WHERE id <> %(id)s;'
    other_users = mysql.query_db(query, data)
    
    return render_template('/wall.html', messages_data = messages_data,users=users,other_users=other_users)

@app.route('/delete/<id>')
def delete(id):
    if 'id' not in session:
        session.clear()
        return redirect('/')

    data = {'id': id}
    mysql = connectToMySQL('logindb')
    query = 'DELETE FROM message WHERE id = %(id)s'
    mysql.query_db(query, data)
    return redirect('/wall')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/send', methods=["POST"])
def send():
    data = {
        'message': request.form['message'],
        'sender_id': session['user_id'],
        'reciever_id': request.form['reciever_id']
    }
    mysql = connectToMySQL('logindb')
    query = 'INSERT INTO message (message, sender_id, reciever_id) VALUES (%(message)s, %(sender_id)s, %(reciever_id)s);'
    mysql.query_db(query, data)
    return redirect('/wall')    

  
if __name__=="__main__":
    app.run(debug=True) 