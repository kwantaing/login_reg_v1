from flask import Flask, render_template, request, redirect, flash, url_for, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re 

NAME_REGEX = re.compile(r'^[a-zA-Z]+$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

app = Flask(__name__)
app.secret_key="secret_key"
bcrypt = Bcrypt(app)

@app.route("/")
def index():
    print(session)
    return render_template("index.html")

@app.route("/register", methods = ["POST"])
def register():
    mysql = connectToMySQL("log_reg")
    isValid = True
    if(len(request.form["password"])<5 or len(request.form["pwconfirm"])<5):
        flash("please make a valid password over 5 characters", 'register')
        isValid = False
    if (len(request.form["first_name"])<2):
        flash("First Name must be at least 2 characters", 'register')
        isValid = False
    if (len(request.form["last_name"])<2):
        flash("Last Name must be at least 2 characters", 'register')
        isValid = False
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email address!", 'register')
        isValid = False
    if isValid ==False:
        return redirect('/')
    hashedpw = (bcrypt.generate_password_hash(request.form["password"]))
    if not (bcrypt.check_password_hash(hashedpw, request.form["pwconfirm"])):
        flash("Passwords do not match!", 'register')
        isValid = False

    data = {
        'first_name' : request.form["first_name"],
        'last_name'  : request.form["last_name"],
        'email'      : request.form["email"],
        'pw'         : hashedpw
    }

    mysql2 = connectToMySQL("log_reg")
    checkemail = "SELECT email from USERS"
    all_emails = mysql2.query_db(checkemail)
    print(all_emails)
    for user in all_emails:
        if(user["email"]==request.form["email"]):
            isValid = False
            flash("email is already registered",'register')
            return redirect('/')

    if(isValid):
        query= "INSERT INTO USERS (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(pw)s, NOW(),NOW())"
        registered = mysql.query_db(query,data)
        session["current_id"]=registered
        return redirect('/success')
    else: 
        return redirect('/')

@app.route('/login', methods = ["POST"])
def login():
    mysql = connectToMySQL("log_reg")
    isValid = True
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email address!",'login')
        isValid = False
    if(len(request.form["password"])<1):
        flash("wrong password, try again",'login')
        isValid = False
    if isValid ==False:
        return redirect('/')
    data = {
        'email':request.form["email"],
        'pw': request.form["password"]
    }
    query = "SELECT * from USERS where email = %(email)s"
    info = mysql.query_db(query,data)
    print(info)
    print(bcrypt.check_password_hash(info[0]['password'],request.form["password"]))
    if not(bcrypt.check_password_hash(info[0]['password'],request.form["password"])):
        flash("wrong password, try again",'login')
        return redirect('/')
    else:
        session["current_id"]=info[0]["user_id"]
        print("success")
        print(session)

        return redirect (url_for("login_success"))

@app.route('/success')
def login_success():
    if bool(session)==False:
        print(session)
        return redirect('/')
    else:
        print(session)
        id = session["current_id"]
        response = "Welcome User id"
        mysql = connectToMySQL("log_reg")
        query = f"SELECT * FROM USERS WHERE user_id = {id}"
        result = mysql.query_db(query)
        print(result)
        return render_template("success.html",user = result)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)
    