from flask import Flask, redirect, render_template, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask_login import LoginManager  # installed but never used

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))

@app.route("/")
def home():
    return render_template('home.html')


class Account(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    email = db.Column("email", db.String(100), unique=True, nullable=False)
    username = db.Column("username", db.String(20), unique=True, nullable=False)
    password = db.Column("password", db.String(20), unique=False, nullable=False)


@app.route("/login", methods=["POST", "GET"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["user"]
        password = request.form["pass"]

        user = Account.query.filter_by(username=username).first()
        #
        if user is None:
            error = '* Username or Password is incorrect'
        elif user.username == username and bcrypt.check_password_hash(user.password, password):
            return redirect(url_for('home'))
        else:
            error = '* Username or Password is incorrect.'
    return render_template('login.html', error=error)  # confirm form resubmission error


@app.route("/register", methods=["POST", "GET"])
def register():
    error = None
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["user"]
        password = request.form["pass"]
        confirm_pass = request.form["confirm-pass"]

        account = Account.query.filter_by(username=username).first()
        account2 = Account.query.filter_by(email=email).first()

        if password != confirm_pass:
            error = "* Passwords don't match"
        elif len(username) < 6:
            error = "* Username too short. Needs to be 6 letters or more"
        elif len(password) < 8:
            error = "* Password too short. Needs to be 8 letters or more."
        elif account is None and account2 is None:
            # add info to database
            # redirect to link created account
            hash_pass = bcrypt.generate_password_hash(password, 10)
            account = Account(email=email, username=username, password=hash_pass)
            db.session.add(account)
            db.session.commit()
            return redirect(url_for('success', message="Success! You have created your account."))
        elif account is not None:
            if username == account.username:
                error = "* Username already exists."
        else:
            if email == account2.email:
                error = "* Email already exists."

    return render_template('register.html', error=error)


@app.route('/forgot', methods=["POST", "GET"])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        user = Account.query.filter_by(email=email).first()

        if user is not None:
            # send an email
            message = Mail(
                from_email='botbotoriginal@gmail.com',
                to_emails=[email],
                subject='Password Reset',
                html_content='<p>This is your link to reset your password: <a href="http://127.0.0.1:5000/reset/'
                             + email + '">Reset Here</a></p> '
            )
            # reset/hashed email for security
            sg.send(message)
            return redirect(url_for('success', message="Success! An email of confirmation has been sent to you. "
                                                       "Click on the link attached to change your password."))
    return render_template('forgot.html')


@app.route('/reset/<email>', methods=["POST", "GET"])
def reset(email):
    error = None
    if request.method == 'POST':
        account = Account.query.filter_by(email=email).first()

        if account is not None:
            password = request.form['password']
            confirm_pass = request.form['confirm-pass']
            if password == confirm_pass:
                pass
                # update database and send back to home
                account.password = bcrypt.generate_password_hash(password, 10)
                db.session.commit()
                return redirect(url_for('success', message="You have successfully changed your password. Click login to"
                                                           " return to login page."))
            else:
                error = "* Passowrds do not match"
    return render_template('reset.html', error=error)


@app.route("/success", methods=["POST", "GET"])
def success():
    if request.method == "POST":
        return redirect('login')
    else:
        return render_template('message.html', message=request.args.get('message'))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
