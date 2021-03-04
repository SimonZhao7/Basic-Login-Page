from flask import Flask, redirect, render_template, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager # installed but never used


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

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
    return render_template('info.html', error=error) # confirl form resubmission error


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
            return redirect(url_for('account_created'))
        elif account is not None:
            if username == account.username:
                error = "* Username already exists."
        else:
            if email == account2.email:
                error = "* Email already exists."

    return render_template('register.html', error=error)


@app.route("/created", methods=["POST", "GET"])
def account_created():
    if request.method == "POST":
        return redirect('login')
    else:
        return render_template('created.html')


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)