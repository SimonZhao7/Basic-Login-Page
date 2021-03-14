from project import db


class Account(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    email = db.Column("email", db.String(100), unique=True, nullable=False)
    username = db.Column("username", db.String(20), unique=True, nullable=False)
    password = db.Column("password", db.String(20), unique=False, nullable=False)
    hash_email = db.Column("hash_email", db.String(100), unique=True, nullable=False)