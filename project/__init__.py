from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sendgrid import SendGridAPIClient
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))

from project.models import *
db.create_all()

import project.views