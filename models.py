from flask_sqlalchemy import SQLAlchemy
from flask import jsonify, request

from werkzeug.security import generate_password_hash, check_password_hash
from config import app

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    password = db.Column(db.String(256))
    email = db.Column(db.String(256), unique=True)
    phone = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean)


def username_password_match(payload):
    check_email = User.query.filter_by(email=payload['email']).first()
    if check_email is None:
        return False
    elif check_password_hash(check_email.password, payload['password'], ) is False:
        return False
    else:
        return True


db.create_all()