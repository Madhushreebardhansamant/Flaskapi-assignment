import jwt
import datetime

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_marshmallow import Marshmallow

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:fission@localhost:5432/postgres'

db = SQLAlchemy(app)

ma = Marshmallow(app)


class StudentSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "email", "phone_number")


userSchema = StudentSchema()
userSchemas = StudentSchema(many=True)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(50), nullable=False)


class Superuser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    admin = db.Column(db.Boolean, default=False)


db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Superuser.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Admin can only perform this action!'})
    users = Student.query.all()
    result = userSchemas.dump(users)
    return jsonify(result), 200


@app.route('/user/<id>', methods=['GET'])
@token_required
def get_one_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Admin can only perform this action!'})
    user = Student.query.filter_by(id=id).first()
    if not user:
        return jsonify({'message': 'No user found!'}), 404
    result = userSchema.dump(user)
    return jsonify(result), 200


@app.route('/admin/register', methods=['POST'])
def create_superuser():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Superuser(name=data['name'], email=data['email'], password=hashed_password, admin=data['admin'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New superuser created!'}), 200


@app.route('/user', methods=['POST'])
@token_required
def create_student(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Admin can only perform that action!'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Student(name=data['name'], email=data['email'], password=hashed_password,
                       phone_number=data['phone_number'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'}), 200


@app.route('/user/<id>', methods=['PUT'])
@token_required
def update_student(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Admin can only perform that action!'})

    user = Student.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    data = request.get_json()
    user.name = data['name']
    user.email = data['email']
    user.phone_number = data['phone_number']
    db.session.commit()
    return jsonify({'message': 'The user has been updated!'}), 200


@app.route('/user/<id>', methods=['DELETE'])
@token_required
def delete_student(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Admin can only perform this action!'})
    user = Student.query.filter_by(id=id).first()
    if not user:
        return jsonify({'message': 'No user found!'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user has been deleted!'}), 200


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = Superuser.query.filter_by(email=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)
