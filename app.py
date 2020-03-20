from flask import jsonify, request
from flask_jwt_extended import (JWTManager,
                                jwt_required,
                                create_access_token,
                                get_jwt_identity)
from flask_restful import Resource, Api
from config import app
from models import User, db, username_password_match
from werkzeug.security import generate_password_hash
from serializer import userSchema, userSchemas

jwt = JWTManager(app)
api = Api(app)


class UserRegister(Resource):
    # @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        if current_user:
            result = User.query.filter_by(email=current_user).first()
            if not result.is_admin:
                return "only admin has access"
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(name=data['name'], email=data['email'], password=hashed_password,
                        phone=data['phone'], is_admin=data['is_admin'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify('user created')


class LoginApi(Resource):
    def post(self):
        payload = request.get_json()
        match = username_password_match(payload)
        if match is True:
            access_token = create_access_token(identity=payload['email'])
            return jsonify({'access_token': access_token})
        else:
            return jsonify({'error': 'invalid data'})


class StudentList(Resource):
    @jwt_required
    def get(self):
        current_user = get_jwt_identity()
        if current_user:
            result = User.query.filter_by(email=current_user).first()
            if not result.is_admin:
                user = User.query.filter_by(id=result.id).first()
                user = userSchema.dump(user)
                return jsonify(user)
            else:
                user = User.query.all()
                user = userSchemas.dump(user)
                return jsonify(user)
        else:
            return jsonify({'message': 'No user found!'})


class StudentDetails(Resource):
    @jwt_required
    def get(self, id):
        current_user = get_jwt_identity()
        if current_user:
            result = User.query.filter_by(email=current_user).first()
            if not result.is_admin:
                if id != result.id:
                    return jsonify({'message': 'No user found!'})
                user = User.query.filter_by(id=id).first()
                user = userSchema.dump(user)
                return jsonify(user)
            else:
                user = User.query.filter_by(id=id).first()
                if not user:
                    return jsonify({'message': 'No user found!'})
                user = userSchema.dump(user)
                return jsonify(user)

    @jwt_required
    def put(self, id):
        current_user = get_jwt_identity()
        result = User.query.filter_by(email=current_user).first()
        user = User.query.filter_by(id=id).first()
        if not user:
            return jsonify({'message': 'No user found!'})
        if not result.is_admin:
            if user.id != result.id:
                return jsonify({'message': 'No user found!'})

        data = request.get_json()
        user.name = data['name']
        user.email = data['email']
        user.phone = data['phone']
        db.session.commit()
        return jsonify({'message': 'The user has been updated!'})