from config import app
from flask_marshmallow import Marshmallow

ma = Marshmallow(app)


class StudentSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "email", "phone_number")


userSchema = StudentSchema()
userSchemas = StudentSchema(many=True)