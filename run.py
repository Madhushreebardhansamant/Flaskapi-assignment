from app import api,UserRegister,LoginApi,StudentList,StudentDetails
from config import app

api.add_resource(UserRegister, '/user/signup/')
api.add_resource(LoginApi, '/user/login/')
api.add_resource(StudentList, '/user/get/')
api.add_resource(StudentDetails, '/user/get/<int:id>')

if __name__ == "__main__":
    app.run(debug=True, port=5555)