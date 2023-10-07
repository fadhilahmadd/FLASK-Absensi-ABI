from flask import Flask, make_response, jsonify, Response, json, request
from flask_marshmallow import Marshmallow
from flask_restx import Resource, Api, reqparse
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash
import jwt

app = Flask(__name__)
api = Api(app)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/absen"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'abiyosoft'

db = SQLAlchemy(app)
ma = Marshmallow(app)


class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    nama = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    createdAt = db.Column(db.DateTime, default=db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Users


user_schema = UserSchema()
users_schema = UserSchema(many=True)

logParser = reqparse.RequestParser()
logParser.add_argument('username', type=str, help='username', location='json', required=True)
logParser.add_argument('password', type=str, help='password', location='json', required=True)


@api.route('/login')
class LogIn(Resource):
    @api.expect(logParser)
    def post(self):
        args = logParser.parse_args()
        username = args['username']
        password = args['password']

        if not username or not password:
            return {
                'message': 'Username dan Password harus diisi'
            }, 400

        user = Users.query.filter_by(username=username).first()

        if not user:
            return {
                'message': 'Username / password salah'
            }, 400

        is_admin = user.is_admin

        if check_password_hash(user.password, password):
            if is_admin:
                token = jwt.encode({
                    "user_id": user.id,
                    "user_username": user.username,                    
                }, app.config['SECRET_KEY'], algorithm="HS256")                

                return {
                    'message': 'Login Berhasil sebagai Admin',
                    'is_admin': 1,
                    'user_id': user.id,
                    'token': token
                }, 200
            else:
                token = jwt.encode({
                    "user_id": user.id,
                    "user_username": user.username,                    
                }, app.config['SECRET_KEY'], algorithm="HS256")                

                return {
                    'message': 'Login Berhasil sebagai User',
                    'is_admin': 0,
                    'user_id': user.id,
                    'token': token
                }, 200
        else:
            return {
                'message': 'Username / Password Salah'
            }, 400


regParser = reqparse.RequestParser()
regParser.add_argument('nama', type=str, help='Nama', location='json', required=True)
regParser.add_argument('username', type=str, help='Username', location='json', required=True)
regParser.add_argument('password', type=str, help='Password', location='json', required=True)
regParser.add_argument('konfirmasi_password', type=str, help='Konfirmasi Password', location='json', required=True)
regParser.add_argument('is_admin', type=int, help='is_admin', location='json', required=True)

@api.route('/register')
class Registration(Resource):
    @api.expect(regParser)
    def post(self):
        args = regParser.parse_args()
        nama = args['nama']
        username = args['username']
        password = args['password']
        password2 = args['konfirmasi_password']
        is_admin = args['is_admin']

        if password != password2:
            return {
                'messege': 'Password tidak cocok'
            }, 400

        user = db.session.execute(
            db.select(Users).filter_by(username=username)).first()
        if user:
            return "Username sudah terpakai silahkan coba lagi menggunakan username lain"
        user = Users()
        user.nama = nama
        user.username = username
        user.password = generate_password_hash(password)
        user.is_admin = is_admin
        db.session.add(user)        
        db.session.commit()
        return {'message':
                'Registrasi Berhasil.'}, 201


def decodetoken(jwtToken):
    decode_result = jwt.decode(
        jwtToken,
        app.config['SECRET_KEY'],
        algorithms=['HS256'],
    )
    return decode_result


usrParser = reqparse.RequestParser()
@api.route('/user')
class GetAllUsers(Resource):
    def get(self):
        args = usrParser.parse_args()
        users = Users.query.all()
        user_list = []

        for user in users:
            is_admin_str = 'admin' if user.is_admin else 'karyawan'
            user_data = {
                'user_id': user.id,
                'username': user.username,
                'nama': user.nama,
                'status': is_admin_str,
            }
            user_list.append(user_data)

        return user_list, 200


@api.route('/user/<int:user_id>')
class GetUser(Resource):
    def get(self, user_id):
        user = Users.query.get(user_id)
        if user:
            user_schema = UserSchema()
            user_data = user_schema.dump(user)
            is_admin_str = 'admin' if user.is_admin else 'karyawan'
            user_data['status'] = is_admin_str
            return user_data, 200
        else:
            return {
                'message': 'User tidak ditemukan',
            }, 404


@api.route('/edit/<int:user_id>')
class EditUser(Resource):
    @api.expect(regParser)
    def put(self, user_id):
        args = regParser.parse_args()
        nama = args['nama']
        username = args['username']
        password = args['password']
        password2 = args['konfirmasi_password']
        is_admin = args['is_admin']

        if password != password2:
            return {
                'message': 'Password tidak cocok'
            }, 400

        user = Users.query.get(user_id)

        if not user:
            return {
                'message': 'User tidak ditemukan',
            }, 404

        user.nama = nama
        user.username = username
        user.password = generate_password_hash(password)
        user.is_admin = is_admin
        db.session.commit()

        return {'message': 'Update user berhasil.'}, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
