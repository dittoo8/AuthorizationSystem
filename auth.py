import json

import jwt
import bcrypt
import mysql.connector
from mysql.connector import Error
from flask import request, jsonify, app
from flask_restx import Resource, Api, Namespace, fields


users = {}

Auth = Namespace(
    name="Auth",
    description="사용자 인증을 위한 API",
)

user_fields = Auth.model('User', {  # Model 객체 생성
    'name': fields.String(description='a User Name', required=True, example="justkode")
})

user_fields_auth = Auth.inherit('User Auth', user_fields, {
    'password': fields.String(description='Password', required=True, example="password")
})

jwt_fields = Auth.model('JWT', {
    'Authorization': fields.String(description='Authorization which you must inclued in header', required=True,
                                   example="eyJ0e~~~~~~~~~")
})


@Auth.route('/register')
class AuthRegister(Resource):
    @Auth.expect(user_fields_auth)
    @Auth.doc(responses={200: 'Success'})
    @Auth.doc(responses={500: 'Register Failed'})
    def post(self):
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        # email 중복체크
        try:
            conn = mysql.connector.connect(host='localhost',
                                           database='userDB',
                                           user='root',
                                           password='1018')
            cursor = conn.cursor()
            email_ck = "SELECT COUNT(*) FROM userDB.userTable WHERE email = '%s'" % email;
            cursor.execute(email_ck)
            sql_result = cursor.fetchall()
            conn.commit()
        except mysql.connector.Error as Error:
            conn.rollback()
            if conn.is_connected():
                cursor.close()
                conn.close()
            return jsonify({
                'result': Error
            }, 500)

        if sql_result[0][0] == 0:  # 중복없는 경우
            # 암호화
            salt = bcrypt.gensalt()
            hash_password = bcrypt.hashpw(password.encode("utf-8"), salt)

            try:
                # 유저 정보 DB 등록
                register_user = "INSERT INTO userDB.userTable (name, email, hashed_password, salt) " \
                                "VALUES('%s','%s', '%s' , '%s')" % (name, email, hash_password.decode(), salt.decode());

                cursor.execute(register_user)
                conn.commit()
                sign_ck = 1
            except mysql.connector.Error as Error:
                conn.rollback()
                sign_ck = Error
            finally:
                if conn.is_connected():
                    cursor.close()
                    conn.close()
        else:  # 중복된 이메일 있음
            sign_ck = 0
        return jsonify({
            'result': sign_ck
        }, 200)

@Auth.route('/validate_user')
class validate_user(Resource):
    @Auth.expect(user_fields_auth)
    @Auth.doc(responses={200: 'Success'})
    @Auth.doc(responses={404: 'User Not Found'})
    @Auth.doc(responses={500: 'Auth Failed'})
    def post(self):
        email = request.form['email']
        name = request.form['name']

        try:
            conn = mysql.connector.connect(host='localhost',
                                           database='userDB',
                                           user='root',
                                           password='1018')
            cursor = conn.cursor()
            valid_user_sql = "SELECT count(*) FROM userDB.userTable" \
                             " WHERE email = '%s' AND name = '%s'" % (email, name);
            print(valid_user_sql)
            cursor.execute(valid_user_sql)
            valid_user_data = cursor.fetchall()
            error_ck = False
        except mysql.connector.Error as Error:
            print(Error)
            error_ck = True
            conn.rollback()
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
        if error_ck:
            return jsonify({'result': 0}, 500)

        if valid_user_data[0][0] == 1:
            return jsonify({'result': 1}, 200)
        else:
            return jsonify({'result': 0}, 500)

@Auth.route('/login')
class AuthLogin(Resource):
    @Auth.expect(user_fields_auth)
    @Auth.doc(responses={200: 'Success'})
    @Auth.doc(responses={404: 'User Not Found'})
    @Auth.doc(responses={500: 'Auth Failed'})
    def post(self):
        email = request.form['email']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(host='localhost',
                                           database='userDB',
                                           user='root',
                                           password='1018')
            cursor = conn.cursor()
            login_user_sql = "SELECT hashed_password, salt, name, isManager,id FROM userDB.userTable WHERE email = '%s'" % email;
            cursor.execute(login_user_sql)
            login_user_data = cursor.fetchall()
            error_ck = False
        except mysql.connector.Error as Error:
            error_ck = True
            conn.rollback()
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
            if error_ck:
                return jsonify({
                    'result': Error
                })
        if len(login_user_data)==1 and bcrypt.checkpw(password.encode(encoding='utf-8'), login_user_data[0][0].encode(encoding="utf-8")):
            token = jwt.encode({'id': login_user_data[0][4]}, str(login_user_data[0][4]), algorithm="HS256").decode(
                    "UTF-8")
            return jsonify({
                'Authorization': token,
                'result': True,
                'name': login_user_data[0][2],
                'isManager': login_user_data[0][3]
            }, 200)
        else:
            return jsonify({
                'result': False
            }, 500)


@Auth.route('/get')
class AuthGet(Resource):
    @Auth.doc(responses={200: 'Success'})
    @Auth.doc(responses={404: 'Login Failed'})
    def get(self):
        header = request.headers.get('Authorization')  # Authorization 헤더로 담음
        print(header)
        if header == None:
            return {"message": "Please Login"}, 404
        data = jwt.decode(header, "secret", algorithm="HS256")
        return data, 200
