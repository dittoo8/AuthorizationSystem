from flask import Flask, make_response
from flask import request, render_template, flash, redirect, url_for, jsonify, json
from flask import redirect
import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
from flask_restx import Resource, Api
from auth import Auth
import requests
import datetime
from flask_mail import Mail, Message
from random import randint

app = Flask(__name__)
app.secret_key = '123'

api = Api(app)
api.add_namespace(Auth, '/auths')

app.config['JWT_SECRET_KEY'] = 'jwt-secret'

mail= Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465

app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)




def valid_data(data):  # 입력된 데이터의 모든 값이 존재하는지 확인
    for key, value in data.items():
        if value == '':
            return False
    return True


@app.route('/user_manage')
def user_manage():
    try:
        conn = mysql.connector.connect(host='localhost',
                                       database='userDB',
                                       user='root',
                                       password='1018')
        cursor = conn.cursor()
        sql = "SELECT email, name FROM userDB.userTable WHERE isManager = 0";
        cursor.execute(sql)
        user_data = cursor.fetchall()
        conn.commit()
    except mysql.connector.Error:
        conn.rollback()
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    return render_template('user_manage.html', userData=user_data)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        if valid_data(data):
            register_result = requests.post('http://0.0.0.0:5000/auths/register', data={
                'email': data['email'],
                'name': data['name'],
                'password': data['password']
            }).json()
            sign_ck = register_result[0]['result']
        else:
            sign_ck = 2
        return jsonify(result='success', signCk=sign_ck)
    else:
        return render_template('register.html')


@app.route('/setcookie', methods=["GET", "POST"])
def setcookie():
    if request.method == 'GET':
        token = request.args.get('auth')
        email = request.args.get('email')
        auto_login = request.args.get('auto_login')
        res = make_response(redirect('main'))
        if  auto_login == 'true':
            expire_date = datetime.datetime.now()+datetime.timedelta(days=90)
            res.set_cookie('auto_login', auto_login, expires=expire_date)
        else:
            expire_date = datetime.datetime.now() + datetime.timedelta(minutes=30)
        res.set_cookie('token', token, expires=expire_date)
        res.set_cookie('user_email', email, expires=expire_date)

        return res


@app.route("/getcookie")
def getcookie():
    token = request.cookies.get('token')
    user_email = request.cookies.get('user_email')
    return [token, user_email]


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':  # 로그인할 데이터 전송받음
        data = request.get_json()
        if valid_data(data):
            login_result = requests.post('http://0.0.0.0:5000/auths/login', data={
                'email': data['email'],
                'password': data['password'],
                'auto_login': data['auto_login']
            }).json()
            login_ck = login_result[0]['result']
            if login_result[1] == 200:
                # 로그인 성공
                return jsonify(result='success', userName=login_result[0]['name'],
                               user_auth=login_result[0]['Authorization'], user_email=data['email'], loginCk=login_ck,
                               auto_login=data['auto_login'])
            else:
                # 로그인 실패 (비밀번호 다름)
                return jsonify(result='success', loginCk=login_ck)
        else:
            return jsonify(result='success', loginCk=2)
    else:
        return render_template('login.html')


# # 이메일 인증 클릭시 이동하는 곳 ?
# @app.route('/newPass/<email>', methods=['GET'])

@app.route("/email", methods=['GET'])
def email():
    if request.method=='POST':
        #setcookie 애서 otp 넣기?
        otp = randint(100000, 999999)
        msg = Message('Hello', sender = 'sohyun1018@gmail.com', recipients = ['sohyun1018@gmail.com'])
        msg.body = "578324"
        mail.send(msg)
        return "Sent"

@app.route('/find_password', methods=['POST','GET'])
def find_password():
    if request.method == 'POST':
        data = request.get_json()
        if valid_data(data):
            valid_user_check = requests.post('http://0.0.0.0:5000/auths/validate_user', data={
                'email': data['email'],
                'name': data['name']
            }).json()
            user_ck = valid_user_check[0]['result']
            return jsonify(result='success', user_ck=user_ck)
        else:
            user_ck = 2
            return jsonify(result='success', user_ck=user_ck)
    # data = request.get_json()
    # 입력된 이메일로 비밀번호 찾기 메일 전송

    ##이메일링크 클릭 시 비밀번호 재설정페이지로 redirect ..?
    else:
        return render_template('find_password.html')


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('main')))
    resp.delete_cookie('token')
    resp.delete_cookie('user_email')
    return resp


@app.route('/main', methods=['GET', 'POST'])
def main():
    cookie = getcookie()
    if cookie:
        return render_template('main.html', name=cookie[1], isManager=1)
    return render_template('main.html')


@app.route('/')
def init():
    return redirect(url_for('main'))


@app.errorhandler(404)
def page_not_found(error):
    return '페이지가 없습니다. URL을 확인하세요', 404


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
