from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
mail= Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'sohy1018@naver.com'
app.config['MAIL_PASSWORD'] = '*****'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

@app.route("/email")
def email():
#    msg = Message('Hello', sender = 'yourId@gmail.com', recipients = ['sohy1018@naver.com'])
#    msg.body = "Hello Flask message sent from Flask-Mail"
#    mail.send(msg)
   print('gdgdgd')
   return "Sent"