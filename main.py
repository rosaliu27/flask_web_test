from flask import Flask, render_template, request, url_for, redirect, flash, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import configparser
from werkzeug.security import check_password_hash, generate_password_hash
import pickle
import pandas as pd

# config 初始化
config = configparser.ConfigParser()
config.read('config.ini')

# Flask 初始化
app = Flask(__name__)
app.secret_key = config.get('flask', 'secret_key')

#users = {'Me': {'password': 'myself'}}
with open("users.pkl", "rb") as tf:
    users = pickle.load(tf)
print(users)

# Flask-Login 初始化
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = 'login'
login_manager.login_message = '請證明你並非來自黑暗草泥馬界'


class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(user_id):
    if user_id not in users:
        return

    user = User()
    user.id = user_id
    return user

@login_manager.request_loader
def request_loader(request):
    user_id = request.form.get('user_id')
    if user_id not in users:
        return

    user = User()
    user.id = user_id

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    user.is_authenticated = request.form['password'] == users[user_id]['password']

    return user


# Flask-Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    
    user_id = request.form['user_id']
    password = request.form['password']
    #if (user_id in users) and check_password_hash(users[user_id]['password'], password):
    if (user_id in users) and (password == users[user_id]['password']):
        user = User()
        user.id = user_id
        login_user(user)
        flash(f'{user_id}！登入成功！')
        return redirect(url_for('photo'))

    flash('登入失敗了...')
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = current_user.get_id()
    logout_user()
    flash('您已登出！')
    return render_template('login.html') 

# register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        username = request.form['user_id']
        password = request.form['password']
        password1 = request.form['password1']

        if password != password1:
            flash('兩次密碼輸入不一致！')
            return redirect(url_for('register'))

        exists_user = username in users
        if exists_user:
            flash('該用戶名已存在，請更換其他用戶名！')
            return redirect(url_for('register'))
        else:    
            users[username] = {'password' : password}
            print(users)
            with open("users.pkl", "wb") as tf:
                pickle.dump(users, tf)
            flash('註冊成功，請重新登入！')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/showcsv')
def showcsv():
    filename = 'file.csv'
    #data = pd.read_csv(filename, header=0, names=['CatonID', 'Storage Code', 'SN', 'PN', 'LOT', 'D/C', 'QTY', 'COO'])
    data = pd.read_csv(filename, header=None)
    datalist = list(data.values)
    print(datalist)
    return render_template('showcsv.html', datalist = datalist)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/download")
def downloadcsv():
    url = "http://172.20.10.8:5000/showcsv"
    table = pd.read_html(url)
    table_df = table[0]
    #df = pd.read_html('/showcsv')
    #df.to_csv('my_file.csv', index=False)
    # resp = make_response(table_df.to_csv())
    # resp.headers["Content-Disposition"] = "attachment; filename=export.csv"
    # resp.headers["Content-Type"] = "text/csv"
    #a = str(len(tables))
    print(table[0])
    

@app.route('/photo')
def photo():
    return render_template('photo.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0',port='5000',debug=True)
