import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError,Optional
from datetime import datetime
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'txt','csv','xlsx','xls'}

app = Flask(__name__)
app.config['SECRET_KEY'] = '518349276'
app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
# 登录表单类
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# 注册表单类
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
        
# 更新用户信息的表单类
class UpdateUserInfoForm(FlaskForm):
    username = StringField('New Username', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Update')
    
# 上传信息的表单类
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(80), nullable=False)
    path = db.Column(db.String(120), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<File {self.filename}>'

# 注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password,form.password.data):
            # 登录成功，设置用户会话
            session['logged_in'] = True
            flash('You were successfully logged in', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/update', methods=['GET', 'POST'])
def update_user():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    form = UpdateUserInfoForm()
    if form.validate_on_submit():
        current_user = User.query.filter_by(username=session['username']).first()
        if current_user:
            # 更新用户名和密码
            current_user.username = form.username.data
            current_user.set_password(form.password.data)
            db.session.commit()
            flash('Your account has been updated.', 'success')
            session['username'] = form.username.data  # 更新session中的用户名
            return redirect(url_for('home'))
        else:
            flash('User not found.', 'danger')
    return render_template('update.html', title='Update User Info', form=form)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # 检查是否有文件在请求的文件对象中
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join('backform\database', filename)
            file.save(filepath)
            new_file = File(filename=filename, path=filepath)
            db.session.add(new_file)
            db.session.commit()
            flash('File successfully uploaded and saved to database.')
            return redirect(url_for('upload_file', filename=filename))
    return render_template('upload.html')

@app.route('/home')
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('home.html', title='Update User Info')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)