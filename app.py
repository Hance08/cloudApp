import os
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 最大檔案上傳大小 16 MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# 資料庫配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///locations.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化資料庫
db = SQLAlchemy(app)

# 初始化 LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 如果未登入的用戶嘗試訪問受保護的路徑，將會重定向到 'login' 頁面

# 使用者資料表
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    
# 建立 Location 資料表
class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    image = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Location {self.name}>'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 檢查並創建資料夾
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 允許的檔案類型檢查
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    locations = Location.query.all()
    return render_template('index.html', locations=locations)

@app.route('/location/<int:id>')
def location(id):
    loc = Location.query.get_or_404(id)
    return render_template('location.html', location=loc)

@app.route('/add', methods=['GET', 'POST'])
def add_location():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        # 檢查圖片
        if 'image' not in request.files:
            return 'No file part'
        file = request.files['image']
        if file.filename == '':
            return 'No selected file'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # 將新地點儲存到資料庫
            new_location = Location(name=name, description=description, image=filename)
            db.session.add(new_location)
            db.session.commit()
            
            return redirect(url_for('index'))
    return render_template('add_location.html')

@app.route('/delete/<int:id>', methods=['POST'])
def delete_location(id):
    location = Location.query.get_or_404(id)
    
    # 刪除資料庫中的地點
    db.session.delete(location)
    db.session.commit()

    # 刪除對應的圖片文件
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], location.image)
    if os.path.exists(image_path):
        os.remove(image_path)

    flash('Location deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 使用 'pbkdf2:sha256' 來加密密碼
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('註冊成功!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 查找用戶
        user = User.query.filter_by(username=username).first()

        # 驗證用戶和密碼
        if user and check_password_hash(user.password, password):
            login_user(user)  # 使用 Flask-Login 進行登入
            flash('成功登入!', 'success')
            return redirect(url_for('index'))
        else:
            flash('無效的帳號或密碼', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出！', 'success')
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    return "這是受保護的頁面，只有登入後才可以查看。"

# 用於 Flask-Login 查找使用者
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
