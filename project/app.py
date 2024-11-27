from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bcrypt import hashpw, gensalt, checkpw
from flask_mail import Mail, Message
import pyotp
import datetime

app = Flask(__name__)

# Cấu hình ứng dụng
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_very_secret_key_here_change_in_production'
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)

# Cấu hình giới hạn truy cập để chống brute force
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "30 per hour"]
)

# Cấu hình Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Bảng Role (quyền truy cập)
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    users = db.relationship('User', backref='role', lazy=True)

# Bảng User với thêm các trường quản lý phiên
class User(UserMixin, db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    otp_secret = db.Column(db.String(32))
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

# Hàm load người dùng
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Hàm tạo bảng và dữ liệu mẫu
def create_tables():
    db.create_all()  # Tạo bảng nếu chưa tồn tại
    
    if Role.query.count() == 0:  # Kiểm tra xem bảng Role có dữ liệu chưa
        admin_role = Role(name='Quản trị viên', description='Toàn quyền quản trị hệ thống')
        user_role = Role(name='Người dùng bình thường', description='Quyền truy cập hạn chế')
        content_manager_role = Role(name='Quản lý nội dung', description='Quyền quản lý nội dung')

        db.session.add(admin_role)
        db.session.add(user_role)
        db.session.add(content_manager_role)
        db.session.commit()

        # Tạo tài khoản admin, user, và content manager
        create_sample_user('admin', 'admin@example.com', 'admin123', admin_role)
        create_sample_user('user', 'user@example.com', 'user123', user_role)
        create_sample_user('content_manager', 'content@example.com', 'cm123', content_manager_role)

        db.session.commit()


def create_sample_user(username, email, password, role):
    hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
    new_user = User(
        username=username, 
        email=email, 
        password=hashed_password, 
        role=role,
        otp_secret=pyotp.random_base32(),
        is_locked=False,
        is_active=True
    )
    db.session.add(new_user)

@app.route("/")
def index():
    return render_template("index.html", title="Trang chính")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Tên người dùng hoặc email đã tồn tại', 'error')
            return render_template("register.html", title="Đăng ký")

        otp_secret = pyotp.random_base32()
        hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
        user_role = Role.query.filter_by(name='Người dùng bình thường').first()
        
        new_user = User(
            username=username, 
            email=email, 
            password=hashed_password, 
            role=user_role,
            otp_secret=otp_secret,
            is_active=True
        )
        
        db.session.add(new_user)
        db.session.commit()

        flash('Đăng ký thành công. Vui lòng đăng nhập', 'success')
        return redirect(url_for("login"))

    return render_template("register.html", title="Đăng ký")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if not user or user.is_locked or not user.is_active:
            flash('Tài khoản không khả dụng', 'error')
            return redirect(url_for('login'))

        if checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            user.last_login = datetime.datetime.utcnow()
            user.login_attempts = 0
            db.session.commit()

            flash('Đăng nhập thành công', 'success')
            return redirect(url_for("dashboard"))

        else:
            if user:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Tên đăng nhập hoặc mật khẩu không chính xác', 'error')

        return redirect(url_for("login"))

    return render_template("login.html", title="Đăng nhập")

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role.name == 'Quản trị viên':
        return redirect(url_for('manage_users'))  # Chuyển đến trang quản lý người dùng
    elif current_user.role.name == 'Quản lý nội dung':
        return redirect(url_for('manage_content'))  # Chuyển đến trang quản lý nội dung
    else:
        return render_template("user_dashboard.html", title="Thông tin Người dùng")  # Trang người dùng

@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.role.name != 'Quản trị viên':
        flash('Bạn không có quyền thêm người dùng', 'error')
        return redirect(url_for('manage_users'))

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]
    role_id = request.form["role_id"]

    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash('Tên người dùng hoặc email đã tồn tại', 'error')
        return redirect(url_for("manage_users"))

    hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
    new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        role_id=role_id,
        otp_secret=pyotp.random_base32(),
        is_locked=False,
        is_active=True
    )

    db.session.add(new_user)
    db.session.commit()
    flash('Thêm người dùng thành công', 'success')

    return redirect(url_for("manage_users"))

@app.route("/manage_users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role.name != 'Quản trị viên':
        flash('Bạn không có quyền quản lý người dùng', 'error')
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        user_id = request.form.get("user_id")
        action = request.form.get("action")

        if action == "delete" and user_id:
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('Xóa người dùng thành công', 'success')
            else:
                flash('Không tìm thấy người dùng', 'error')

    users = User.query.all()
    roles = Role.query.all()  # Fetch all roles
    return render_template("manage_users.html", title="Quản lý Người dùng", users=users, roles=roles)

@app.route("/edit_user", methods=["POST"])
@login_required
def edit_user():
    if current_user.role.name != 'Quản trị viên':
        flash('Bạn không có quyền chỉnh sửa người dùng', 'error')
        return redirect(url_for('manage_users'))

    user_id = request.form.get("user_id")
    username = request.form.get("username")
    email = request.form.get("email")
    role_id = request.form.get("role_id")

    user = User.query.get(user_id)
    if user:
        user.username = username
        user.email = email
        user.role_id = role_id
        db.session.commit()
        flash('Chỉnh sửa người dùng thành công', 'success')
    else:
        flash('Không tìm thấy người dùng', 'error')

    return redirect(url_for("manage_users"))

@app.route("/manage_content")
@login_required
def manage_content():
    if current_user.role.name != 'Quản lý nội dung':
        flash('Bạn không có quyền quản lý nội dung', 'error')
        return redirect(url_for('dashboard')) 
    
    return render_template("manage_content.html", title="Quản Lý Nội Dung")


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Cập nhật thông tin người dùng hiện tại
        current_user.username = username
        current_user.email = email

        # Nếu mật khẩu mới được nhập, cập nhật mật khẩu
        if password:
            hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
            current_user.password = hashed_password

        db.session.commit()
        flash("Thông tin cá nhân đã được cập nhật!", "success")
        return redirect(url_for("edit_profile"))

    return render_template("edit_profile.html", title="Chỉnh sửa thông tin cá nhân")

from flask import redirect, url_for
from flask_login import logout_user, login_required

@app.route('/logout', methods=['POST'])
@login_required  
def logout():
    logout_user()  # Đăng xuất người dùng
    return redirect(url_for('login'))  # Chuyển hướng về trang đăng nhập


if __name__ == "__main__":
    with app.app_context():
        create_tables()
    app.run(host='0.0.0.0', port=5000, debug=True)