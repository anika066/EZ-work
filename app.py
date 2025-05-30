from flask import Flask, request, jsonify, send_from_directory
from flask import render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
import os, jwt, time, uuid
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'docx', 'pptx', 'xlsx'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
fernet = Fernet(Fernet.generate_key())

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    verified = db.Column(db.Boolean, default=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    filepath = db.Column(db.String(300))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'error': 'Token missing'}), 403
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.get(data['user_id'])
                if role and user.role != role:
                    return jsonify({'error': 'Access denied'}), 403
                return f(user, *args, **kwargs)
            except:
                return jsonify({'error': 'Invalid token'}), 403
        return wrapper
    return decorator

# --------- HTML PAGE ROUTES (Frontend) ---------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup-page')
def signup_page():
    return render_template('signup.html')

@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
@token_required()
def dashboard(current_user):
    return render_template('dashboard.html', email=current_user.email)

# --------- API ROUTES (Backend) ---------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_pw = generate_password_hash(data['password'])
    user = User(email=data['email'], password=hashed_pw, role='client')
    db.session.add(user)
    db.session.commit()
    token = serializer.dumps(user.email, salt='email-verify')
    verify_url = f"http://localhost:5000/verify/{token}"
    msg = Message('Verify your email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Click here to verify: {verify_url}'
    mail.send(msg)
    return jsonify({'message': 'User created. Check email to verify.'})

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully'})
        return jsonify({'error': 'User not found'})
    except:
        return jsonify({'error': 'Invalid or expired token'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        if not user.verified:
            return jsonify({'error': 'Email not verified'}), 403
        token = jwt.encode({'user_id': user.id, 'role': user.role, 'exp': time.time() + 3600}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'})

@app.route('/upload', methods=['POST'])
@token_required(role='ops')
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'})
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    new_file = File(filename=filename, filepath=filepath, uploader_id=current_user.id)
    db.session.add(new_file)
    db.session.commit()
    return jsonify({'message': 'File uploaded successfully'})

@app.route('/files', methods=['GET'])
@token_required(role='client')
def list_files(current_user):
    files = File.query.all()
    return jsonify([{'id': f.id, 'filename': f.filename} for f in files])

@app.route('/download/<int:file_id>', methods=['GET'])
@token_required(role='client')
def generate_download_link(current_user, file_id):
    file = File.query.get(file_id)
    if not file:
        return jsonify({'error': 'File not found'})
    token = fernet.encrypt(f"{file_id}|{current_user.id}".encode()).decode()
    return jsonify({'download_url': f"http://localhost:5000/secure-download/{token}"})

@app.route('/secure-download/<token>', methods=['GET'])
@token_required(role='client')
def secure_download(current_user, token):
    try:
        data = fernet.decrypt(token.encode()).decode()
        file_id, user_id = map(int, data.split('|'))
        if user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        file = File.query.get(file_id)
        return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)
    except:
        return jsonify({'error': 'Invalid or expired download link'})

# --------- Run the App ---------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
