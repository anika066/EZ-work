from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import jwt, time

def hash_password(password):
    return generate_password_hash(password)

def check_password(password, hashed):
    return check_password_hash(hashed, password)

def generate_jwt(data, secret, expires=3600):
    return jwt.encode({'data': data, 'exp': time.time() + expires}, secret, algorithm='HS256')

def decode_jwt(token, secret):
    return jwt.decode(token, secret, algorithms=['HS256'])['data']

def is_allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

