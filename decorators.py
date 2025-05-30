from functools import wraps
from flask import request, jsonify, current_app
import jwt

def token_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split(" ")[1]
            if not token:
                return jsonify({'msg': 'Missing token'}), 403
            try:
                data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            except Exception as e:
                return jsonify({'msg': 'Invalid token', 'error': str(e)}), 403
            if role and data['role'] != role:
                return jsonify({'msg': 'Permission denied'}), 403
            return fn(data, *args, **kwargs)
        return decorated
    return wrapper
