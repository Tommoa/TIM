import os
from time import sleep
from . import database
from datetime import datetime, timedelta
import jwt
from functools import wraps

from flask import (
    Blueprint, jsonify, flash, g, redirect, 
    render_template, request, session, url_for,
    make_response
)

from flask import current_app as app

bp = Blueprint('login', __name__, url_prefix='/login')

@bp.route('/')
def login():
    auth = request.authorization

    if auth and auth.password == "password":
        token = jwt.encode({'user' : auth.username, 'exp': datetime.utcnow() + timedelta(hours = 6)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required:'})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') #http://127.0.0.1:5000/route?token=afjlkasjfl
        if not token:
            return jsonify({'message': 'Token is missing.'}), 403
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid.'}), 403

        return f(*args, **kwargs)
    return decorated
