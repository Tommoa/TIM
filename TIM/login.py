import os
from time import sleep
from . import database
from datetime import datetime, timedelta
import jwt
from functools import wraps

from flask_cors import cross_origin 
 
from flask import (
    Blueprint, jsonify, flash, g, redirect, 
    render_template, request, session, url_for,
    make_response
)

from flask import current_app as app

bp = Blueprint('login', __name__, url_prefix='/login')

@bp.route('/')
@cross_origin() 
def login():
    auth = request.authorization

    if auth and auth.password == "Group1Password":
        token = jwt.encode({'user' : auth.username, 'exp': datetime.utcnow() + timedelta(hours = 6)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required:'})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing.'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid.'}), 401
        
        return f(*args, **kwargs)
    return decorated