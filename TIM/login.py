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

@bp.route('/', methods = ['POST', 'GET'])
@cross_origin()
def login():
    
    # Post request with data fields
    if request.method == 'POST':
        username = request.values.get('username')
        password = request.values.get('password')
        
        if password and password == app.config['TIM_PASSWORD']:
            token = jwt.encode({'user':username, 'exp':datetime.utcnow() + timedelta(hours = 6)}, app.config['SPA_SECRET_KEY'], algorithm='HS256')
            return jsonify({'token' : token.decode('UTF-8')})

<<<<<<< HEAD
    # GET request basic authentication
    else:
        auth = request.authorization
        if auth and auth.password == app.config['TIM_PASSWORD']:
            token = jwt.encode({'user':auth.username, 'exp': datetime.utcnow() + timedelta(hours = 6)}, app.config['SPA_SECRET_KEY'], algorithm='HS256')
            return jsonify({'token' : token.decode('UTF-8')})
=======
    if auth and auth.password == "Group1Password":
        token = jwt.encode({'user' : auth.username, 'exp': datetime.utcnow() + timedelta(hours = 6)}, app.config['SPA_SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
>>>>>>> 13d6dbd... Add 'SPA_' prefix to all env variables
    
    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required:'})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if request.method == 'POST':
            if 'x-access-token' in request.values:
                token = request.values.get('x-access-token')

        if request.method == 'GET':
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing.'}), 401

        try:
            data = jwt.decode(token, app.config['SPA_SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid.'}), 401
        
        return f(*args, **kwargs)
    return decorated
