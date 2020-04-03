import functools
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
import database


from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_brute_force', __name__, url_prefix='/get_brute_force')

@bp.route('/')
def get_brute_force():
    
    db = database.db()
    db.blacklist_table.insert({'id': 12345678, 'time': '09/02/20 12:30', 'message': '20 failed log in attempts'})
    print (db.blacklist_table.search(tinydb.where('id') == 12345678))
    
    return
    