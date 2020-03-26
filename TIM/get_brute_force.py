import functools
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client


from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_brute_force', __name__, url_prefix='/get_brute_force')

@bp.route('/')
def get_brute_force():

    # How to open a table and insert a row.
    from . import database
    db = database.db()
    db.blacklist_table.insert({'id': 12345678, 'time': '09/02/20 12:30', 'message': '20 failed log in attempts'})


    return "Brute Force"
