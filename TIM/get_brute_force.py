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
    return "Brute Force"