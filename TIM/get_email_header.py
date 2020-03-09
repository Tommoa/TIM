import functools
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_email_header', __name__, url_prefix='/get_email_header')

@bp.route('/')
def get_email_header():
    return "Email Header"