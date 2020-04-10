import functools
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from . import database

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('test', __name__, url_prefix='/test')

@bp.route('/')
def test_endpoint():
    return "Testing endpoint is working!"
