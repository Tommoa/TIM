from .threat_intelligence import gen_statistics
from flask_cors import cross_origin
from . import login

from . import database

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_statistics', __name__, url_prefix='/get_statistics')

@bp.route('/')
@cross_origin()
@login.token_required
def get_statistics():
    # generate threat statistics using threat intelligence system
    stats = gen_statistics()

    return jsonify(stats)
