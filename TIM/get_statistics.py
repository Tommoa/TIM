from flask import Blueprint, jsonify

from flask_cors import cross_origin

from . import login
from .threat_intelligence import gen_statistics


from flask import current_app as app

bp = Blueprint('get_statistics', __name__, url_prefix='/get_statistics')

@bp.route('/')
@cross_origin()
@login.token_required
def get_statistics():
    # generate threat statistics using threat intelligence system
    stats = gen_statistics()

    return jsonify(stats)
