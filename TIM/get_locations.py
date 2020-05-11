from flask_cors import cross_origin
from . import login

from . import database

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_locations', __name__, url_prefix='/get_locations')

@bp.route('/')
@cross_origin()
@login.token_required
def get_locations():
    # Retrieve alerts
    db = database.db()
    alerts = [doc for table_name in db.db.tables() for doc in db.db.table(
                table_name).all() if table_name != 'default']
    db.db.close()

    response = []

    # Retrieve threat locations
    num_locations = 5
    alerts.sort(key=lambda alert: alert["time"], reverse=True)
    locations = [alert['location'] for alert in alerts if
                alert['location'] != {"lat": None, "lon": None}]
    if not len(locations) == 0:
        response = locations[0: num_locations]

    return jsonify(response)
