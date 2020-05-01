import os
from time import sleep
from . import database
from datetime import datetime


from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_locations', __name__, url_prefix='/get_locations')

@bp.route('/')
def get_locations():
    # Retrieve alerts
    db = database.db()
    alerts = [doc for table_name in db.db.tables() for doc in db.db.table(
                table_name).all() if table_name != 'default']
    db.db.close()

    response = "No locations found."
    
    # Retrieve threat locations
    num_locations = 5
    alerts.sort(key=lambda alert: alert["time"], reverse=True)
    locations = [alert['location'] for alert in alerts if
                alert['location'] != {"lat": None, "lon": None}]
    if not len(locations) == 0:
        response = locations[0: num_locations]

    return jsonify(response)
