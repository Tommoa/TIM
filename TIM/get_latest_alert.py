import os
from time import sleep
from datetime import datetime
from . import login, database
from .threat_intelligence import (
    gen_brute_force_desc,
    gen_multi_logins_desc,
    gen_website_blacklist_desc)
from flask_cors import cross_origin

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_latest_alert', __name__, url_prefix='/get_latest_alert')

@bp.route('/', methods = ['GET', 'POST'])
@cross_origin()
@login.token_required
def get_latest_alert():
    # Retrieve alerts
    db = database.db()
    alerts = [doc for table_name in db.db.tables() for doc in db.db.table(
                table_name).all() if table_name != 'default']
    db.db.close()

    # Check if any alerts are present
    if len(alerts) == 0:
        response = "No alerts found."
        return response

    # Get latest alert
    alerts.sort(key=lambda alert: alert["time"], reverse=True)
    latest_alert = alerts[0]

    # Prepare response
    timestamp = int(latest_alert['time'])
    dt = datetime.fromtimestamp(timestamp)
    timestamp = dt.strftime("%d %B %Y %I:%M %p")
    desc_func = {
        "brute_force": gen_brute_force_desc,
        "multi_logins": gen_multi_logins_desc,
        "website_blacklist": gen_website_blacklist_desc,
    }
    description = desc_func[latest_alert['threat']](latest_alert)

    response = [{ "user" : latest_alert['username'],
                  "alert": description,
                  "timestamp": timestamp,
                  "threat level": latest_alert['threat_level']
                  }]

    return jsonify(response)
