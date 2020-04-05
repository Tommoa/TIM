import functools
import os
from re import findall
from time import sleep
import splunklib.results as results
import splunklib.client as client

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_multi_logins', __name__, url_prefix='/get_multi_logins')

@bp.route('/')
def get_multi_logins():
    # Set up config
    HOST = app.config['HOST']
    PORT = app.config['PORT']
    USERNAME = app.config['USERNAME']
    PASSWORD = app.config['PASSWORD']

    service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD)

    # Define multi-login threat parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = "5m" #
    unique_logins_thresh = "0"

    # Generate other necessary parameters for search
    exec_mode = {"exec_mode": "normal"}
    # TODO: Delta will correctly fail if time_window Splunk SPL string is not in
    # valid format - add proper exception handling and checks.
    delta_t = int(findall(r'\d+', time_window)[0])

    search_string = """
        search * is-ise (cise_passed_authentications
        AND RadiusFlowType=Wireless802_1x)
        | sort 0 _time
        | bin _time span={}
        | stats dc(UserName) AS unique_logins, values(UserName) AS usernames
        BY _time EndPointMACAddress
        | streamstats time_window=5m min(_time) AS start,  max(_time) AS end,
        sum(unique_logins) AS logins BY EndPointMACAddress
        | eval _time = start, end = start + {}
        | where unique_logins >= {}
        | stats values(start) AS start_times, values(end) AS end_times,
        values(usernames) AS usernames, values(unique_logins) AS unique_logins
        BY EndPointMACAddress
    """.format(time_window, delta_t, unique_logins_thresh)

    job = service.jobs.create(search_string, **exec_mode)

    # Wait until search is completed
    # TODO: Properly handle pending searches blocking whole thread. Maybe
    # 'lib/concurrent/futures/'.
    while not job.is_ready() and not job["isDone"]:
        sleep(2)

    multi_login_dets = []
    reader = results.ResultsReader(job.results())
    
    for result in reader:
        if isinstance(result, dict):
            multi_login_dets.append({
                "mac": result['EndPointMACAddress'],
                "start_times": result['start_times'],
                "end_times": result['end_times'],
                "usernames": result['usernames'],
                "unique_logins": result['unique_logins']
            })

    return jsonify(multi_login_dets)
