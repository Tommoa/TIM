import functools
import os
from re import findall
import splunklib.results as results
import splunklib.client as client
from time import sleep


from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_brute_force', __name__, url_prefix='/get_brute_force')

@bp.route('/')
def get_brute_force():
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

    # Define brute force parameters
    # TODO: Create config file to define threat identification parameters.
    time_window = "5m" 
    num_attempts_thresh = "3"
    num_failures_thresh = "3"

    # Generate other necessary parameters for search
    exec_mode = {"exec_mode": "normal"}
    # Get number representing window width from time_window spl arg 
    # TODO: Delta will correctly fail if time_window Splunk SPL string is not in
    # valid format - add proper exception handling and checks.
    delta_t = int(findall(r'\d+', time_window)[0])

    search_string = """
        search * is-ise (cise_passed_authentications
        OR (CISE_Failed_Attempts AND "FailureReason=24408"))
        | sort 0 _time
        | bin _time span={}
        | stats count(eval(searchmatch("CISE_Failed_Attempts")))
        AS num_failures count(eval(searchmatch("cise_passed_authentications")))
        AS num_successes, values(EndPointMACAddress) as macs BY _time UserName
        | streamstats time_window=5m min(_time) AS start,  max(_time) AS end,
        sum(num_failures) AS num_failures, sum(num_successes) AS num_sucesses
        BY UserName
        | eval _time = start, end = start + {}
        | eval num_attempts = num_sucesses + num_failures
        | where num_attempts >= {} AND num_successes == 0 AND num_failures >= {}
        | stats values(start) as start_times, values(end) as end_times,
        values(macs) as macs, values(num_failures) as num_failures,
        values(num_successes) as num_successes,
        values(num_attempts) as num_attempts by UserName
    """.format(time_window, delta_t, num_attempts_thresh, num_failures_thresh)

    job = service.jobs.create(search_string, **exec_mode)

    # Wait until search is completed
    # TODO: Properly handle pending searches blocking whole thread. Maybe
    # 'lib/concurrent/futures/'.
    while not job.is_ready() and not job["isDone"]:
        sleep(2)

    brute_force_dets = []
    reader = results.ResultsReader(job.results())

    for result in reader:
        if isinstance(result, dict):
            brute_force_dets.append({
                "username": result['UserName'],
                "start_times": result['start_times'],
                "end_times": result['end_times'],
                "macs": result['macs'],
                "num_failures": result['num_failures'],
                "num_successes": result['num_successes'],
                "num_attempts": result['num_attempts']
            })

    return jsonify(brute_force_dets)
