import functools
import os
from time import sleep

import splunklib.results as results
import splunklib.client as client

from flask_cors import cross_origin
from . import login

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_id', __name__, url_prefix='/get_id')

@bp.route('/', methods=['GET', 'POST'])
@login.token_required
@cross_origin()
def ids():
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

    # Define the search string
    from_date = "2019-06-20"
    to_date = "2019-10-19"
    identity = "21969062"
    exec_mode = {"exec_mode": "normal"}

    search_string = """
        search * is-ise cise_passed_authentications
        earliest = "{}" latest="{}" timeformat="%Y-%m-%d" "User-Name"
        | where like(UserName, "{}")
        | eval MAC=mvindex(split(Acct_Session_Id, "/"), 1)
        | table UserName MAC
    """.format(from_date, to_date, identity)

    job = service.jobs.create(search_string, **exec_mode)

    # Wait until search is completed
    while True:
        while not job.is_ready():
            pass

        if(job["isDone"]):
            break

        sleep(2)

    profiles = []
    reader = results.ResultsReader(job.results())
    for result in reader:
        if isinstance(result, dict):
            profiles.append({
                "username": result['UserName'],
                "mac": result['MAC']
            })

    return jsonify(profiles)
    