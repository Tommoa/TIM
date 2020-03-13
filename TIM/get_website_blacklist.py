import functools
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from . import database
from . import login
from flask_cors import cross_origin

from flask import (
    Blueprint, jsonify, flash, g, redirect, render_template, request, session, url_for
)

from flask import current_app as app

bp = Blueprint('get_website_blacklist', __name__, url_prefix='/get_website_blacklist')

@bp.route('/')
@cross_origin()
@login.token_required
def get_website_blacklist():
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

    search_time = '-3mon'
    exec_mode = {"exec_mode": "normal"}

    # Add in time ranges later
    # Need to connect to IDs later
    # | lookup otherlog | ip as src_ip OUTPUT id
    # etc.
    search_string = '''
    * "Built inbound * connection" earliest={}
	| rex "for\s.*?:(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	| rex "to internet:(?<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	| search
	    [| inputlookup myblacklist_lookup
	    | rename _key as dest_ip
	    | fields dest_ip]
	| table _time, src_ip, dest_ip
    '''.format(search_time)

    job = service.jobs.create(search_string, **exec_mode)

    # Wait until search is completed
    while True:
        while not job.is_ready():
            pass
        if(job["isDone"]):
            break
        sleep(2)
