import os
import splunklib.results as results
import splunklib.client as client
from flask import Flask, jsonify
from flask_cors import CORS
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from .threat_intelligence import gen_complete_threat_query
from . import database
import tinydb
import yaml

def create_app(test_config=None):

    # Instaniate Flask class to use as app
    app = Flask(__name__, instance_relative_config=True)

    # Set Up CORS
    cors = CORS(app)
    app.config['CORS_HEADERS'] = 'Content-Type'

    # Load config
    if app.config["ENV"] == "development":
      app.config.from_object("config.DevelopmentConfig")
    if app.config["ENV"] == "production":
      app.config.from_object("prod_config.ProductionConfig")

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # register blueprints e.g. endpoints
    from . import get_id, get_mac
    from . import get_website_blacklist, test

    app.register_blueprint(get_id.bp)
    app.register_blueprint(test.bp)
    app.register_blueprint(get_mac.bp)
    app.register_blueprint(get_website_blacklist.bp)

    poll_splunk_for_threats(app)
    return app

def detect_threats(app, db, threat_query):
    print("Detecting_threats.")
    
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
    # stats limit

    # Generate necessary parameters for search and run search
    kwargs_search = {"exec_mode": "blocking"}
    job = service.jobs.create(threat_query, **kwargs_search)

    # Process results and write to database
    reader = results.ResultsReader(job.results())
    for result in reader:
        if isinstance(result, dict):
            if result['threat'] == "brute_force":
                for (threat, time, mac, username, num_attempts, num_failures,
                        num_successes) in zip(*list(result.values())):
                    brute_force_threats = {
                        "username": username,
                        "threat": threat,
                        "time": time,
                        "mac": mac,
                        "num_failures": num_failures,
                        "num_successes": num_successes,
                        "num_attempts": num_attempts
                }
                    db.brute_force_table.insert(brute_force_threats)
            elif result['threat'] == "multi_logins":
                for (threat, time, mac, unique_logins, username) in zip(
                        *list(result.values())):
                    multi_logins_threats = {
                        "username": username,
                        "threat": threat,
                        "time": time,
                        "mac": mac,
                        "unique_logins": unique_logins
                    }
                    db.multi_logins_table.insert(multi_logins_threats)


#@app.before_first_request
def poll_splunk_for_threats(app):
    db = database.db()
    polling_interval = app.config['POLLING_INTERVAL']
    with open(app.config['TI_CONFIG']) as f: # FileNotFoundError
        config = yaml.safe_load(f)
    try:
        complete_threat_query = gen_complete_threat_query(config)
        sched = BackgroundScheduler(daemon=True)
        sched.add_job(detect_threats, 'interval',
            [app, db, complete_threat_query], seconds=polling_interval)
        sched.start()
    except UserWarning as e: # comp none?
        print(repr(e))

    # Shut down the scheduler when exiting the app
    atexit.register(lambda: sched.shutdown(wait=False))
