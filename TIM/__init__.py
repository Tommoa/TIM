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
    from . import get_website_blacklist, get_brute_force, get_multi_logins, test

    app.register_blueprint(get_id.bp)
    app.register_blueprint(test.bp)
    app.register_blueprint(get_mac.bp)
    app.register_blueprint(get_website_blacklist.bp)
    app.register_blueprint(get_brute_force.bp)
    app.register_blueprint(get_multi_logins.bp)

    poll_splunk_for_threats()
    return app

def detect_threats(db, complete_threat_query):
    print("Detecting_threats")
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

    # Generate necessary parameters for search
    kwargs_blockingsearch = {"exec_mode": "blocking"}
    # Run a blocking search
    job = service.jobs.create(search_query, **kwargs_blockingsearch)

    reader = results.ResultsReader(job.results())
    for result in reader:
        if isinstance(result, dict):
            if result['threat'] == "brute_force":
                brute_force_threats = {
                    "username": result['username'],
                    "threat": result['threat'],
                    "time": result['time'],
                    "mac": result['mac'],
                    "num_failures": result['num_failures'],
                    "num_successes": result['num_successes'],
                    "num_attempts": result['num_attempts']
                }
                db.brute_force_table.insert(brute_force_threats)
            elif result['threat'] == "multi_logins":
                multi_logins_threats = {
                    "username": result['username'],
                    "threat": result['threat'],
                    "time": result['time'],
                    "mac": result['mac'],
                    "unique_logins": result['unique_logins']
                }
                db.multi_logins_table.insert(multi_logins_threats)


#@app.before_first_request
def poll_splunk_for_threats():
    db = database.db()
    polling_interval = app.config['POLLING_INTERVAL']
	with open(app.config['TI_CONFIG']) as f:
		config = yaml.safe_load(f)
    try:
        complete_threat_query = gen_complete_threat_query(config)
        sched = BackgroundScheduler(daemon=True)
        sched.add_job(detect_threats(db, complete_threat_query), 'interval',
            seconds=polling_interval)
        sched.start()
    except UserWarning as e:
        print(repr(e))

    # Shut down the scheduler when exiting the app
    atexit.register(lambda: sched.shutdown(wait=False))
