import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from flask import Flask, jsonify
from flask_cors import CORS
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

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

    testScheduler()
    return app 

# Process Splunk Logs
def processLogs():
    print("Scheduler is alive!")

    # Call 3 functions here - one for each threat
    # Functions should be in the respective files




#@app.before_first_request
def testScheduler():
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(processLogs,'interval',seconds=5)
    sched.start()
 
    # Shut down the scheduler when exiting the app
    atexit.register(lambda: sched.shutdown(wait=False))
