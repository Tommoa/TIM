import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from flask import Flask, jsonify
from flask_cors import CORS

def create_app(test_config=None):
    
    # Instaniate Flask class to use as app
    app = Flask(__name__, instance_relative_config=True)

    # Set Up CORS
    cors = CORS(app)
    app.config['CORS_HEADERS'] = 'Content-Type'

    # Load config
    if app.config["ENV"] == "development":
      app.config.from_object("config.DevelopmentConfig")

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # register blueprints e.g. endpoints
    from . import get_id, get_mac
    from . import get_email_header, get_website_blacklist, get_brute_force
    app.register_blueprint(get_id.bp)
    app.register_blueprint(get_mac.bp)
    app.register_blueprint(get_website_blacklist.bp)
    app.register_blueprint(get_brute_force.bp)
    app.register_blueprint(get_email_header.bp)

    return app
