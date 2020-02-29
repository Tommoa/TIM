import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from flask import Flask, jsonify

def create_app(test_config=None):
    
    # Instaniate Flask class to use as app
    app = Flask(__name__, instance_relative_config=True)

    # Load config
    if app.config["ENV"] == "development":
      app.config.from_object("config.DevelopmentConfig")

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # register blueprints e.g. endpoints
    from . import get_id
    app.register_blueprint(get_id.bp)

    return app
