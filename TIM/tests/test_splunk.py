import pytest

import json
import splunklib.client as splunk_client
import splunklib.results as results

import TIM

_app = TIM.create_app(True)

# https://docs.pytest.org/en/latest/example/simple.html
# https://flask.palletsprojects.com/en/1.1.x/testing/
# http://boussejra.com/2018/08/01/testing-with-flask.html

@pytest.fixture
def client(app):
    # Get a test client for your Flask app
    return app.test_client()

@pytest.fixture
def app():
    """Yield your app with its context set up and ready"""

    # Set up: Establish an application context
    ctx = _app.app_context()
    ctx.push()
    yield _app

    # Tear down: run this after the tests are completed
    ctx.pop()

class TestSplunk:
    def test_splunk_access(self, client):
        # Checks that TIM can access splunk using the credentials in config
        # and complete an empty search
        HOST = _app.config['SPA_HOST']
        PORT = _app.config['SPA_PORT']
        USERNAME = _app.config['SPA_USERNAME']
        PASSWORD = _app.config['SPA_PASSWORD']
        service = splunk_client.connect(
            host=HOST,
            port=PORT,
            username=USERNAME,
            password=PASSWORD)
        
        kwargs_search = {"exec_mode": "blocking"}
        job = service.jobs.create("search *", **kwargs_search)
        
        assert (service)
