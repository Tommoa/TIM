import pytest

import json
import pytz
from datetime import datetime, timedelta

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

class TestScheduler:
    def test_scheduler(self, client):
        # Checks that the SPA polling has been scheduled and that 
        # it is scheduled to run at the right time

        print ('Testing that task has been scheduled')

        detected_job = False
        sched = TIM.poll_splunk_for_threats(_app)
        for job in sched.get_jobs():
            if ('detect_threats' in job.name):
                detected_job = True
                utc=pytz.UTC
                run_time = job.next_run_time.replace(tzinfo=None)
                assert (
                    run_time <= datetime.now() + 
                    timedelta(seconds = 80)
                )
        assert (detected_job)
