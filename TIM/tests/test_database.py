import json
import pytest

import TIM

_app = TIM.create_app(True)

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

def login(client, usr, pwd):
    return client.post('/login/', data=dict(
        username=usr,
        password=pwd
    ), follow_redirects=True)

class TestEndpoints:
    # Test unprotected endpoints
    def test_unprotected_endpoints(self, client):
        print ('Testing endpoint: "/test"')
        response = client.get("/test/")
        assert response.status_code == 200
