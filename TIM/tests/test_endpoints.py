import pytest

from flask import url_for
from base64 import b64encode, b64decode


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

def login(client, username1, password1):
    # DOES NOT WORK
    encoded = b64encode(b"user:Group1Password")
    encoded = b"Basic " + encoded
    print (str(encoded))
    encoded_hard = "Basic IDpHcm91cDFQYXNzd29yZA=="
    return client.get('/login', query_string = {"Authorization": encoded_hard}, follow_redirects=True)

def logout(client):
    return client.get('/logout', follow_redirects=True)


class Test:
    # Test unprotected endpoints
    def test_unprotected_endpoints(self, client):
        print ('Testing endpoint: "/test"')
        response = client.get("/test/")
        assert response.status_code == 200
    
    # Test protected endpoints
    def test_protected_endpoints(self, client):
        urls = ["/get_id/", "/get_alerts/", "/get_latest_alert/", "/get_mac/", "/login/"]
        for url in urls:
            print ("Testing endpoint:" + url)
            response = client.get(url)
            assert response.status_code == 401

    # DOES NOT WORK
    def test_login_endpoint(self, client):
        rv = login(client, "", "Group1Password")
        print (rv.data)
        assert b'token' in rv.data
    
