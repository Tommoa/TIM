import pytest

import json

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

def login(client, usr, pwd):
    return client.post('/login/', data=dict(
        username=usr,
        password=pwd
    ), follow_redirects=True)

def logout(client):
    return client.get('/logout', follow_redirects=True)

class TestEndpoints:
    # Test unprotected endpoints
    def test_unprotected_endpoints(self, client):
        print ('Testing endpoint: "/test"')
        response = client.get("/test/")
        assert response.status_code == 200
    
    # Test protected endpoints
    def test_protected_endpoints_without_login(self, client):
        urls = ["/get_id/", "/get_alerts/", "/get_latest_alert/", "/get_mac/", "/login/"]
        for url in urls:
            print ("Testing endpoint without login: " + url)
            response = client.get(url)
            assert response.status_code == 401

    # Test login with correct and incorrect password
    def test_login_endpoint(self, client):
        rv = login(client, " ", _app.config['TIM_PASSWORD'])
        assert b'token' in rv.data

        rv = login(client, " ", _app.config['TIM_PASSWORD'] + "x")
        assert b'Could not verify' in rv.data

    def test_protected_endpoints_with_login(self, client):
        # not working
        urls = ["/get_id/", "/get_alerts/", "/get_latest_alert/", "/get_mac/"]
        for url in urls:

            token_reply = login(client, " ", _app.config['TIM_PASSWORD'])
            token = (json.loads(str(token_reply.data, 'utf-8'))['token'])

            response = client.post(url, data = dict(
                xaccesstoken=token
            ))

            print ("Testing endpoint with login: " + url)
            assert response.status_code == 200


    
