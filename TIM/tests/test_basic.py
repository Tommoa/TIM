import pytest

import TIM
_app = TIM.create_app(True)

# https://docs.pytest.org/en/latest/example/simple.html
# https://flask.palletsprojects.com/en/1.1.x/testing/
# http://boussejra.com/2018/08/01/testing-with-flask.html


@pytest.fixture
def client(app):
    """Get a test client for your Flask app"""
    return app.test_client()

@pytest.fixture
def app():
    """Yield your app with its context set up and ready"""

    with _app.app_context():
        yield _app


class TestLogin:
    def test_login_page(self, client):
        print ("Testing login page...")
        response = client.get("/test/")
        assert response.status_code == 200

