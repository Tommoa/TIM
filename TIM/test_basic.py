import pytest

from . import my_app
_app = my_app.create_app()

#from my_app import app as _app

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
        response = client.get("/test/")
        assert response.status_code == 200
