import hashlib
from base import TestBase


class TestRoot(TestBase):
    """
    Expand this to test the api you have created.

    """

    def create_user(self, email='admin@test.com', password='pass'):
        self.app.db.user.delete_one({'email': email})
        self.app.db.user.insert_one({
            'email': email,
            'password': hashlib.sha1(password).hexdigest()
        })
        return email, password

    def generate_token(self, email='admin@test.com', password='pass'):
        self.create_user(email, password)
        resp = self.app.post_json('/login/', {'email': email, 'password': password})
        assert resp.status_int == 200
        return resp.json['token']

    def test_index(self):
        resp = self.app.get('/')
        assert resp.status_int == 200
        assert 'Welcome to Crunch.' in resp

    def test_login(self):
        email, password = self.create_user()
        resp = self.app.post_json('/login/', {'email': email, 'password': password})
        assert resp.status_int == 200

    def test_get_users_without_auth_should_raise_403(self):
        resp = self.app.get('/users/')
        assert resp.status_int == 403

    def test_get_users_with_auth_should_return_200(self):
        user_token = self.generate_token()

        resp = self.app.get('/users/', headers={'Authorization': user_token})
        assert resp.status_int == 200

    def test_get_distances_without_auth_should_raise_403(self):
        resp = self.app.get('/distances/')
        assert resp.status_int == 403

    def test_get_distances_with_auth_should_return_200(self):
        user_token = self.generate_token()

        resp = self.app.get('/distances/', headers={'Authorization': user_token})
        assert resp.status_int == 200
