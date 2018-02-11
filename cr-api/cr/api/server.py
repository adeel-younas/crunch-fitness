import os
import sys
import json
import hashlib
import random
import math

from functools import wraps
from itertools import combinations

import cherrypy
import numpy as np

from cherrypy import request
from cr.db.store import global_settings as settings, connect, pymongo

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNICODE_ASCII_CHARACTER_SET = ('abcdefghijklmnopqrstuvwxyz'
                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                               '0123456789')

HTML_TEMPLATES = {
    'logged_in': """
        <div style="clear:both;">
            <h4>Welcome %(email)s</h4>
        </div>
        <div style="clear:both;">
            <a href="/users/">Users</a> | <a href="/distances/">Distances</a> | 
            <a href="/logout/">Logout</a>
        </div>
    """,
    'login_form': """
        <h4>Login</h4>
        <form method="post">
            Username: <input type="text" name="email" /> <br/><br/>
            Password: <input type="password" name="password" /> <br/><br/>
            <input type="submit" value="submit" />
        </form>
    """
}


def validate(regex, value):
    import re
    return re.match(regex, value)


def validate_email(value):
    regex = r'[^@]+@[^@]+\.[^@]+'
    return validate(regex, value)


def validate_lat(value):
    regex = r'^(\+|-)?(?:90(?:(?:\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,6})?))$'
    return validate(regex, value)


def validate_lon(value):
    regex = r'^(\+|-)?(?:180(?:(?:\.0{1,6})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,6})?))$'
    return validate(regex, value)


def login_required():
    def decorator(func):
        @wraps(func)
        def wrapper(_self, *args, **kwargs):
            token = cherrypy.session.get('token')
            if not token:
                try:
                    token = cherrypy.request.headers['Authorization']
                except KeyError:
                    pass
                else:
                    if not _self.is_valid_user_token(token):
                        cherrypy.response.headers['Content-Type'] = 'application/json'
                        return jsonify_response(403, 'Invalid Token')
            if not token:
                if 'text/html' in request.headers.get('Accept'):
                    raise cherrypy.HTTPRedirect('/login/')

                return jsonify_response(403, 'login required')
            request.token = token
            return func(_self, *args, **kwargs)

        return wrapper

    return decorator


def jsonify_response(status, data):
    cherrypy.response.headers['Content-Type'] = 'application/json'
    cherrypy.response.status = status

    if isinstance(data, (list, dict, tuple)):
        data = json.dumps(data)
    else:
        data = json.dumps({"message": data})
    return data


class Root(object):

    def __init__(self, settings):
        self.db = connect(settings)

    def create_debug_user(self):
        try:
            self.db.user.create_index("email", unique=True)
        except pymongo.errors.DuplicateKeyError:
            pass

        # create token collection to store
        try:
            self.db.create_collection("token")
        except pymongo.errors.CollectionInvalid:
            pass
        else:
            self.db.token.create_index("token", unique=True)

        try:
            self.db.user.delete_one({'email': "admin"})

            self.db.user.insert_one({
                "email": "admin@fit.com",
                "password": hashlib.sha1("pass").hexdigest(),
                "lat": "25.555555",
                "lon": "55.555555"
            })
        except pymongo.errors.DuplicateKeyError:
            pass

    @staticmethod
    def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
        rand = random.SystemRandom()
        return ''.join(rand.choice(chars) for _ in range(length))

    def generate_and_store_user_token(self, user_id):
        token = Root.generate_token()
        self.db.token.insert_one({'token': token, 'user_id': user_id})
        return 'Token %s' % token

    def is_valid_user_token(self, token):
        try:
            _, token = token.split(' ')
        except ValueError:
            pass
        if not token:
            return False

        return self.db.token.find_one({'token': token})

    def delete_user_token(self, token):
        try:
            _, token = ' '.split(token)
        except ValueError:
            pass

        self.db.token.delete_one({'token': token})
        return

    def index(self):
        return 'Welcome to Crunch.  Please <a href="/login">login</a>.'

    index.exposed = True

    @login_required()
    def users(self):
        """
        for GET: update this to return a json stream defining a listing of the users
        for POST: should add a new user to the users collection, with validation

        Only logged-in users should be able to connect.  If not logged in, should return the
        appropriate HTTP response.  Password information should not be revealed.

        note: Always return the appropriate response for the action requested.
        """
        if cherrypy.request.method == "POST":
            if request.headers.get('Content-Type') == 'application/json':
                raw_data = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
                post_data = json.loads(raw_data)
            else:
                post_data = cherrypy.request.body.params
            if not post_data:
                return jsonify_response(400, 'missing post data')

            errors = {}
            creation_data = {}

            email = post_data.get('email')
            if email and validate_email(email):
                creation_data['email'] = email
            else:
                errors['email'] = 'Invalid/Missing email'

            password = post_data.get('password')
            if password:
                creation_data['password'] = hashlib.sha1(password).hexdigest()
            else:
                errors['password'] = 'Required'

            lat = post_data.get('lat')
            if lat and validate_lat(lat):
                creation_data['lat'] = lat
            else:
                errors['lat'] = 'Invalid/Missing lat'

            lon = post_data.get('lon')
            if lon and validate_lon(lon):
                creation_data['lon'] = lon
            else:
                errors['lon'] = 'Invalid/Missing lon'

            if errors:
                return jsonify_response(400, errors)

            try:
                self.db.user.insert_one(creation_data)
            except pymongo.errors.DuplicateKeyError:
                return jsonify_response(400, 'User already exist')

            creation_data.pop('_id')
            creation_data.pop('password')
            return jsonify_response(201, creation_data)

        return jsonify_response(200, {
            'users': [{
                'email': u['email'],
                'lat': u.get('lat'),
                'lon': u.get('lon'),
            } for u in self.db.user.find()]})

    users._cp_config = {'response.stream': True}
    users.exposed = True

    @cherrypy.tools.accept(media='application/json')
    def login(self, **kwargs):
        """
        a GET to this endpoint should provide the user login/logout capabilities

        a POST to this endpoint with credentials should set up persistence tokens for the user,
        allowing them to access other pages.

        hint: this is how the admin's password was generated:
              import hashlib; hashlib.sha1('123456').hexdigest()
        """
        session_user = cherrypy.session.get('user_id')

        if session_user:
            return HTML_TEMPLATES['logged_in'] % {
                "email": cherrypy.session.get('email')
            }
        if cherrypy.request.method == "POST":
            if request.headers.get('Content-Type') == 'application/json':
                raw_data = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
                post_data = json.loads(raw_data)
            else:
                post_data = cherrypy.request.body.params
            try:
                email = post_data['email']
                password = post_data['password']
            except KeyError:
                if 'text/html' in request.headers.get('Accept'):
                    return HTML_TEMPLATES['login_form'] + """
                        <span style="background:red; clear:both;"> email and password required. </span>
                    """
                return jsonify_response(400, 'email and password required')

            password = hashlib.sha1(password).hexdigest()

            user = self.db.user.find_one({'email': email,
                                          'password': password})

            if not user:
                if 'text/html' in request.headers.get('Accept'):
                    return HTML_TEMPLATES['login_form'] + """
                        <span style="background:red; clear:both;"> Invalid credentials</span>
                    """
                return jsonify_response(400, 'Invalid credentials')

            token = self.generate_and_store_user_token(user['_id'])

            if 'text/html' not in request.headers.get('Accept'):
                return jsonify_response(200, {'token': token})

            cherrypy.session['user_id'] = user['_id']
            cherrypy.session['email'] = user['email']
            cherrypy.session['token'] = token
            cherrypy.session.save()

            return HTML_TEMPLATES['logged_in'] % {
                "email": email
            }

        if cherrypy.request.method == "GET":
            return HTML_TEMPLATES['login_form']

    login.exposed = True

    @login_required()
    def logout(self):
        """
        Should log the user out, rendering them incapable of accessing the users endpoint, and it
        should redirect the user to the login page.
        """
        cherrypy.session.regenerate()
        self.delete_user_token(request.token)
        if 'text/html' in request.headers.get('Accept'):
            raise cherrypy.InternalRedirect('/login/')

        cherrypy.response.status = 202
        return

    logout.exposed = True

    @classmethod
    def distance_betwen_coordinates(cls, lat1, lon1, lat2, lon2):
        radius_earth = 6373.0
        lat1 = math.radians(float(lat1))
        lon1 = math.radians(float(lon1))
        lat2 = math.radians(float(lat2))
        lon2 = math.radians(float(lon2))

        dlon = lon2 - lon1
        dlat = lat2 - lat1

        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        distance = radius_earth * c

        return distance

    @login_required()
    def distances(self):
        """
        Each user has a lat/lon associated with them.  Using only numpy, determine the distance
        between each user pair, and provide the min/max/average/std as a json response.
        This should be GET only.

        Don't code, but explain how would you scale this to 1,000,000 users, considering users
        changing position every few minutes?

        Purposed Improvements:

        - Processing the desired data when user is created/updated will make API to respond faster.
        - Storing information like avg, min, max after first calculation and then recalculating on update can save a lot
            of iterations, e.g, Sum of distances can be stored as (SUM, NUM_OF_RECORDS) and on update/creation of user average can
            be update as (SUM + NEW_DISTANCE) / (NUM_OF_RECORDS + 1) .
        - Caching can help to prevent calculating twice


        As I am not much experienced with numpy, will also explore some options there if there are any mathematical
            formulae to solve these kind of problems.
        """
        user_coordinates = []

        for user in self.db.user.find():
            if user.get('lat') and user.get('lon'):
                user_coordinates.append([user.get('lat'), user.get('lon')])
        user_coordinates_combinations = combinations(user_coordinates, 2)

        distances = []
        for _, combination in enumerate(user_coordinates_combinations):
            distances.append(self.distance_betwen_coordinates(combination[0][0],
                                                              combination[0][1],
                                                              combination[1][0],
                                                              combination[1][1]))

        if distances:
            return jsonify_response(200, {
                'min': np.min(distances),
                'max': np.max(distances),
                'std': np.std(distances),
                'avg': np.average(distances)
            })

        return jsonify_response(200, {})

    distances.exposed = True


def run(file_path=None, debug=False):
    if not file_path:
        file_path = sys.argv[1]
    settings.update(json.load(file(file_path)))

    config = {
        '/': {
            'tools.sessions.on': True,
            'engine.autoreload.on': True
        }
    }
    app = Root(settings)

    if debug:
        app.create_debug_user()

    cherrypy.quickstart(app, "/", config)


if __name__ == '__main__':
    run(os.path.join(BASE_DIR, '..', '..', 'settings.json'), debug=True)
