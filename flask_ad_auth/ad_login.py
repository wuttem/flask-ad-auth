#!/usr/bin/python
# coding: utf8

import sqlite3

try:
    from urlparse import urlparse, urlunparse
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlparse, urlunparse, urlencode

import json
import logging
import base64
import datetime
import time
import requests
import functools
import importlib
import inspect
from collections import namedtuple

try:
    import redis
except Exception:
    redis = None

from flask import current_app, request, abort, redirect, make_response, g, flash
from flask import _app_ctx_stack as stack
from flask_login import LoginManager, login_user, current_user


logger = logging.getLogger(__name__)


RefreshToken = namedtuple("RefreshToken",
                          ["access_token", "refresh_token", "expires_on"])


def ad_group_required(ad_group):
    """
    This will ensure that only an user with the correct AD group
    may access the decorated view.
    """
    def decorater(func):
        @functools.wraps(func)
        def decorated_view(*args, **kwargs):
            if current_app.login_manager._login_disabled:
                return func(*args, **kwargs)
            elif not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            elif not current_user.is_in_group(ad_group):
                if current_app.config["AD_GROUP_FORBIDDEN_REDIRECT"]:
                    return redirect(current_app.config["AD_GROUP_FORBIDDEN_REDIRECT"])
                return abort(make_response("You dont have the necessary group to access this view", 403))
            return func(*args, **kwargs)
        return decorated_view
    return decorater


def ad_required(func):
    """
    This will ensure that only an user with the basic AD group
    may access the decorated view.
    """
    @functools.wraps(func)
    def decorated_view(*args, **kwargs):
        if current_app.login_manager._login_disabled:
            return func(*args, **kwargs)
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        elif current_app.config["AD_AUTH_GROUP"] and not current_user.is_in_default_group():
            if current_app.config["AD_GROUP_FORBIDDEN_REDIRECT"]:
                return redirect(current_app.config["AD_GROUP_FORBIDDEN_REDIRECT"])
            return abort(make_response("You dont have the necessary group to access this view", 403))
        return func(*args, **kwargs)
    return decorated_view


class User(object):
    def __init__(self, email, access_token, refresh_token, expires_on,
                 token_type, resource, scope, group_string=None, metadata=None):
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_on = int(expires_on)
        self.token_type = token_type
        self.resource = resource
        self.scope = scope
        self.metadata = {}
        self._group_names = None
        if metadata is not None:
            self.metadata.update(metadata)
        if group_string is None:
            self._group_ids = []
        else:
            self._group_ids = list(filter(bool, group_string.split(";")))
        self.ad_manager = None

    def set_ad_manager(self, manager):
        self.ad_manager = manager

    def store(self):
        if self.ad_manager is None:
            raise RuntimeError("no ad_manager set for this user instance")
        self.ad_manager.store_user(self)

    def add_metadata(self, metadata_dict):
        assert isinstance(metadata_dict, dict)
        self.metadata.update(metadata_dict)
        self.store()

    def get_metadata_field(self, name, default=None):
        return self.metadata.get(name, default)

    @property
    def group_string(self):
        return ";".join(self._group_ids)

    @property
    def is_authenticated(self):
        return True

    @property
    def groups(self):
        if self._group_names is None:
            all_groups = ADAuth.get_all_groups(self.access_token)
            name_lookup = dict((x["id"], x["name"]) for x in all_groups)
            new_group_names = []
            for g in self._group_ids:
                new_group_names.append(name_lookup.get(g, "MISSING"))
            self._group_names = new_group_names
        gs = zip(self._group_ids, self._group_names)
        return [{"id": g_id, "name": g_name} for g_id, g_name in gs]

    @property
    def is_expired(self):
        if (self.expires_on - 10) > time.time():
            return False
        return True

    def is_in_group(self, group):
        for g in self.groups:
            if g["id"] == group:
                return True
            if g["name"].lower() == group.lower():
                return True
        return False

    def is_in_default_group(self):
        return self.is_in_group(current_app.config["AD_AUTH_GROUP"])

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        False

    def get_id(self):
        return self.email

    @property
    def expires_in(self):
        return self.expires_on - time.time()

    def full_refresh(self):
        refresh_result = ADAuth.refresh_oauth_token(self.refresh_token)
        if refresh_result is None:
            return False
        self.access_token = refresh_result.access_token
        self.refresh_token = refresh_result.refresh_token
        self.expires_on = int(refresh_result.expires_on)
        self.refresh_groups()
        return True

    def refresh_groups(self):
        gs = ADAuth.get_user_groups(self.access_token)
        self._group_ids = gs
        self._group_names = None
        return True

    def get_groups_named(self):
        return self.groups

    def get_ad_object(self):
        return ADAuth.get_user_object(self.access_token)

    def to_dict(self):
        return {
            "email": self.email,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_on": self.expires_on,
            "token_type": self.token_type,
            "resource": self.resource,
            "scope": self.scope,
            "group_string": self.group_string,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            email=d["email"],
            access_token=d["access_token"],
            refresh_token=d["refresh_token"],
            expires_on=int(d["expires_on"]),
            token_type=d["token_type"],
            resource=d["resource"],
            scope=d["scope"],
            group_string=d["group_string"],
            metadata=d.get("metadata", None)
        )


class ADAuth(LoginManager):
    group_name_cache = {}
    group_name_cache_refresh = None
    group_name_cache_time = 3600

    def __init__(self, app=None, add_context_processor=True, user_baseclass=None):
        """
        Flask extension constructor.
        """
        super(ADAuth, self).__init__(
            app=app, add_context_processor=add_context_processor)
        self.connection_class = SQLiteDatabase
        self.connected = False
        self.on_login_callback = None
        if user_baseclass is not None:
            self.user_baseclass = user_baseclass
        else:
            self.user_baseclass = User

    def set_user_baseclass(self, user_baseclass):
        if self.connected:
            raise RuntimeError("User base class change after connecting")
        self.user_baseclass = user_baseclass

    def init_app(self, app, add_context_processor=True):
        """
        Flask extension init method. We add our variables and
        startup code. Then we just use the init method of the parent.
        """
        app.config.setdefault("AD_STORAGE", "sqlite")
        app.config.setdefault("AD_REDIS_HOST", "localhost")
        app.config.setdefault("AD_REDIS_PORT", "6379")
        app.config.setdefault("AD_REDIS_DB", 0)
        app.config.setdefault("AD_SQLITE_DB", "file::memory:?cache=shared")
        app.config.setdefault("AD_APP_ID", None)
        app.config.setdefault("AD_APP_KEY", None)
        app.config.setdefault("AD_REDIRECT_URI", None)
        app.config.setdefault("AD_DOMAIN_FOR_GROUPS", "smaxtec.com")
        app.config.setdefault("AD_AUTH_URL", 'https://login.microsoftonline.com/common/oauth2/authorize')
        app.config.setdefault("AD_TOKEN_URL", 'https://login.microsoftonline.com/common/oauth2/token')
        app.config.setdefault("AD_GRAPH_URL", 'https://graph.windows.net')
        app.config.setdefault("AD_CALLBACK_PATH", '/connect/get_token')
        app.config.setdefault("AD_LOGIN_REDIRECT", '/')
        app.config.setdefault("AD_GROUP_FORBIDDEN_REDIRECT", None)
        app.config.setdefault("AD_AUTH_GROUP", None)
        app.config.setdefault("AD_AUTH_USER_BASECLASS", None)

        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown_db)
        else:
            app.teardown_request(self.teardown_db)

        # Register Callback
        app.add_url_rule(app.config["AD_CALLBACK_PATH"], "oauth_callback",
                         self.oauth_callback)

        # Set Base Class
        if app.config["AD_AUTH_USER_BASECLASS"]:
            if inspect.isclass(app.config["AD_AUTH_USER_BASECLASS"]):
                self.user_baseclass = app.config["AD_AUTH_USER_BASECLASS"]
            else:
                mod, classname = app.config["AD_AUTH_USER_BASECLASS"].rsplit(".", 1)
                m = importlib.import_module(mod)
                c = getattr(m, classname)
                if not inspect.isclass(c):
                    raise ValueError("{} is not a valid class".format(app.config["AD_AUTH_USER_BASECLASS"]))
                self.user_baseclass = c

        # Set Storage
        if app.config["AD_STORAGE"] == "sqlite":
            self.setDatabaseClass(SQLiteDatabase)
        elif app.config["AD_STORAGE"] == "redis":
            self.setDatabaseClass(RedisDatabase)
        else:
            raise ValueError("unknown storage {}".format(app.config["AD_STORAGE"]))

        # Parent init call
        super(ADAuth, self).init_app(
            app=app, add_context_processor=add_context_processor)

        self.user_callback = self.load_user

    def setDatabaseClass(self, my_class):
        if self.connected:
            raise RuntimeError("Connection class change after connecting")
        self.connection_class = my_class

    def teardown_db(self, exception):
        """
        Close database connection.
        """
        ctx = stack.top
        self.connected = False
        if hasattr(ctx, 'adauth_db'):
            ctx.adauth_db.close()

    @property
    def db_connection(self):
        """
        Connection property. Use this to get the connection.
        It will create a reusable connection on the flask context.
        """
        ctx = stack.top
        if ctx is not None:
            if not hasattr(ctx, 'adauth_db'):
                ctx.adauth_db = self.connection_class(current_app.config,
                                                      user_baseclass=self.user_baseclass)
                ctx.adauth_db.connect()
                self.connected = True
            return ctx.adauth_db

    @property
    def sign_in_url(self):
        """
        URL you need to use to login with microsoft.
        """
        url_parts = list(urlparse(current_app.config["AD_AUTH_URL"]))
        auth_params = {
            'response_type': 'code',
            'redirect_uri': current_app.config["AD_REDIRECT_URI"],
            'client_id': current_app.config["AD_APP_ID"]
        }
        url_parts[4] = urlencode(auth_params)
        return urlunparse(url_parts)

    @classmethod
    def datetime_from_timestamp(cls, timestamp):
        """
        Convert unix timestamp to python datetime.
        """
        timestamp = float(timestamp)
        return datetime.datetime.utcfromtimestamp(timestamp)

    def get_user_token(self, code):
        """
        Receive OAuth Token with the code received.
        """
        token_params = {
            'grant_type': 'authorization_code',
            'redirect_uri': current_app.config["AD_REDIRECT_URI"],
            'client_id': current_app.config["AD_APP_ID"],
            'client_secret': current_app.config["AD_APP_KEY"],
            'code': code,
            'resource': current_app.config["AD_GRAPH_URL"]
        }
        res = requests.post(current_app.config["AD_TOKEN_URL"], data=token_params)
        token = res.json()
        # Decode User Info
        encoded_jwt = token["id_token"].split('.')[1]
        if len(encoded_jwt) % 4 == 2:
            encoded_jwt += '=='
        else:
            encoded_jwt += '='
        user_info = json.loads(base64.b64decode(encoded_jwt))
        # Return Important Fields
        email = user_info["upn"]
        access_token = token['access_token']
        refresh_token = token['refresh_token']
        expires_on = int(token['expires_on'])
        token_type = token['token_type']
        resource = token['resource']
        scope = token['scope']
        user = self.user_baseclass(email=email, access_token=access_token,
                                   refresh_token=refresh_token, expires_on=expires_on,
                                   token_type=token_type, resource=resource, scope=scope)
        user.set_ad_manager(self)
        return user

    @classmethod
    def refresh_oauth_token(cls, refresh_token):
        """
        Receive a new access token with the refresh token. This will also
        get a new refresh token which can be used for the next call.
        """
        refresh_params = {
            'grant_type': 'refresh_token',
            'redirect_uri': current_app.config["AD_REDIRECT_URI"],
            'client_id': current_app.config["AD_APP_ID"],
            'client_secret': current_app.config["AD_APP_KEY"],
            'refresh_token': refresh_token,
            'resource': current_app.config["AD_GRAPH_URL"]
        }
        r = requests.post(current_app.config["AD_TOKEN_URL"],
                          data=refresh_params).json()
        if "access_token" not in r or not r["access_token"]:
            logger.error("error refreshing user. result: {}".format(r))
            return None
        return RefreshToken(access_token=r["access_token"],
                            refresh_token=r["refresh_token"],
                            expires_on=r["expires_on"])

    @classmethod
    def get_user_object(cls, access_token):
        """
        Get the AD User Object.
        """
        headers = {
            "Authorization": "Bearer {}".format(access_token),
            'Accept' : 'application/json'
        }
        params = {
            "api-version": "1.6"
        }
        url = "{}/me".format(current_app.config["AD_GRAPH_URL"])
        r = requests.get(url, headers=headers, params=params)
        return r.json()

    @classmethod
    def load_all_groups_from_ad(cls, access_token):
        headers = {
            "Authorization": "Bearer {}".format(access_token),
            'Accept' : 'application/json'
        }
        params = {
            "api-version": "1.6"
        }
        url = "{}/{}/groups".format(current_app.config["AD_GRAPH_URL"],
                                    current_app.config["AD_DOMAIN_FOR_GROUPS"])
        r = requests.get(url, headers=headers, params=params)
        for g in r.json()["value"]:
            g_id = g["objectId"]
            g_name = g["displayName"]
            cls.group_name_cache[g_id] = g_name
        cls.group_name_cache_refresh = time.time()
        return cls.group_name_cache

    @classmethod
    def get_all_groups(cls, access_token):
        """
        Get a List of all groups in the organisation with their name.
        """
        if not cls.group_name_cache_refresh:
            g = cls.load_all_groups_from_ad(access_token)
        else:
            diff = time.time() - cls.group_name_cache_refresh
            if diff < cls.group_name_cache_time:
                g = cls.group_name_cache
            else:
                g = cls.load_all_groups_from_ad(access_token)
        return [{"id": key, "name":g[key]} for key in g]

    @classmethod
    def get_user_groups(cls, access_token):
        """
        Get a list with the id of all groups the user belongs to.
        """
        headers = {
            "Authorization": "Bearer {}".format(access_token),
            'Accept' : 'application/json'
        }
        params = {
            "api-version": "1.6"
        }
        body = {
            "securityEnabledOnly": False
        }
        url = "{}/me/getMemberGroups".format(current_app.config["AD_GRAPH_URL"])
        my_groups = requests.post(url, headers=headers, params=params, json=body).json()
        out = []
        for g in my_groups["value"]:
            out.append(g)
        return out

    def oauth_callback(self):
        code = request.args.get('code')
        if not code:
            logger.error("NO 'code' VALUE RECEIVED")
            return abort(400)
        user = self.get_user_token(code)
        user.refresh_groups()
        # Write to db
        user.set_ad_manager(self)
        self.store_user(user)
        login_user(user, remember=True) # Todo Remember me
        logger.warning("User %s logged in", user.email)
        if self.on_login_callback is not None:
            return self.on_login_callback(user)
        # Todo we should add an on login callback here
        # Or maybe redirect to next...
        flash("Logged in!", "success")
        return redirect(current_app.config["AD_LOGIN_REDIRECT"])

    def set_on_login_callback(self, callback):
        assert callable(callback)
        self.on_login_callback = callback

    def store_user(self, user):
        """
        Store user in database. This will insert or replace the user with
        given email.
        """
        return self.db_connection.store_user(user)

    def get_user(self, email):
        """
        Query User from db. Will return the user object or None.
        """
        u = self.db_connection.get_user(email)
        if u is not None:
            u.set_ad_manager(self)
        else:
            logger.warning("user not existing in database")
        return u

    def load_user(self, email):
        logger.debug("loading user %s", email)
        user = self.get_user(email)
        # User exists in db
        if user:
            # Still valid
            if not user.is_expired:
                g.user_id = user.email
                return user
            # Try to refresh with refresh token
            else:
                logger.warning("Refreshing user %s", email)
                if not user.full_refresh():
                    return None
                self.store_user(user)
                g.user_id = user.email
                return user
        logger.warning("User %s not in database", email)
        # We need a new authentication
        # maybe reload sign_in_url automatically
        return None


class SQLiteDatabase(object):
    def __init__(self, config, user_baseclass=None):
        self.config = config
        self.conn = None
        if user_baseclass is None:
            self.user_baseclass = User
        else:
            self.user_baseclass = user_baseclass

    def connect(self):
        """
        Connect to SQLite3 database. This will create a new user table if
        it doesnt exist.
        """
        conn = sqlite3.connect(self.config['AD_SQLITE_DB'])
        conn.execute("CREATE TABLE IF NOT EXISTS users ("
                        "email TEXT PRIMARY KEY, "
                        "refresh_token TEXT, "
                        "access_token TEXT, "
                        "expires_on INTEGER, "
                        "token_type TEXT, "
                        "resource TEXT, "
                        "scope TEXT,"
                        "groups TEXT,"
                        "metadata TEXT);")
        conn.commit()
        self.conn = conn
        return conn

    def close(self):
        if self.conn is not None:
            self.conn.close()

    def store_user(self, user):
        """
        Store user in database. This will insert or replace the user with
        given email.
        """
        c = self.conn.cursor()
        _metadata = json.dumps(user.metadata)
        c.execute("INSERT OR REPLACE INTO users (email, access_token, refresh_token, expires_on, "
                  "token_type, resource, scope, groups, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (user.email, user.access_token, user.refresh_token, user.expires_on,
                   user.token_type, user.resource, user.scope, user.group_string, _metadata))
        self.conn.commit()
        return user

    def get_user(self, email):
        """
        Get User from db. Will return the user object or None.
        """
        c = self.conn.cursor()
        c.execute("SELECT email, access_token, refresh_token, expires_on, "
                  "token_type, resource, scope, groups, metadata FROM users WHERE email=?", (email,))
        row = c.fetchone()
        if row:
            _metadata = json.loads(row[8])
            return self.user_baseclass(email=row[0], access_token=row[1], refresh_token=row[2],
                                       expires_on=int(row[3]), token_type=row[4], resource=row[5],
                                       scope=row[6], group_string=row[7], metadata=_metadata)
        return None


class RedisDatabase(object):
    def __init__(self, config, user_baseclass=None):
        self.config = config
        self.conn = None
        if user_baseclass is None:
            self.user_baseclass = User
        else:
            self.user_baseclass = user_baseclass

    def connect(self):
        """
        Connect to Redis.
        """
        conn = redis.StrictRedis(self.config["AD_REDIS_HOST"], self.config["AD_REDIS_PORT"],
                                 self.config["AD_REDIS_DB"])
        self.conn = conn
        return conn

    def close(self):
        if self.conn is not None:
            self.conn = None

    def store_user(self, user):
        """
        Store user in database. This will insert or replace the user with
        given email.
        """

        key = user.email
        value = json.dumps(user.to_dict())

        c = self.conn
        c.hset("ad_auth_users", key, value)
        return user

    def get_user(self, email):
        """
        Get User from db. Will return the user object or None.
        """

        c = self.conn
        raw = c.hget("ad_auth_users", email)
        if raw:
            d = json.loads(raw)
            return self.user_baseclass.from_dict(d)
        return None
