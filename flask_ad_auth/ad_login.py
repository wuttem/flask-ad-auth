#!/usr/bin/python
# coding: utf8

import sqlite3

try:
    from urlparse import urlparse, urlunparse
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlparse, urlunparse, urlencode

import jwt
import json
import logging
import base64
import datetime
import time
import requests
import functools
import importlib
import inspect
import msal

from collections import namedtuple

try:
    import redis
except Exception:
    redis = None

from flask import current_app, request, abort, redirect, make_response, g, flash, url_for
from flask_login import LoginManager, login_user, current_user


BASE_AUTHORITY = "https://login.microsoftonline.com/"
DEFAULT_SCOPE = [ "https://graph.microsoft.com/.default" ]
BASE_ENDPOINT = "https://graph.microsoft.com/v1.0"


GROUP_NAME_CACHE = {}
GROUP_NAME_CACHE_REFRESH = None
GROUP_NAME_CACHE_TIME = 3600


logger = logging.getLogger(__name__)


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
                 token_type, scope, group_string=None, metadata=None):
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_on = int(expires_on)
        self.token_type = token_type
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
        self._info = None

    def set_ad_manager(self, manager):
        self.ad_manager = manager

    def store(self):
        self.adm.store_user(self)

    @property
    def adm(self):
        if self.ad_manager is None:
            raise RuntimeError("no ad_manager set for this user instance")
        return self.ad_manager

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
            all_groups = self.get_all_groups()
            name_lookup = dict((x["id"], x["name"]) for x in all_groups)
            new_group_names = []
            for g in self._group_ids:
                new_group_names.append(name_lookup.get(g, "MISSING"))
            self._group_names = new_group_names
        gs = zip(self._group_ids, self._group_names)
        return [{"id": g_id, "name": g_name} for g_id, g_name in gs]

    @property
    def info(self):
        if self._info is None:
            self._info = self.get_ad_object()
        return self._info

    @property
    def is_expired(self):
        if (self.expires_on - 30) > time.time():
            return False
        return True

    def is_in_group(self, group):
        if group in self._group_ids:
            return True
        return False
        # for g in self.groups:
        #     if g["id"] == group:
        #         return True
        #     if g["name"].lower() == group.lower():
        #         return True
        # return False

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

    def get_access_token(self):
        if self.is_expired:
            self.token_refresh()
        return self.access_token

    def get_requests_session(self):
        s = requests.Session()
        s.headers.update({"Authorization": "Bearer {}".format(self.get_access_token()),
                          'Accept' : 'application/json'})
        return s

    def build_graph_url(self, path):
        base = BASE_ENDPOINT
        if current_app:
            base = current_app.config["AD_GRAPH_URL"]
        if path.startswith("/"):
            return "{}{}".format(base, path)
        return "{}/{}".format(base, path)

    def token_refresh(self):
        tokens = self.adm.get_token_silent(self)
        if not tokens:
            return False

        self.access_token = tokens["access_token"]
        self.token_type = tokens["token_type"]
        self.expires_on = time.time() + tokens["expires_in"]
        return True

    def full_refresh(self):
        res = self.token_refresh()
        if not res:
            return res

        self.refresh_groups()
        return True

    def refresh_groups(self):
        gs = self.get_user_groups()
        self._group_ids = gs
        self._group_names = None
        return True

    def get_user_groups(self):
        """
        Get a list with the id of all groups the user belongs to.
        """
        body = {
            "securityEnabledOnly": False
        }
        url = self.build_graph_url("/me/getMemberGroups")
        with self.get_requests_session() as s:
            my_groups = s.post(url, json=body).json()
        out = []
        for g in my_groups["value"]:
            out.append(g)
        return out

    def get_user_object(self):
        """
        Get the AD User Object.
        """
        url = self.build_graph_url("/me")
        with self.get_requests_session() as s:
            return s.get(url).json()

    def load_all_groups_from_ad(self):
        """
        Loading all groups with names
        """
        global GROUP_NAME_CACHE, GROUP_NAME_CACHE_REFRESH
        url = self.build_graph_url("/groups")
        with self.get_requests_session() as s:
            res = s.get(url).json()
        if "error" in res:
            print(res["error"])
            raise RuntimeError("Not able to get groups from AD")

        for g in res["value"]:
            g_id = g["objectId"]
            g_name = g["displayName"]
            GROUP_NAME_CACHE[g_id] = g_name
        GROUP_NAME_CACHE_REFRESH = time.time()
        return GROUP_NAME_CACHE

    def get_all_groups(self):
        """
        Get a List of all groups in the organisation with their name.
        """
        if not GROUP_NAME_CACHE_REFRESH:
            g = self.load_all_groups_from_ad()
        else:
            diff = time.time() - GROUP_NAME_CACHE_REFRESH
            if diff < GROUP_NAME_CACHE_TIME:
                g = GROUP_NAME_CACHE
            else:
                g = self.load_all_groups_from_ad()
        return [{"id": key, "name":g[key]} for key in g]

    def get_groups_named(self):
        return self.groups

    def get_ad_object(self):
        return self.get_user_object()

    def to_dict(self):
        return {
            "email": self.email,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_on": self.expires_on,
            "token_type": self.token_type,
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
        self.connection_class = SQLiteDatabase
        self.on_login_callback = None
        if user_baseclass is not None:
            self.user_baseclass = user_baseclass
        else:
            self.user_baseclass = User
        super(ADAuth, self).__init__(
            app=app, add_context_processor=add_context_processor)

    def set_user_baseclass(self, user_baseclass):
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
        app.config.setdefault("AD_TENANT_ID", "common")
        app.config.setdefault("AD_REDIRECT_URI", None)
        #app.config.setdefault("AD_AUTH_URL", 'https://login.microsoftonline.com/common/oauth2/authorize')
        #app.config.setdefault("AD_TOKEN_URL", 'https://login.microsoftonline.com/common/oauth2/token')
        app.config.setdefault("AD_GRAPH_URL", BASE_ENDPOINT)
        app.config.setdefault("AD_CALLBACK_PATH", '/connect/get_token')
        app.config.setdefault("AD_LOGIN_PATH", '/connect/init')
        app.config.setdefault("AD_LOGIN_REDIRECT", '/')
        app.config.setdefault("AD_GROUP_FORBIDDEN_REDIRECT", None)
        app.config.setdefault("AD_AUTH_GROUP", None)
        app.config.setdefault("AD_AUTH_USER_BASECLASS", None)

        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown_db)

        # Register Callback
        app.add_url_rule(app.config["AD_CALLBACK_PATH"], "auth_callback",
                         self.auth_callback)
        app.add_url_rule(app.config["AD_LOGIN_PATH"], "auth_init",
                         self.auth_init)

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

        # Create Client
        self.authority = BASE_AUTHORITY + str(app.config["AD_TENANT_ID"])
        self.client = msal.ConfidentialClientApplication(client_id=app.config["AD_APP_ID"], authority=self.authority,
                                                         client_credential=app.config["AD_APP_KEY"])
        self.redirect_uri = app.config["AD_REDIRECT_URI"]

        # Parent init call
        super(ADAuth, self).init_app(
            app=app, add_context_processor=add_context_processor)
        self.user_loader(self.load_user)
        self.flask_app = app

    def setDatabaseClass(self, my_class):
        self.connection_class = my_class

    def teardown_db(self, exception):
        """
        Close database connection.
        """
        adauth_db = g.pop('adauth_db', None)
        if adauth_db is not None:
            adauth_db.close()

    @property
    def db_connection(self):
        """
        Connection property. Use this to get the connection.
        It will create a reusable connection on the flask context.
        """
        if 'adauth_db' not in g:
            g.adauth_db = self.connection_class(current_app.config,
                                                user_baseclass=self.user_baseclass)
            g.adauth_db.connect()
        return g.adauth_db

    @property
    def sign_in_url(self):
        """
        Return the for the login redirect.
        """
        return url_for("auth_init")

    @classmethod
    def datetime_from_timestamp(cls, timestamp):
        """
        Convert unix timestamp to python datetime.
        """
        timestamp = float(timestamp)
        return datetime.datetime.utcfromtimestamp(timestamp)

    def get_token_silent(self, user):
        # lets see if we have this in cache
        accounts = self.client.get_accounts(user.email)
        if accounts:
            res = self.client.acquire_token_silent(scopes=DEFAULT_SCOPE, account=accounts[0])
            if res:
                logger.info("got token from cache")
                return res
            return None
        # try to migrate the refresh token to cache
        res = self.client.acquire_token_by_refresh_token(user.refresh_token, scopes=DEFAULT_SCOPE)
        if "error" in res:
            logger.warning("Refresh Error: {}").format(res.get("error"))
            return None
        logger.info("got token from db refresh")
        return res

    def decode_id_token(self, id_token):
        return jwt.decode(id_token, options={"verify_signature": False})

    def auth_callback(self):
        state_id = request.args.get('state')
        flow = self.db_connection.get_session_state(state_id)
        auth_result = self.client.acquire_token_by_auth_code_flow(auth_code_flow=flow, auth_response=request.args, scopes=None)
        if "error" in auth_result:
            print(auth_result)
            print("---")
            print("Auth Error: {}, {}".format(auth_result.get("error"), auth_result.get("error_description")))
            return abort(400)

        user_info = self.decode_id_token(auth_result["id_token"])
        try:
            full_user_id = "{}.{}".format(user_info["oid"], user_info["tid"])
            user_name = user_info["preferred_username"]
            email = user_name
            access_token = auth_result['access_token']
            refresh_token = auth_result['refresh_token']
            expires_in = int(auth_result['expires_in'])
            expires_on = time.time() + expires_in
            token_type = auth_result['token_type']
            scope = auth_result['scope']
        except KeyError:
            print(auth_result)
            raise
        user = self.user_baseclass(email=email, access_token=access_token,
                                   refresh_token=refresh_token, expires_on=expires_on,
                                   token_type=token_type, scope=scope)
        user.set_ad_manager(self)
        user.refresh_groups()
        self.store_user(user)
        login_user(user, remember=True) # Todo Remember me
        logger.warning("User %s logged in", user.email)
        if self.on_login_callback is not None:
            return self.on_login_callback(user)
        # Todo we should add an on login callback here
        # Or maybe redirect to next...
        flash("Logged in!", "success")
        return redirect(current_app.config["AD_LOGIN_REDIRECT"])

    def auth_init(self):
        redirect_after = request.args.get('redirect')
        res = self.client.initiate_auth_code_flow(scopes=DEFAULT_SCOPE, redirect_uri=self.redirect_uri,
                                                  prompt=None, domain_hint=None)
        id = res["state"]
        self.db_connection.store_session_state(id, res)
        return redirect(res["auth_uri"], 302)

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
            # Try to refresh
            else:
                logger.warning("Refreshing user %s", email)
                if not user.full_refresh():
                    return None
                self.store_user(user)
                g.user_id = user.email
                return user
        logger.warning("User %s not in database", email)
        # We need a new authentication
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
                        "scope TEXT,"
                        "groups TEXT,"
                        "metadata TEXT);")
        conn.execute("CREATE TABLE IF NOT EXISTS sessions ("
                        "id TEXT PRIMARY KEY, "
                        "expires_on FLOAT, "
                        "payload TEXT);")
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
                  "token_type, scope, groups, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (user.email, user.access_token, user.refresh_token, user.expires_on,
                   user.token_type, user.scope, user.group_string, _metadata))
        self.conn.commit()
        return user

    def get_user(self, email):
        """
        Get User from db. Will return the user object or None.
        """
        c = self.conn.cursor()
        c.execute("SELECT email, access_token, refresh_token, expires_on, "
                  "token_type, scope, groups, metadata FROM users WHERE email=?", (email,))
        row = c.fetchone()
        if row:
            _metadata = json.loads(row[7])
            return self.user_baseclass(email=row[0], access_token=row[1], refresh_token=row[2],
                                       expires_on=int(row[3]), token_type=row[4],
                                       scope=row[5], group_string=row[6], metadata=_metadata)
        return None

    def store_session_state(self, id, payload, ex=5*60):
        value = json.dumps(payload)
        expires_on = time.time() + ex
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO sessions (id, expires_on, payload) VALUES (?, ?, ?)",
                  (id, expires_on, value))
        self.conn.commit()
        # todo remove old states

    def get_session_state(self, id):
        c = self.conn.cursor()
        c.execute("SELECT id, expires_on, payload FROM sessions WHERE id=?", (id,))
        row = c.fetchone()
        if row:
            expires_on = row[1]
            if expires_on >= time.time():
                return json.loads(row[2])
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

    def store_session_state(self, id, payload, ex=5*60):
        value = json.dumps(payload)
        c = self.conn
        c.set("state_{}".format(id), value, ex=5*60)

    def get_session_state(self, id):
        c = self.conn
        raw = c.get("state_{}".format(id))
        if raw:
            return json.loads(raw)
        return None

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
