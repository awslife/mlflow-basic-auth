import os
import sys
import logging
import jwt
import uuid
import requests

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from typing import Union

from flask import Response, make_response, session, request, url_for
from mlflow.server.auth import store as auth_store

from werkzeug.datastructures import Authorization

OIDC_USERNAME_CLAIM = os.getenv("OIDC_USERNAME_CLAIM", "email")
OIDC_ISSUER_URL = os.environ["OIDC_ISSUER_URL"]
OIDC_CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
OIDC_USER_GROUP = os.environ["OIDC_USER_GROUP"]

OIDC_AUTH_ENDPOINT_URL = f"{OIDC_ISSUER_URL}/protocol/openid-connect/auth"
OIDC_TOKEN_ENDPOINT_URL = f"{OIDC_ISSUER_URL}/protocol/openid-connect/token"

DEBUG = os.getenv("DEBUG", "false")
BEARER_PREFIX = "Bearer "

_logger = logging.getLogger(__name__)
if DEBUG == "True" or DEBUG == "true":
    _logger.addHandler(logging.StreamHandler(sys.stdout))
    _logger.setLevel(logging.DEBUG)

_auth_store = auth_store

_issuer_req = requests.get(OIDC_ISSUER_URL)
_public_key = serialization.load_der_public_key(b64decode(_issuer_req.json()["public_key"].encode()))
_redirect_uri = url_for('serve', _external=True)

def parse_token(token: dict = None) -> dict:
    user_info = dict()
    user_info["username"] = token[OIDC_USERNAME_CLAIM]

    groups = [str for str in token["groups"] if OIDC_USER_GROUP in str]
    user_info["is_admin"] = False
    for group in groups:
        if group.lower().endswith("_admin") is True:
            user_info["is_admin"] = True
            break
    return user_info

def update_user(user_info: dict = None):
    if _auth_store.has_user(user_info["username"]) is False:
        _auth_store.create_user(user_info["username"], user_info["username"], user_info["is_admin"])
    else:
        _auth_store.update_user(user_info["username"], user_info["username"], user_info["is_admin"])

def authenticate_request() -> Union[Authorization, Response]:
    if session.get("user_info", None) is not None:
        # _logger.debug("session.get(\"user_info\", None) is not None")
        return Authorization(auth_type="jwt", data=session["user_info"])

    resp = make_response()
    if session.get("state", None) is None:
        session["state"] = str(uuid.uuid4())

    token = request.headers.get("Authorization", None)
    code = request.args.get('code', None)
    if token is None and code is None:
        _logger.debug("token is None and code is None")

        session["user_info"] = None

        resp.status_code = 301
        resp.headers["Content-Type"] = "application/x-www-form-urlencoded"
        resp.location = (f"{OIDC_AUTH_ENDPOINT_URL}"
                    "?response_type=code"
                    "&scope=openid email profile"
                    f"&client_id={OIDC_CLIENT_ID}"
                    f"&redirect_uri={_redirect_uri}"
                    f"&state={session['state']}"
                    )
        return resp

    resp.status_code = 401
    resp.set_data(
        "You are not authenticated. Please provide a valid JWT Bearer token with the request."
    )
    resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'

    user_info = dict()
    # if token is not None and code is None:
    if token is not None:
        # _logger.debug("token is not None and code is None")
        _logger.debug("token is not None")
        if token.startswith(BEARER_PREFIX) or token.startswith(BEARER_PREFIX.lower()):
            token = token[len(BEARER_PREFIX):]
        _logger.debug(f"token={token}")
        try:
            jwt_token = jwt.decode(token, _public_key, algorithms=['HS256', 'RS256'], audience=OIDC_CLIENT_ID)
            if not jwt_token:
                _logger.warning("No jwt_token returned")
                return resp
            
            user_info = parse_token(jwt_token)
            update_user(user_info)
            session["user_info"] = user_info

            return Authorization(auth_type="jwt", data=user_info)
        except jwt.exceptions.InvalidTokenError:
            return resp

    if code is not None and request.headers.get("Authorization", None) is None:
        _logger.debug("code is not None and request.headers.get(\"Authorization\", None) is None")
        if session.get('state', None) != request.args.get('state', None):
            return resp
        
        payload = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{_redirect_uri}",
            "client_id": f"{OIDC_CLIENT_ID}",
            "client_secret": f"{OIDC_CLIENT_SECRET}",
        }
        
        resp_token = requests.post(f"{OIDC_TOKEN_ENDPOINT_URL}", data=payload)
        access_token = resp_token.json()["access_token"]
        jwt_token = jwt.decode(access_token, _public_key, algorithms=['HS256', 'RS256'], audience=OIDC_CLIENT_ID)
        if not jwt_token:
            _logger.warning("No jwt_token returned")
            return resp
        
        user_info = parse_token(jwt_token)
        update_user(user_info)
        session["user_info"] = user_info

        return Authorization(auth_type="jwt", data=user_info)
    
    return resp
