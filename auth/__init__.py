import base64
import os
import sys
import logging
import jwt
import httpx
import uuid
import requests

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from typing import Union

from flask import Response, make_response, session, request, url_for
from mlflow.server.auth import store as auth_store

from werkzeug.datastructures import Authorization

OIDC_PROVIDER_NAME = os.getenv("OIDC_PROVIDER_NAME", "keycloak")
OIDC_USERNAME_CLAIM = os.getenv("OIDC_USERNAME_CLAIM", "email")
OIDC_ISSUER_URL = os.environ["OIDC_ISSUER_URL"]
OIDC_CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]

OIDC_AUTH_ENDPOINT_URL = f"{OIDC_ISSUER_URL}/protocol/openid-connect/auth"
OIDC_TOKEN_ENDPOINT_URL = f"{OIDC_ISSUER_URL}/protocol/openid-connect/token"

BEARER_PREFIX = "bearer "

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.StreamHandler(sys.stdout))
_logger.setLevel(logging.DEBUG)

_store = auth_store

req = requests.get(OIDC_ISSUER_URL)
_public_key = serialization.load_der_public_key(b64decode(req.json()["public_key"].encode()))
_redirect_uri = url_for('serve', _external=True)

def authenticate_request() -> Union[Authorization, Response]:
    if session.get("user_info", None) is not None:
        return Authorization(auth_type="jwt", data=session["user_info"])

    resp = make_response()
    if session.get("state", None) is None:
        session["state"] = str(uuid.uuid4())
    # _logger.debug(f"session['state']={session['state']}")

    token = request.headers.get("Authorization", None)
    code = request.args.get('code', None)
    if token is None and code is None:
        _logger.debug("301")
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
    if token is not None and code is None:
        token = token.lower().startswith(BEARER_PREFIX)[len(BEARER_PREFIX):]
        try:
            token_info = jwt.decode(token, "secret", algorithms=["HS256"])
            if not token_info:  # pragma: no cover
                _logger.warning("No token_info returned")
                return resp
            user_info["username"] = token_info[OIDC_USERNAME_CLAIM]
            session["user_info"] = user_info

            if _store.has_user(user_info['username']) is False:
                _store.create_user(user_info['username'], user_info['username'], is_admin=True)
            else:
                _store.update_user(user_info['username'], user_info['username'], is_admin=True)
            
            return Authorization(auth_type="jwt", data=user_info)
        except jwt.exceptions.InvalidTokenError:
            return resp

    if code is not None and request.headers.get("Authorization", None) is None:
        if session.get('state', None) != request.args.get('state', None):
            _logger.debug(f"session['state']={session['state']}, request['state']={request.args.get('state')}")
            return resp
        
        payload = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{_redirect_uri}",
            "client_id": f"{OIDC_CLIENT_ID}",
            "client_secret": f"{OIDC_CLIENT_SECRET}",
        }
        
        response = httpx.post(f"{OIDC_TOKEN_ENDPOINT_URL}", data=payload)
        access_token = response.json()["access_token"]
        token_info = jwt.decode(access_token, _public_key, algorithms=['HS256', 'RS256'], audience=OIDC_CLIENT_ID)
        user_info["username"] = token_info[OIDC_USERNAME_CLAIM]

        _logger.debug(f'username={user_info["username"]}')

        if _store.has_user(user_info['username']) is False:
            _store.create_user(user_info['username'], user_info['username'], is_admin=True)
        else:
            _store.update_user(user_info['username'], user_info['username'], is_admin=True)
        
        if not token_info:  # pragma: no cover
            _logger.warning("No token_info returned")
            return resp
        session["user_info"] = user_info

        return Authorization(auth_type="jwt", data=user_info)
    
    return resp
