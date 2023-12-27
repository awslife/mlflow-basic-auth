# mlflow basic auth

mlflow에서 제공하는 model tracking 기능을 활용하면 모델 이력 관리가 가능해서 모델 개발시 매우 편리합니다. 하지만 개발하는 모델의 규모가 커서 여러 사람과 함께 모델을 개발해야 할때에는 기본으로 제공하는 mlflow의 basic auth 기능 만으로는 사용자 관리가 매우 어렵습니다. 물론 management mlflow를 사용하면 이러한 불편한 점들이 많이 개선되지만 management mlflow를 사용하지 못하는 경우에는 기본적인 mlflow 많으로는 매우 아쉬운게 사실입니다. 이 글에서는 mlflow에 OIDC 인증을 연동하여 사용자 관리를 좀 더 편리하게 가능하도록 하는 방법을 소개하고자 합니다.

## 필수 요구 사항
- Python >= 3.10
- MLflow >= 2.9
- Keycloak >= 20.0.5

## 환경 구성

conda를 사용해서 가상 환경을 생성한 다음 mlflow 2.9 버전을 설치합니다. 그리고 basic_auth.ini 파일을 가상 환경 아래 생성하고 해당 Path를 MLFLOW_AUTH_CONFIG_PATH 환경 변수로 설정합니다.

basic_auth.init sample

```ini
[mlflow]
default_permission = READ
database_uri = sqlite:///basic_auth.db
admin_username = admin
admin_password = password
authorization_function = auth.oidc_auth:authenticate_request
```

## OIDC 연동 함수 개발

mlflow에서 커스텀 인증을 사용하기 위해서는 authorization_function을 변경해야 하고 auth/oidc_auth.py 파일을 생성하여 커스텀 인증을 구현하였습니다.
oidc_auth.py 에서는 4가지 케이스를 고려해서 기능을 구현해야 한다.

- REST API를 통해서 jwt 토큰이 전달 될때의 인증
- MLflow UI를 통해서 OIDC를 연동할때의 인증
  - OIDC Issuer에서 인증 후 callbak 될때의 인증 구현
  - MLflow 메인 페이지에서 사용자 정보 전달

아래는 4가지 케이스가 고려된 기능 예제이다.
(핵심 소스만 가져왔으며 전체 소스가 보고 싶으면 레퍼런스의 github repository를 참고하기 바란다)

```python
...

def authenticate_request() -> Union[Authorization, Response]:
    if session.get("user_info", None) is not None:
        return Authorization(auth_type="jwt", data=session["user_info"])

    resp = make_response()
    if session.get("state", None) is None:
        session["state"] = str(uuid.uuid4())

    token = request.headers.get("Authorization", None)
    code = request.args.get('code', None)
    if token is None and code is None:
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
            jwt_token = jwt.decode(token, "secret", algorithms=["HS256"])
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
```

## 데모

테스트를 위해서는 mlflow 설치와 OIDC Issuer 정보를 환경 변수로 설정해야 한다.

```bash
$ conda create -y -n mlflow-basic-auth python=3.10 mlflow=2.9
$ conda activate mlflow-basic-auth
$ export OIDC_ISSUER_URL=https://oidc.issuer.io
$ export OIDC_USERNAME_CLAIM=preferred_username
$ export OIDC_CLIENT_ID=client
$ export OIDC_CLIENT_SECRET=secret
$ export OIDC_USER_GROUP="MLFLOW"
$ export MLFLOW_AUTH_CONFIG_PATH=$BASE_DIR/basic_auth.ini
$ mlflow server --dev --workers 1 --app-name basic-auth --host 0.0.0.0 --port 8080
```
mlflow 서버가 실행되면 웹브라우져에서 OIDC 연동이 정상적으로 되는지 체크한다.

## 마치며

mlflow에 keycloak을 이용한 oidc 인증을 적용해 보았다.
mlflow를 좀 더 확장해 적용하고 싶다면 레퍼런스에서 좀 더 많은 정보를 찾을 수 있을것이다.

## 레퍼런스

- [mlflow oidc login](https://github.com/awslife/mlflow-basic-auth)