# mlflow basic auth

mlflow에서 제공하는 model tracking 기능을 활용하면 모델 이력 관리가 가능해서 모델 개발시 매우 편리합니다. 하지만 개발하는 모델의 규모가 커서 여러 사람과 함께 모델을 개발해야 할때에는 기본으로 제공하는 mlflow의 basic auth 기능 만으로는 사용자 관리가 매우 어렵습니다. 물론 management mlflow를 사용하면 이러한 불편한 점들이 많이 개선되지만 management mlflow를 사용하지 못하는 경우에는 기본적인 mlflow 많으로는 매우 아쉬운게 사실입니다. 이 글에서는 mlflow에 OIDC 인증을 연동하여 사용자 관리를 좀 더 편리하게 가능하도록 하는 방법을 소개하고자 합니다.

## 필수 요구 사항
- Python >= 3.10
- MLflow >= 2.9
- Keycloak >= 20.0.5

## 환경 구성

conda를 사용해서 가상 환경을 생성한 다음 mlflow 2.9 버전을 설치합니다. 그리고 basic_auth.ini 파일을 가상 환경 아래 생성하고 해당 Path를 MLFLOW_AUTH_CONFIG_PATH 환경 변수로 설정합니다.


## OIDC 연동 함수 개발



## 마치며

## 레퍼런스