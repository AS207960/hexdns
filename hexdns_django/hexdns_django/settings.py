"""
Django settings for hexdns_django project.

Generated by 'django-admin startproject' using Django 3.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import json
import logging
import sentry_sdk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sentry_sdk.integrations.django import DjangoIntegration

logging.basicConfig(level=logging.INFO)

sentry_sdk.init(
    dsn="https://d6b7136a929749a0976ec3cf2251d949@o222429.ingest.sentry.io/5197801",
    environment=os.getenv("SENTRY_ENVIRONMENT", "dev"),
    release=os.getenv("RELEASE", None),
    integrations=[DjangoIntegration()],
    send_default_pii=True,
)

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY", "")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = [os.getenv("HOST", "dns.as207960.net")]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django_keycloak_auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "crispy_forms",
    "dns_grpc",
    "django_grpc",
    'crispy_bootstrap4',
    'rest_framework',
]

MIDDLEWARE = [
    'xff.middleware.XForwardedForMiddleware',
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_keycloak_auth.middleware.OIDCMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "hexdns_django.urls"

AUTHENTICATION_BACKENDS = ["django_keycloak_auth.auth.KeycloakAuthorization"]

LOGIN_URL = "oidc_login"
LOGOUT_REDIRECT_URL = "oidc_login"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, 'templates')],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "hexdns_django.wsgi.application"


GRPCSERVER = {
    "servicers": [
        "dns_grpc.grpc.grpc_hook",
        "dns_grpc.axfr.grpc_hook",
    ],
    "maximum_concurrent_rpcs": None,
}

# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django_cockroachdb",
        "HOST": os.getenv("DB_HOST", "localhost"),
        "NAME": os.getenv("DB_NAME", "hexdns"),
        "USER": os.getenv("DB_USER", "hexdns"),
        "PASSWORD": os.getenv("DB_PASS"),
        "PORT": '26257',
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = "en-gb"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

EXTERNAL_URL_BASE = os.getenv("EXTERNAL_URL", f"https://{ALLOWED_HOSTS[0]}")

STATIC_URL = os.getenv("STATIC_URL", f"{EXTERNAL_URL_BASE}/static/")
MEDIA_URL = os.getenv("MEDIA_URL", f"{EXTERNAL_URL_BASE}/media/")

AWS_S3_CUSTOM_DOMAIN = os.getenv("S3_CUSTOM_DOMAIN", "")
AWS_QUERYSTRING_AUTH = False
AWS_S3_REGION_NAME = os.getenv("S3_REGION", "")
AWS_S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT", "")
AWS_STORAGE_BUCKET_NAME = os.getenv("S3_BUCKET", "")
AWS_S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "")
AWS_S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "")
AWS_S3_ADDRESSING_STYLE = "virtual"
AWS_S3_SIGNATURE_VERSION = "s3v4"

ZONE_STORAGE_BUCKET = os.getenv("S3_ZONE_BUCKET", "")

STORAGES = {
    "default": {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage"},
    "staticfiles": {"BACKEND": "storages.backends.s3boto3.S3ManifestStaticStorage"}
}

DEFAULT_FROM_EMAIL = os.getenv("EMAIL_FROM", "Glauca HexDNS <dns@glauca.digital>")

LISTMONK_TEMPLATE_ID = int(os.getenv("LISTMONK_TEMPLATE_ID"))
LISTMONK_URL = os.getenv("LISTMONK_URL")

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
OIDC_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
OIDC_SCOPES = os.getenv("KEYCLOAK_SCOPES")

GITHUB_APP_NAME = os.getenv("GITHUB_APP_NAME")
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

NETNOD_API_KEY = os.getenv("NETNOD_API_KEY")

CRISPY_TEMPLATE_PACK = "bootstrap4"

DNSSEC_KEY_LOCATION = os.getenv("DNSSEC_KEY_LOCATION")
DNSSEC_PUBKEY_LOCATION = os.getenv("DNSSEC_PUBKEY_LOCATION")
DNSSEC_SIGNAL_PRIVKEY_LOCATION = os.getenv("DNSSEC_SIGNAL_PRIVKEY_LOCATION")
DOMAINS_PUBKEY_LOCATION = os.getenv("DOMAINS_PUBKEY_LOCATION")

with open(DNSSEC_PUBKEY_LOCATION, "rb") as f:
    pub_key_data = f.read()

with open(DNSSEC_SIGNAL_PRIVKEY_LOCATION, "r") as f:
    DNSSEC_SIGNAL_PRIVKEY_DATA = f.read()

with open(DOMAINS_PUBKEY_LOCATION, "rb") as f:
    DOMAINS_JWT_PUB = f.read()

DNSSEC_PUBKEY = load_pem_public_key(pub_key_data, backend=default_backend())
if not issubclass(type(DNSSEC_PUBKEY), EllipticCurvePublicKey):
    raise Exception("Only EC public keys supported")

XFF_TRUSTED_PROXY_DEPTH = 1
XFF_STRICT = True

DOMAINS_URL = os.getenv("DOMAINS_URL")
FEEDBACK_URL = os.getenv("FEEDBACK_URL")
BILLING_URL = os.getenv("BILLING_URL")
PAT_URL = os.getenv("PAT_URL")
BILLING_PLAN_ID = os.getenv("BILLING_PLAN_ID")

RESOLVER_ADDR = os.getenv("RESOLVER_ADDR")
RESOLVER_PORT = int(os.getenv("RESOLVER_PORT"))
RESOLVER_IPV6 = True
RESOLVER_NO_DNS64_ADDR = os.getenv("RESOLVER_NO_DNS64_ADDR")
RESOLVER_NO_DNS64_PORT = int(os.getenv("RESOLVER_NO_DNS64_PORT"))
RESOLVER_NO_DNS64_IPV6 = True

RABBITMQ_RPC_URL = os.getenv("RABBITMQ_RPC_URL")

KUBE_IN_CLUSTER = bool(os.getenv("KUBE_IN_CLUSTER"))
KUBE_NAMESPACE = os.getenv("KUBE_NAMESPACE")

ZONE_FILE_LOCATION = os.getenv("ZONE_FILE_LOCATION")

CELERY_RESULT_BACKEND = "rpc://"
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser'
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'as207960_utils.api.auth.BearerAuthentication',
        'as207960_utils.api.auth.PATAuthentication',
        'as207960_utils.api.auth.SessionAuthentication',
    ] if PAT_URL else [
        'as207960_utils.api.auth.BearerAuthentication',
        'as207960_utils.api.auth.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 25
}

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

