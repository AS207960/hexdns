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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logging.basicConfig(level=logging.INFO)

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "pb9=mpf!@sphhhjc=074!%)g4!ek#3#onh)+5d4rdkmnl*mp4x"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

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
    "servicers": ["dns_grpc.grpc.grpc_hook"],
    "maximum_concurrent_rpcs": None,
}

# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
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

EXTERNAL_URL_BASE = "http://localhost:8002"
STATIC_URL = "/static/"

with open(os.path.join(BASE_DIR, "secrets/keycloak.json")) as f:
    keycloak_conf = json.load(f)

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "Glauca HexDNS <dns@glauca.digital>"

KEYCLOAK_SERVER_URL = keycloak_conf["server_url"]
KEYCLOAK_REALM = keycloak_conf["realm"]
OIDC_CLIENT_ID = keycloak_conf["client_id"]
OIDC_CLIENT_SECRET = keycloak_conf["client_secret"]
OIDC_SCOPES = keycloak_conf["scopes"]

CRISPY_TEMPLATE_PACK = "bootstrap4"

DNSSEC_KEY_LOCATION = "secrets/k.pem"
DNSSEC_PUBKEY_LOCATION = "secrets/p.pem"

with open(DNSSEC_PUBKEY_LOCATION, "rb") as f:
    pub_key_data = f.read()

with open("domains_jwt_pub.pem", "rb") as f:
    DOMAINS_JWT_PUB = f.read()

DNSSEC_PUBKEY = load_pem_public_key(pub_key_data, backend=default_backend())
if not issubclass(type(DNSSEC_PUBKEY), EllipticCurvePublicKey):
    raise Exception("Only EC public keys supported")

BILLING_URL = "http://localhost:8001"
FEEDBACK_URL = "http://localhost:8003"
DOMAINS_URL = "http://localhost:8000"
BILLING_PLAN_ID = "billing_recurringplan_c66432f6b3c544b1b88615fcdb6f9b79"

RESOLVER_ADDR = "2a0d:1a40:7900::2"
RESOLVER_PORT = 53

RABBITMQ_RPC_URL = "amqp://guest:guest@localhost:5672/rpc"

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
        'as207960_utils.api.auth.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 25
}

LOGGING = {
    'version': 1,
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
        }
    },
    'loggers': {
        'django.db.backends': {
            'level': 'INFO',
            'handlers': ['console'],
        }
    }
}