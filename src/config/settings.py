import sys
from pathlib import Path
from dotenv import load_dotenv

# ----------------PATH FOR ENV FILE----------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent

sys.path.append(str(BASE_DIR))

load_dotenv(dotenv_path=BASE_DIR / ".env")

# ----------------HELPERS----------------
def require_env(var_name):
    from dotenv import dotenv_values
    env = dotenv_values(BASE_DIR / ".env")
    value = env.get(var_name)
    if not value:
        raise Exception(f"❌ Missing env var: {var_name}")
    return value

# ----------------API KEY SETTINGS----------------
SECRET_KEY = require_env("SECRET_KEY")

NET_ENCODER_API_KEY = require_env("NET_ENCODER_API_KEY")
JF_API_KEY = require_env("JF_API_KEY")

# ----------------DATABASE SETTINGS----------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': require_env('DB_NAME'),
        'USER': require_env('DB_USER'),
        'PASSWORD': require_env('DB_PASS'),
        'HOST': require_env('DB_HOST'),
        'PORT': require_env('DB_PORT'),
    }
}

# ----------------CORS SETTINGS----------------
CORS_ALLOW_ALL_ORIGINS = True   
CORS_ALLOW_CREDENTIALS = True
ALLOWED_HOSTS = ["*", "127.0.0.1", "localhost", "15.236.16.120"]
CORS_ALLOW_HEADERS = "*" 
CORS_ALLOW_METHODS = "*"  
CSRF_TRUSTED_ORIGINS = ["http://15.236.16.120"]

# ----------------INSTALLED APPS----------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "apps.net_encoder",
    'apps.revalidator.apps.RevalidatorConfig',
    'apps.device_registry.apps.DeviceRegistryConfig',
    "corsheaders",
]

# ----------------MIDDLEWARE----------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# ----------------ROOT URL CONF----------------
ROOT_URLCONF = "config.urls"

# ----------------TEMPLATES----------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
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

# ----------------AUTH PASSWORD VALIDATORS----------------
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

WSGI_APPLICATION = "config.wsgi.application"

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_PARSER_CLASSES": ("rest_framework.parsers.JSONParser",),
}
