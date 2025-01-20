# Add 'accounts' to INSTALLED_APPS
INSTALLED_APPS = [
    # ...
    'accounts',
]

# Add custom user model
AUTH_USER_MODEL = 'accounts.User'

# Add login URL
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'client_dashboard' 