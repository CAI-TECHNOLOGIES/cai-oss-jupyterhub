import asyncio
import types
import configparser as CP
import os
import re      #k8s
import sys     #k8s
import logging
import requests
import sqlalchemy as db
import json


from tornado.httpclient import AsyncHTTPClient     #k8s
from kubernetes import client         #k8s
from jupyterhub.utils import url_path_join    #k8s
from tornado import gen
#from dockerspawner.dockerspawner import DockerSpawner as DS
from werkzeug.security import check_password_hash
from jupyterhub.auth import Authenticator
# from ldapauthenticator import LDAPAuthenticator
from pathlib import Path
from urllib.parse import urlparse

from oauthenticator.azuread import AzureAdOAuthenticator

DATABASE_DIALECT = "mysql"
MYSQL_DB = os.environ.get("MYSQL_DATABASE", "caihub")
USER_TABLE = os.environ.get("USER_TABLE", "ab_user")
NOTEBOOK_DIR = os.environ.get("DOCKER_NOTEBOOK_DIR", "/home/jovyan/work")
CONFIGS_DIR = os.environ.get("HADOOP_CONFIGS_DIR", "/home/jovyan/.configs/hadoop_config_groups/")
MEM_LIMIT = os.environ.get('NOTEBOOK_CONTAINER_MEM_LIMIT', '2G')
# DOCKER_SPAWNER_IMAGE = os.environ.get('DOCKER_SPAWNER_IMAGE', 'couture/jupyter-server-spawner:latest')
SETUP_VOLUME_PATH = os.environ.get("SETUP_VOLUME_PATH", "/opt/setup")
SETUP_VOLUME_NAME = os.environ.get("SETUP_VOLUME_NAME", "setup")
CODE_ARTIFACT_VOLUME_NAME = os.environ.get("CODE_ARTIFACT_VOLUME_NAME", "code")
CODE_ARTIFACT_VOLUME_PATH = os.environ.get("CODE_ARTIFACT_VOLUME_PATH", "/opt/code")
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI",'http://couture-mlflow:5000')
MLFLOW_S3_ENDPOINT_URL = os.getenv("MLFLOW_S3_ENDPOINT_URL", "http://couture-minio:9000")
MODEL_SERVERS_VOLUME_PATH = os.environ.get("MODEL_SERVERS_VOLUME_PATH", "/home/jovyan/model-servers")
MYSQL_SERVICE_NAMESPACE = os.environ.get("MYSQL_SERVICE_NAMESPACE","dev") + ".svc"
# check if AUTH_TYPE is AUTH_LDAP or AUTH_DB and set `self.find_user`
# to appropriate method.

LDAP_PATH = os.environ.get('LDAP_CONF_PATH', '/etc/ldap.conf')
IS_GPU = os.environ.get("IS_GPU", "no")

def getVaultSecrets(VAULT_ADDR, VAULT_SECRET_PATH, VAULT_TOKEN, VAULT_MOUNT):
    """
    Input: Take in Vault URL address, path to secrets, and user's token
    Output: Return dictoanry of secrets for the path provided
    """
    auth_header = {
        "X-Vault-Token": VAULT_TOKEN
    }
    url = f"{VAULT_ADDR}/v1/{VAULT_MOUNT}/data/{VAULT_SECRET_PATH}"
    response = requests.get(url=url, headers=auth_header)
    return response.json()['data']['data']

def getToken(VAULT_ADDR, VAULT_ROLE):
    token = ""
    with open('/vault/secrets/vault_config.json', 'r', encoding='utf-8') as file:
        token = json.load(file)

    return token['token']

token = getToken(VAULT_ADDR=os.environ.get("VAULT_ADDR","http://vault.vault.svc:8200"), \
                                VAULT_ROLE="notebook-server")
                                
secrets = getVaultSecrets(VAULT_ADDR=os.environ.get("VAULT_ADDR","http://vault.vault.svc:8200"), \
                                VAULT_SECRET_PATH="configs", \
                                VAULT_MOUNT="notebook-server", \
                                VAULT_TOKEN=os.environ.get("VAULT_NOTEBOOKS_TOKEN", token))
AWS_ACCESS_KEY_ID = secrets["aws_access_key_id"]
AWS_SECRET_ACCESS_KEY = secrets["aws_secret_access_key"]

MYSQL_USER = secrets["mysql_user"]
MYSQL_PASSWORD = secrets["mysql_password"]
MYSQL_HOST = f"{secrets['mysql_host']}.{MYSQL_SERVICE_NAMESPACE}"
MYSQL_PORT = secrets["mysql_port"]
CONFIGPROXY_AUTH_TOKEN = secrets["configproxy_auth_token"]



# if IS_GPU == "yes" or IS_GPU == "True":
#     IS_GPU = True
#     DOCKER_SPAWNER_IMAGE = os.environ.get('DOCKER_SPAWNER_IMAGE', 'couture/jupyter-server-spawner:latest-gpu')
# else:
#     IS_GPU = False

# class DockerSpawner(DS):
#     setup_volume_path = SETUP_VOLUME_PATH
#     setup_volume_name = SETUP_VOLUME_NAME
#     def get_notebook_env(self):
#         KEYTAB_CONFIG = os.path.join(CONFIGS_DIR, 'default/keytab/keytab.conf')
#         try:
#             krb_config = CP.ConfigParser()
#             krb_config.optionxform = str
#             krb_config.read(filenames=KEYTAB_CONFIG)
#             try:
#                 KRB5_CLIENT_KTNAME = os.path.join(CONFIGS_DIR, *['default', 'keytab',  str(krb_config.get('arguments', 'keytab')).split('/')[-1]])
#                 KRB5_PRINCIPAL = krb_config.get('arguments', 'principal')
#                 KRB5_CONFIG = os.path.join(CONFIGS_DIR, 'default/keytab/krb5.conf')
#             except Exception:
#                 KRB5_CLIENT_KTNAME = ''
#                 KRB5_PRINCIPAL = ''
#                 KRB5_CONFIG = ''

#             # {
#             #     'HADOOP_HOME': os.path.join(self.setup_volume_path, 'Hadoop'),
#             #     'HADOOP_COMMON_LIB_NATIVE_DIR': f'{os.path.join(self.setup_volume_path, "Hadoop")}/lib/native',
#             #     'HADOOP_CLIENT_OPTS': f'-Djava.library.path={os.path.join(self.setup_volume_path, "Hadoop")}/lib',
#             #     # TODO: Rename jdk1.8.0_181 to jdk1.8.0_271 
#             #     'JAVA_HOME': os.path.join(self.setup_volume_path, 'jdk1.8.0_271'),
#             #     'SPARK_HOME': os.path.join(self.setup_volume_path, 'Spark'),
#             #     'LIBHDFS_OPTS': f'-Djava.security.krb5.conf={KRB5_CONFIG}'
#             # }
#             return {
#                 'KRB5_CLIENT_KTNAME': KRB5_CLIENT_KTNAME,
#                 'KRB5_PRINCIPAL': KRB5_PRINCIPAL,
#                 'KRB5_CONFIG': KRB5_CONFIG,
#                 'HADOOP_HOME': os.path.join(self.setup_volume_path, 'Hadoop'),
#                 'HADOOP_COMMON_LIB_NATIVE_DIR': f'{os.path.join(self.setup_volume_path, "Hadoop")}/lib/native',
#                 'HADOOP_CLIENT_OPTS': f'-Djava.library.path={os.path.join(self.setup_volume_path, "Hadoop")}/lib',
#                 # TODO: Rename jdk1.8.0_181 to jdk1.8.0_271 
#                 'JAVA_HOME': os.path.join(self.setup_volume_path, 'jdk1.8.0_271'),
#                 'SPARK_HOME': os.path.join(self.setup_volume_path, 'Spark'),
#                 'LIBHDFS_OPTS': f'-Djava.security.krb5.conf={KRB5_CONFIG}',
#                 'HADOOP_CONF_DIR': os.path.join(CONFIGS_DIR, 'default'),
#                 'PYTHONPATH': '$PYTHONPATH:/opt/code/templates/dl_commons.egg',
#                 'MLFLOW_TRACKING_URI': MLFLOW_TRACKING_URI,
#                 'MLFLOW_S3_ENDPOINT_URL': MLFLOW_S3_ENDPOINT_URL,
#                 'AWS_ACCESS_KEY_ID': AWS_ACCESS_KEY_ID,
#                 'AWS_SECRET_ACCESS_KEY': AWS_SECRET_ACCESS_KEY
#             }
#         except Exception as e:
#             # self.log.error("EXCEPTION: " + e)
#             return {'error': str(e)}



# def get_env(self):
#     env = super().get_env()
#     env.update(self.get_notebook_env())
#     self.log.debug('Adding Hadoop Env Variables {}'.format(env))
#     return env

# @gen.coroutine
# def create_object(self):
#     """Create the container/service object"""

#     create_kwargs = dict(
#         image=self.image,
#         environment=self.get_env(),
#         volumes=self.volume_mount_points,
#         name=self.container_name,
#         command=(yield self.get_command()),
#     )

#     # ensure internal port is exposed
#     create_kwargs["ports"] = {"%i/tcp" % self.port: None}

#     create_kwargs.update(self.extra_create_kwargs)

#     # build the dictionary of keyword arguments for host_config
#     host_config = dict(binds=self.volume_binds, links=self.links)

#     if getattr(self, "mem_limit", None) is not None:
#         # If jupyterhub version > 0.7, mem_limit is a traitlet that can
#         # be directly configured. If so, use it to set mem_limit.
#         # this will still be overriden by extra_host_config
#         host_config["mem_limit"] = self.mem_limit

#     if not self.use_internal_ip:
#         host_config["port_bindings"] = {self.port: (self.host_ip,)}
#     host_config.update(self.extra_host_config)
#     host_config.setdefault("network_mode", self.network_name)
#     if IS_GPU:
#         host_config.update(device_requests=[
#             docker.types.DeviceRequest(count=-1, capabilities=[['gpu']])
#         ])
#     self.log.debug("Starting host with config: %s", host_config)

#     host_config = self.client.create_host_config(**host_config)

#     create_kwargs.setdefault("host_config", {}).update(host_config)

#     # create the container
#     obj = yield self.docker("create_container", **create_kwargs)
#     return obj

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = "%s://%s:%s@%s:%s/%s" % (
    DATABASE_DIALECT,
    MYSQL_USER,
    MYSQL_PASSWORD,
    MYSQL_HOST,
    MYSQL_PORT,
    MYSQL_DB,
)

# SQLALCHEMY_DATABASE_URI = "sqlite:////srv/jupyterhub/airflow.db"

CULL_TIMEOUT = os.environ.get('CULL_TIMEOUT', '3600')
ADMIN_USERS = set(os.environ.get('ADMIN', 'superadmin').split(','))


class HackyAuthenticator(Authenticator):

    # attributes used for Workflow DB access
    __engine = None
    __metadata = None
    __users = None

    # attributes used for LDAP access
    __ldap_authenticator = None

    # admin_users = set(['superadmin', 'admin'])
    admin_users = ADMIN_USERS


    def __init__(self, *args, **kwargs):

        config = CP.ConfigParser()
        config.optionxform = str
        config.read(filenames=LDAP_PATH)
        # check if AUTH_TYPE is AUTH_LDAP or AUTH_DB and set `self.find_user`
        # to appropriate method.
        if config.get('ldap', 'AUTH_TYPE') == 'AUTH_LDAP':
            self.find_user = self.find_ldap_user
            self.set_ldap_conf(config)
        else:
            self.find_user = self.find_db_user
            self.init_db_engine()
            self.init_db_metadata()
            self.init_db_table()
        super().__init__(*args, **kwargs)


    @property
    def ldap_authenticator(self):
        if not self.__ldap_authenticator:
            self.__ldap_authenticator = LDAPAuthenticator()
        return self.__ldap_authenticator

    @classmethod
    def init_db_engine(cls):
        if not cls.__engine:
            cls.__engine = db.create_engine(
                SQLALCHEMY_DATABASE_URI,
                pool_pre_ping=True)

        return cls.__engine

    @classmethod
    def get_db_connection(cls):
        return cls.init_db_engine().connect()

    @classmethod
    def init_db_metadata(cls):
        if not cls.__metadata:
            cls.__metadata = db.MetaData()

    @classmethod
    def init_db_table(cls):
        if not cls.__users:
            cls.__users = db.Table(
                USER_TABLE,
                cls.__metadata,
                autoload=True,
                autoload_with=cls.__engine)

    def set_ldap_conf(self, config):
        url = urlparse(config.get('ldap', 'AUTH_LDAP_SERVER'))
        self.ldap_authenticator.server_address = url.netloc.split(':')[0]
        if len(url.netloc.split(':')[0]) > 1:
            self.ldap_authenticator.server_port = int(url.netloc.split(':')[1])
        # NOTE: If making changes in thise section, go through 
        # https://github.com/jupyterhub/ldapauthenticator/blob/master/ldapauthenticator/ldapauthenticator.py
        # to make sure you don't need to any more fields.
        self.ldap_authenticator.use_ssl = config.get('ldap', 'AUTH_LDAP_USE_TLS') == 'True'
        self.ldap_authenticator.allowed_groups = None
        self.ldap_authenticator.search_filter = config.get('ldap', 'AUTH_LDAP_SEARCH_FILTER')
        self.ldap_authenticator.user_attribute = config.get('ldap', 'AUTH_LDAP_UID_FIELD')
        self.ldap_authenticator.user_search_base = config.get('ldap', 'AUTH_LDAP_SEARCH')
        self.ldap_authenticator.bind_dn_template = ["%s={username},%s" %(self.ldap_authenticator.user_attribute, self.ldap_authenticator.user_search_base)]
        
        # Not supported right now        
        # self.ldap_authenticator.lookup_dn = True
        # self.ldap_authenticator.lookup_dn_search_user = config.get('ldap', 'AUTH_LDAP_BIND_USER')
        # self.ldap_authenticator.lookup_dn_search_password = config.get('ldap', 'AUTH_LDAP_BIND_PASSWORD')


    async def find_db_user(self, handler, data):
        username = data['username']
        query = db.select([self.__users.columns.username, self.__users.columns.password]).where(
            self.__users.columns.username == username)
        user = self.get_db_connection().execute(query).first()
        if not user:
            return None
        if check_password_hash(user[1], data['password']):
            return user[0]

    async def find_ldap_user(self, handler, data):
        return await self.ldap_authenticator.authenticate(handler, data)

    async def authenticate(self, handler, data):
        return await self.find_user(handler, data)


# Configuration file for jupyterhub.

# ------------------------------------------------------------------------------
# Application(SingletonConfigurable) configuration
# ------------------------------------------------------------------------------

# This is an application.

# The date format used by logging formatters for %(asctime)s
#c.Application.log_datefmt = '%Y-%m-%d %H:%M:%S'

# The Logging format template
#c.Application.log_format = '[%(name)s]%(highlevel)s %(message)s'

# Set the log level by value or name.
#c.Application.log_level = 30

# ------------------------------------------------------------------------------
# JupyterHub(Application) configuration
# ------------------------------------------------------------------------------

# An Application for starting a Multi-User Jupyter Notebook server.

# Maximum number of concurrent servers that can be active at a time.
#
#  Setting this can limit the total resources your users can consume.
#
#  An active server is any server that's not fully stopped. It is considered
#  active from the time it has been requested until the time that it has
#  completely stopped.
#
#  If this many user servers are active, users will not be able to launch new
#  servers until a server is shutdown. Spawn requests will be rejected with a 429
#  error asking them to try again.
#
#  If set to 0, no limit is enforced.
#c.JupyterHub.active_server_limit = 0

# Duration (in seconds) to determine the number of active users.
#c.JupyterHub.active_user_window = 1800

# Resolution (in seconds) for updating activity
#
#  If activity is registered that is less than activity_resolution seconds more
#  recent than the current value, the new value will be ignored.
#
#  This avoids too many writes to the Hub database.
#c.JupyterHub.activity_resolution = 30

# Grant admin users permission to access single-user servers.
#
#  Users should be properly informed if this is enabled.
#c.JupyterHub.admin_access = False

# DEPRECATED since version 0.7.2, use Authenticator.admin_users instead.
#c.JupyterHub.admin_users = set()

# Allow named single-user servers per user
#c.JupyterHub.allow_named_servers = False

# Answer yes to any questions (e.g. confirm overwrite)
#c.JupyterHub.answer_yes = False

# PENDING DEPRECATION: consider using services
#
#  Dict of token:username to be loaded into the database.
#
#  Allows ahead-of-time generation of API tokens for use by externally managed
#  services, which authenticate as JupyterHub users.
#
#  Consider using services for general services that talk to the JupyterHub API.
#c.JupyterHub.api_tokens = {}

# Authentication for prometheus metrics
#c.JupyterHub.authenticate_prometheus = True

# Class for authenticating users.
#
#          This should be a subclass of :class:`jupyterhub.auth.Authenticator`
#
#          with an :meth:`authenticate` method that:
#
#          - is a coroutine (asyncio or tornado)
#          - returns username on success, None on failure
#          - takes two arguments: (handler, data),
#            where `handler` is the calling web.RequestHandler,
#            and `data` is the POST form data from the login page.
#
#          .. versionchanged:: 1.0
#              authenticators may be registered via entry points,
#              e.g. `c.JupyterHub.authenticator_class = 'pam'`
#
#  Currently installed:
#    - default: jupyterhub.auth.PAMAuthenticator
#    - dummy: jupyterhub.auth.DummyAuthenticator
#    - pam: jupyterhub.auth.PAMAuthenticator
# c.JupyterHub.authenticator_class = HackyAuthenticator

c.JupyterHub.authenticator_class = AzureAdOAuthenticator

# c.MyOAuthenticator.oauth_callback_url = 'https://jupyter.example.com/hub/oauth_callback'
c.AzureAdOAuthenticator.authorize_url = 'https://login.microsoftonline.com/56ed7cf6-887d-4a15-8cab-9c5981b3c4e7/oauth2/v2.0/authorize'
c.AzureAdOAuthenticator.token_url = 'https://login.microsoftonline.com/56ed7cf6-887d-4a15-8cab-9c5981b3c4e7/oauth2/v2.0/token'


c.AzureAdOAuthenticator.client_id = secrets['client_id']
c.AzureAdOAuthenticator.client_secret = secrets['client_secret']
c.AzureAdOAuthenticator.scope = [
        'openid',
        'profile',
        'email',
        'offline_access',
    ]
# c.AzureAdOAuthenticator.username_key = 'preferred_username'
c.AzureAdOAuthenticator.oauth_callback_url = os.environ.get("OAUTH_CALLBACK_URL", 'https://exl.workbench.couture.ai/hub/oauth_callback')
c.AzureAdOAuthenticator.tenant_id = secrets["tenant_id"]

def get_token(client_id, client_secret, scope):
    url = 'https://login.microsoftonline.com/'+ secrets["tenant_id"] +'/oauth2/v2.0/token'
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'scope': scope,
        'client_secret': client_secret
    }
    req = requests.post(url, data=payload)
    return req.json()['access_token']

# get access token
try:
    access_token = get_token(secrets["client_id"], secrets["client_secret"], 'https://graph.microsoft.com/.default')
except Exception as e:
    print("Error fetching access token")
    print("Error log -", e)
    access_token = None
    
# resource id of our app
resource_id = secrets["cai_nb_server_resource_id"]
# get all service principles (manifest of azuread)
try:
    serviceprincipal_url = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + resource_id
    service_principles_list = requests.get(serviceprincipal_url, headers={'Authorization': 'Bearer ' + access_token})
    approles = service_principles_list.json()['appRoles']
except Exception as e:
    print("Error fetching app roles")
    print("Error log -", e)
    approles = []
    
# get list of people assigned to so and so role ids
try:
    approleassign_url = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + resource_id + '/appRoleAssignedTo'
    approle_assign_list = requests.get(approleassign_url, headers={'Authorization': 'Bearer ' + access_token})
    approle_assigned_to = approle_assign_list.json()['value']
except Exception as e:
    print("Error fetching app assignments")
    print("Error log -", e)
    approle_assigned_to = []

# filter out name,scope and users assigned to a current approle in azure ad 
filterdict = {}
for role in approles:
    role_name = role['displayName']
    role_desc = role['description']
    role_id = role['id']
    role_value = role['value']
    for assign in approle_assigned_to:
        if 'appRoleId' in assign and assign['appRoleId'] == role_id:
            if role_name in filterdict:
                filterdict[role_name]['users'].append(assign['principalDisplayName'])
            else:
                filterdict[role_name] = {'name': role_name, 'scopes': [role_value], 'users': [assign['principalDisplayName']]}

# Final filtered roles list from dictionary to assign it to JupyterHub.load_roles .
filter_roles = []
for key, value in filterdict.items():
    filter_roles.append(value)


# idle culler service to kill idle user's servers
c.JupyterHub.services = [
    {
        "name": "jupyterhub-idle-culler-service",
        'command': [sys.executable, '-m', 'jupyterhub_idle_culler', '--timeout=7200']
    }
]

# create a role for idle culler to kill user's servers utilising idle culler service
filter_roles.append(
    {
        "name": "jupyterhub-idle-culler-role",
        "services": ["jupyterhub-idle-culler-service"],
        "scopes": ["admin:users", "list:users", "read:users:activity", "admin:servers",],
    }
)

# add final roles to jupyterhub roles.
c.JupyterHub.load_roles = filter_roles




# c.JupyterHub.authenticator_class = 'jhub_remote_user_authenticator.remote_user_auth.RemoteUserLocalAuthenticator'
# The base URL of the entire application.
#
#  Add this to the beginning of all JupyterHub URLs. Use base_url to run
#  JupyterHub within an existing website.
#
#  .. deprecated: 0.9
#      Use JupyterHub.bind_url
#c.JupyterHub.base_url = '/'

# The public facing URL of the whole JupyterHub application.
#
#  This is the address on which the proxy will bind. Sets protocol, ip, base_url
#c.JupyterHub.bind_url = 'http://:8000'

# Whether to shutdown the proxy when the Hub shuts down.
#
#  Disable if you want to be able to teardown the Hub while leaving the proxy
#  running.
#
#  Only valid if the proxy was starting by the Hub process.
#
#  If both this and cleanup_servers are False, sending SIGINT to the Hub will
#  only shutdown the Hub, leaving everything else running.
#
#  The Hub should be able to resume from database state.
#c.JupyterHub.cleanup_proxy = True

# Whether to shutdown single-user servers when the Hub shuts down.
#
#  Disable if you want to be able to teardown the Hub while leaving the single-
#  user servers running.
#
#  If both this and cleanup_proxy are False, sending SIGINT to the Hub will only
#  shutdown the Hub, leaving everything else running.
#
#  The Hub should be able to resume from database state.
#c.JupyterHub.cleanup_servers = True

# Maximum number of concurrent users that can be spawning at a time.
#
#  Spawning lots of servers at the same time can cause performance problems for
#  the Hub or the underlying spawning system. Set this limit to prevent bursts of
#  logins from attempting to spawn too many servers at the same time.
#
#  This does not limit the number of total running servers. See
#  active_server_limit for that.
#
#  If more than this many users attempt to spawn at a time, their requests will
#  be rejected with a 429 error asking them to try again. Users will have to wait
#  for some of the spawning services to finish starting before they can start
#  their own.
#
#  If set to 0, no limit is enforced.
#c.JupyterHub.concurrent_spawn_limit = 100

# The config file to load
#c.JupyterHub.config_file = 'jupyterhub_config.py'

# DEPRECATED: does nothing
#c.JupyterHub.confirm_no_ssl = False

# Number of days for a login cookie to be valid. Default is two weeks.
#c.JupyterHub.cookie_max_age_days = 14

# The cookie secret to use to encrypt cookies.
#
#  Loaded from the JPY_COOKIE_SECRET env variable by default.
#
#  Should be exactly 256 bits (32 bytes).
#c.JupyterHub.cookie_secret = b''

# File in which to store the cookie secret.
#c.JupyterHub.cookie_secret_file = 'jupyterhub_cookie_secret'

# The location of jupyterhub data files (e.g. /usr/local/share/jupyterhub)
#c.JupyterHub.data_files_path = '/Users/anubhavujjawal/Desktop/work/Couture/airflow-work/EDA/myenv/share/jupyterhub'

# Include any kwargs to pass to the database connection. See
#  sqlalchemy.create_engine for details.
#c.JupyterHub.db_kwargs = {}

# url for the database. e.g. `sqlite:///jupyterhub.sqlite`
c.JupyterHub.db_url = SQLALCHEMY_DATABASE_URI

# log all database transactions. This has A LOT of output
#c.JupyterHub.debug_db = False

# DEPRECATED since version 0.8: Use ConfigurableHTTPProxy.debug
#c.JupyterHub.debug_proxy = False

# If named servers are enabled, default name of server to spawn or open, e.g. by
#  user-redirect.
#c.JupyterHub.default_server_name = ''

# The default URL for users when they arrive (e.g. when user directs to "/")
#
#  By default, redirects users to their own server.
#c.JupyterHub.default_url = ''

# Dict authority:dict(files). Specify the key, cert, and/or ca file for an
#  authority. This is useful for externally managed proxies that wish to use
#  internal_ssl.
#
#  The files dict has this format (you must specify at least a cert)::
#
#      {
#          'key': '/path/to/key.key',
#          'cert': '/path/to/cert.crt',
#          'ca': '/path/to/ca.crt'
#      }
#
#  The authorities you can override: 'hub-ca', 'notebooks-ca', 'proxy-api-ca',
#  'proxy-client-ca', and 'services-ca'.
#
#  Use with internal_ssl
#c.JupyterHub.external_ssl_authorities = {}

# Register extra tornado Handlers for jupyterhub.
#
#  Should be of the form ``("<regex>", Handler)``
#
#  The Hub prefix will be added, so `/my-page` will be served at `/hub/my-page`.
#c.JupyterHub.extra_handlers = []

# DEPRECATED: use output redirection instead, e.g.
#
#  jupyterhub &>> /var/log/jupyterhub.log
#c.JupyterHub.extra_log_file = ''

# Extra log handlers to set on JupyterHub logger
#c.JupyterHub.extra_log_handlers = []

# Generate certs used for internal ssl
#c.JupyterHub.generate_certs = False

# Generate default config file
#c.JupyterHub.generate_config = False

# The URL on which the Hub will listen. This is a private URL for internal
#  communication. Typically set in combination with hub_connect_url. If a unix
#  socket, hub_connect_url **must** also be set.
#
#  For example:
#
#      "http://127.0.0.1:8081"
#      "unix+http://%2Fsrv%2Fjupyterhub%2Fjupyterhub.sock"
#
#  .. versionadded:: 0.9
#c.JupyterHub.hub_bind_url = ''

# The ip or hostname for proxies and spawners to use for connecting to the Hub.
#
#  Use when the bind address (`hub_ip`) is 0.0.0.0 or otherwise different from
#  the connect address.
#
#  Default: when `hub_ip` is 0.0.0.0, use `socket.gethostname()`, otherwise use
#  `hub_ip`.
#
#  Note: Some spawners or proxy implementations might not support hostnames.
#  Check your spawner or proxy documentation to see if they have extra
#  requirements.
#
#  .. versionadded:: 0.8
#c.JupyterHub.hub_connect_ip = ''

# DEPRECATED
#
#  Use hub_connect_url
#
#  .. versionadded:: 0.8
#
#  .. deprecated:: 0.9
#      Use hub_connect_url
#c.JupyterHub.hub_connect_port = 0

# The URL for connecting to the Hub. Spawners, services, and the proxy will use
#  this URL to talk to the Hub.
#
#  Only needs to be specified if the default hub URL is not connectable (e.g.
#  using a unix+http:// bind url).
#
#  .. seealso::
#      JupyterHub.hub_connect_ip
#      JupyterHub.hub_bind_url
#
#  .. versionadded:: 0.9
#c.JupyterHub.hub_connect_url = ''

# The ip address for the Hub process to *bind* to.
#
#  By default, the hub listens on localhost only. This address must be accessible
#  from the proxy and user servers. You may need to set this to a public ip or ''
#  for all interfaces if the proxy or user servers are in containers or on a
#  different host.
#
#  See `hub_connect_ip` for cases where the bind and connect address should
#  differ, or `hub_bind_url` for setting the full bind URL.
c.JupyterHub.hub_ip = '0.0.0.0'         #k8s

# The internal port for the Hub process.
#
#  This is the internal port of the hub itself. It should never be accessed
#  directly. See JupyterHub.port for the public port to use when accessing
#  jupyterhub. It is rare that this port should be set except in cases of port
#  conflict.
#
#  See also `hub_ip` for the ip and `hub_bind_url` for setting the full bind URL.
#c.JupyterHub.hub_port = 8081

# Timeout (in seconds) to wait for spawners to initialize
#
#  Checking if spawners are healthy can take a long time if many spawners are
#  active at hub start time.
#
#  If it takes longer than this timeout to check, init_spawner will be left to
#  complete in the background and the http server is allowed to start.
#
#  A timeout of -1 means wait forever, which can mean a slow startup of the Hub
#  but ensures that the Hub is fully consistent by the time it starts responding
#  to requests. This matches the behavior of jupyterhub 1.0.
#
#  .. versionadded: 1.1.0
c.JupyterHub.init_spawners_timeout = -1

# The location to store certificates automatically created by JupyterHub.
#
#  Use with internal_ssl
#c.JupyterHub.internal_certs_location = 'internal-ssl'

# Enable SSL for all internal communication
#
#  This enables end-to-end encryption between all JupyterHub components.
#  JupyterHub will automatically create the necessary certificate authority and
#  sign notebook certificates as they're created.
#c.JupyterHub.internal_ssl = False

# The public facing ip of the whole JupyterHub application (specifically
#  referred to as the proxy).
#
#  This is the address on which the proxy will listen. The default is to listen
#  on all interfaces. This is the only address through which JupyterHub should be
#  accessed by users.
#
#  .. deprecated: 0.9
#      Use JupyterHub.bind_url
c.JupyterHub.ip = os.environ['PROXY_PUBLIC_SERVICE_HOST']              #k8s

# Supply extra arguments that will be passed to Jinja environment.
#c.JupyterHub.jinja_environment_options = {}

# Interval (in seconds) at which to update last-activity timestamps.
c.JupyterHub.last_activity_interval = 60           #k8s

# Dict of 'group': ['usernames'] to load at startup.
#
#  This strictly *adds* groups and users to groups.
#
#  Loading one set of groups, then starting JupyterHub again with a different set
#  will not remove users or groups from previous launches. That must be done
#  through the API.
#c.JupyterHub.load_groups = {}

# Specify path to a logo image to override the Jupyter logo in the banner.
c.JupyterHub.logo_file = './exl_logo_rgb_orange_pos_94.png'

# Maximum number of concurrent named servers that can be created by a user at a
#  time.
#
#  Setting this can limit the total resources a user can consume.
#
#  If set to 0, no limit is enforced.
#c.JupyterHub.named_server_limit_per_user = 0

# File to write PID Useful for daemonizing JupyterHub.
#c.JupyterHub.pid_file = ''

# The public facing port of the proxy.
#
#  This is the port on which the proxy will listen. This is the only port through
#  which JupyterHub should be accessed by users.
#
#  .. deprecated: 0.9
#      Use JupyterHub.bind_url
c.JupyterHub.port = int(os.environ['PROXY_PUBLIC_SERVICE_PORT'])           #k8s

# DEPRECATED since version 0.8 : Use ConfigurableHTTPProxy.api_url
#c.JupyterHub.proxy_api_ip = ''

# DEPRECATED since version 0.8 : Use ConfigurableHTTPProxy.api_url
#c.JupyterHub.proxy_api_port = 0

# DEPRECATED since version 0.8: Use ConfigurableHTTPProxy.auth_token
#c.JupyterHub.proxy_auth_token = ''

# Interval (in seconds) at which to check if the proxy is running.
#c.JupyterHub.proxy_check_interval = 30

# The class to use for configuring the JupyterHub proxy.
#
#          Should be a subclass of :class:`jupyterhub.proxy.Proxy`.
#
#          .. versionchanged:: 1.0
#              proxies may be registered via entry points,
#              e.g. `c.JupyterHub.proxy_class = 'traefik'`
#
#  Currently installed:
#    - configurable-http-proxy: jupyterhub.proxy.ConfigurableHTTPProxy
#    - default: jupyterhub.proxy.ConfigurableHTTPProxy
#c.JupyterHub.proxy_class = 'jupyterhub.proxy.ConfigurableHTTPProxy'

# DEPRECATED since version 0.8. Use ConfigurableHTTPProxy.command
#c.JupyterHub.proxy_cmd = []

# Recreate all certificates used within JupyterHub on restart.
#
#  Note: enabling this feature requires restarting all notebook servers.
#
#  Use with internal_ssl
#c.JupyterHub.recreate_internal_certs = False

# Redirect user to server (if running), instead of control panel.
#c.JupyterHub.redirect_to_server = True

# Purge and reset the database.
#c.JupyterHub.reset_db = False

# Interval (in seconds) at which to check connectivity of services with web
#  endpoints.
#c.JupyterHub.service_check_interval = 60

# Dict of token:servicename to be loaded into the database.
#
#  Allows ahead-of-time generation of API tokens for use by externally managed
#  services.
#c.JupyterHub.service_tokens = {}

# List of service specification dictionaries.
#
#  A service
#
#  For instance::
#
#      services = [
#          {
#              'name': 'cull_idle',
#              'command': ['/path/to/cull_idle_servers.py'],
#          },
#          {
#              'name': 'formgrader',
#              'url': 'http://127.0.0.1:1234',
#              'api_token': 'super-secret',
#              'environment':
#          }
#      ]
#c.JupyterHub.services = []

# Shuts down all user servers on logout
#c.JupyterHub.shutdown_on_logout = False

# The class to use for spawning single-user servers.
#
#          Should be a subclass of :class:`jupyterhub.spawner.Spawner`.
#
#          .. versionchanged:: 1.0
#              spawners may be registered via entry points,
#              e.g. `c.JupyterHub.spawner_class = 'localprocess'`
#
#  Currently installed:
#    - default: jupyterhub.spawner.LocalProcessSpawner:
#    - localprocess: jupyterhub.spawner.LocalProcessSpawner
#    - simple: jupyterhub.spawner.SimpleLocalProcessSpawner
# DockerSpawner.get_env = types.MethodType(get_env, DockerSpawner)


###k8s###c.JupyterHub.spawner_class = DockerSpawner
c.JupyterHub.spawner_class = 'kubespawner.KubeSpawner' #k8s
c.ConfigurableHTTPProxy.auth_token = CONFIGPROXY_AUTH_TOKEN # Set ConfigurableHTTPProxy Auth-Token 
c.ConfigurableHTTPProxy.api_url = 'http://{}:{}'.format(os.environ['PROXY_API_SERVICE_HOST'], int(os.environ['PROXY_API_SERVICE_PORT']))           #k8s
c.ConfigurableHTTPProxy.should_start = False            #k8s
c.KubeSpawner.image = os.environ.get("SPAWNER_IMAGE", "532019373627.dkr.ecr.us-east-1.amazonaws.com/cai-nb-spawner:1.0.0")
c.KubeSpawner.service_account = "cai-nb-hub"


# c.KubeSpawner.extra_annotations = {"sidecar.istio.io/inject": "false"}
# Mount volume for storage k8s
pvc_name_template = 'claim-{username}'
c.KubeSpawner.pvc_name_template = pvc_name_template
volume_name_template = 'volume-{username}'

c.KubeSpawner.storage_pvc_ensure = True
c.KubeSpawner.storage_class = 'efs-sc'
c.KubeSpawner.storage_access_modes = ['ReadWriteMany']
c.KubeSpawner.storage_capacity = '200Mi'

# Add volumes to singleuser pods
c.KubeSpawner.volumes = [
   {
       'name': volume_name_template,
       'persistentVolumeClaim': {
           'claimName': pvc_name_template
       }
   }
]
c.KubeSpawner.volume_mounts = [
   {
       'mountPath': '/home/jovyan/work',
       'name': volume_name_template
   }
]




# Path to SSL certificate file for the public facing interface of the proxy
#
#  When setting this, you should also set ssl_key
#c.JupyterHub.ssl_cert = ''

# Path to SSL key file for the public facing interface of the proxy
#
#  When setting this, you should also set ssl_cert
#c.JupyterHub.ssl_key = ''

# Host to send statsd metrics to. An empty string (the default) disables sending
#  metrics.
#c.JupyterHub.statsd_host = ''

# Port on which to send statsd metrics about the hub
#c.JupyterHub.statsd_port = 8125

# Prefix to use for all metrics sent by jupyterhub to statsd
#c.JupyterHub.statsd_prefix = 'jupyterhub'

# Run single-user servers on subdomains of this host.
#
#  This should be the full `https://hub.domain.tld[:port]`.
#
#  Provides additional cross-site protections for javascript served by single-
#  user servers.
#
#  Requires `<username>.hub.domain.tld` to resolve to the same host as
#  `hub.domain.tld`.
#
#  In general, this is most easily achieved with wildcard DNS.
#
#  When using SSL (i.e. always) this also requires a wildcard SSL certificate.
#c.JupyterHub.subdomain_host = ''

# Paths to search for jinja templates, before using the default templates.
#c.JupyterHub.template_paths = []

# Extra variables to be passed into jinja templates
#c.JupyterHub.template_vars = {}

# Extra settings overrides to pass to the tornado application.
#c.JupyterHub.tornado_settings = {}

# Trust user-provided tokens (via JupyterHub.service_tokens) to have good
#  entropy.
#
#  If you are not inserting additional tokens via configuration file, this flag
#  has no effect.
#
#  In JupyterHub 0.8, internally generated tokens do not pass through additional
#  hashing because the hashing is costly and does not increase the entropy of
#  already-good UUIDs.
#
#  User-provided tokens, on the other hand, are not trusted to have good entropy
#  by default, and are passed through many rounds of hashing to stretch the
#  entropy of the key (i.e. user-provided tokens are treated as passwords instead
#  of random keys). These keys are more costly to check.
#
#  If your inserted tokens are generated by a good-quality mechanism, e.g.
#  `openssl rand -hex 32`, then you can set this flag to True to reduce the cost
#  of checking authentication tokens.
#c.JupyterHub.trust_user_provided_tokens = False

# Names to include in the subject alternative name.
#
#  These names will be used for server name verification. This is useful if
#  JupyterHub is being run behind a reverse proxy or services using ssl are on
#  different hosts.
#
#  Use with internal_ssl
#c.JupyterHub.trusted_alt_names = []

# Downstream proxy IP addresses to trust.
#
#  This sets the list of IP addresses that are trusted and skipped when
#  processing the `X-Forwarded-For` header. For example, if an external proxy is
#  used for TLS termination, its IP address should be added to this list to
#  ensure the correct client IP addresses are recorded in the logs instead of the
#  proxy server's IP address.
#c.JupyterHub.trusted_downstream_ips = []

# Upgrade the database automatically on start.
#
#  Only safe if database is regularly backed up. Only SQLite databases will be
#  backed up to a local file automatically.
#c.JupyterHub.upgrade_db = False

# Callable to affect behavior of /user-redirect/
#
#  Receives 4 parameters: 1. path - URL path that was provided after /user-
#  redirect/ 2. request - A Tornado HTTPServerRequest representing the current
#  request. 3. user - The currently authenticated user. 4. base_url - The
#  base_url of the current hub, for relative redirects
#
#  It should return the new URL to redirect to, or None to preserve current
#  behavior.
#c.JupyterHub.user_redirect_hook = None

# ------------------------------------------------------------------------------
# Spawner(LoggingConfigurable) configuration
# ------------------------------------------------------------------------------

# Base class for spawning single-user notebook servers.
#
#  Subclass this, and override the following methods:
#
#  - load_state - get_state - start - stop - poll
#
#  As JupyterHub supports multiple users, an instance of the Spawner subclass is
#  created for each user. If there are 20 JupyterHub users, there will be 20
#  instances of the subclass.

# Extra arguments to be passed to the single-user server.
#
#  Some spawners allow shell-style expansion here, allowing you to use
#  environment variables here. Most, including the default, do not. Consult the
#  documentation for your spawner to verify!
#c.Spawner.args = []

# An optional hook function that you can implement to pass `auth_state` to the
#  spawner after it has been initialized but before it starts. The `auth_state`
#  dictionary may be set by the `.authenticate()` method of the authenticator.
#  This hook enables you to pass some or all of that information to your spawner.
#
#  Example::
#
#      def userdata_hook(spawner, auth_state):
#          spawner.userdata = auth_state["userdata"]
#
#      c.Spawner.auth_state_hook = userdata_hook
#c.Spawner.auth_state_hook = None

# The command used for starting the single-user server.
#
#  Provide either a string or a list containing the path to the startup script
#  command. Extra arguments, other than this path, should be provided via `args`.
#
#  This is usually set if you want to start the single-user server in a different
#  python environment (with virtualenv/conda) than JupyterHub itself.
#
#  Some spawners allow shell-style expansion here, allowing you to use
#  environment variables. Most, including the default, do not. Consult the
#  documentation for your spawner to verify!
#c.Spawner.cmd = ['jupyterhub-singleuser']

# Maximum number of consecutive failures to allow before shutting down
#  JupyterHub.
#
#  This helps JupyterHub recover from a certain class of problem preventing
#  launch in contexts where the Hub is automatically restarted (e.g. systemd,
#  docker, kubernetes).
#
#  A limit of 0 means no limit and consecutive failures will not be tracked.
#c.Spawner.consecutive_failure_limit = 0

# Minimum number of cpu-cores a single-user notebook server is guaranteed to
#  have available.
#
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.cpu_guarantee = None

# Maximum number of cpu-cores a single-user notebook server is allowed to use.
#
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#
#  The single-user notebook server will never be scheduled by the kernel to use
#  more cpu-cores than this. There is no guarantee that it can access this many
#  cpu-cores.
#
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.cpu_limit = None

# Enable debug-logging of the single-user server

# c.Spawner.debug = True
c.KubeSpawner.debug = True    #k8s

# The URL the single-user server should start in.
#
#  `{username}` will be expanded to the user's username
#
#  Example uses:
#
#  - You can set `notebook_dir` to `/` and `default_url` to `/tree/home/{username}` to allow people to
#    navigate the whole filesystem from their notebook server, but still start in their home directory.
#  - Start with `/notebooks` instead of `/tree` if `default_url` points to a notebook instead of a directory.
#  - You can set this to `/lab` to have JupyterLab start by default, rather than Jupyter Notebook.
# c.Spawner.default_url = '/lab'

c.KubeSpawner.default_url = '/lab'   #k8s

# Disable per-user configuration of single-user servers.
#
#  When starting the user's single-user server, any config file found in the
#  user's $HOME directory will be ignored.
#
#  Note: a user could circumvent this if the user modifies their Python
#  environment, such as when they have their own conda environments / virtualenvs
#  / containers.
# c.Spawner.disable_user_config = False
c.KubeSpawner.disable_user_config = False  #k8s
# Whitelist of environment variables for the single-user server to inherit from
#  the JupyterHub process.
#
#  This whitelist is used to ensure that sensitive information in the JupyterHub
#  process's environment (such as `CONFIGPROXY_AUTH_TOKEN`) is not passed to the
#  single-user server's process.
#c.Spawner.env_keep = ['PATH', 'PYTHONPATH', 'CONDA_ROOT', 'CONDA_DEFAULT_ENV', 'VIRTUAL_ENV', 'LANG', 'LC_ALL']

# Extra environment variables to set for the single-user server's process.
#
#  Environment variables that end up in the single-user server's process come from 3 sources:
#    - This `environment` configurable
#    - The JupyterHub process' environment variables that are whitelisted in `env_keep`
#    - Variables to establish contact between the single-user notebook and the hub (such as JUPYTERHUB_API_TOKEN)
#
#  The `environment` configurable should be set by JupyterHub administrators to
#  add installation specific environment variables. It is a dict where the key is
#  the name of the environment variable, and the value can be a string or a
#  callable. If it is a callable, it will be called with one parameter (the
#  spawner instance), and should return a string fairly quickly (no blocking
#  operations please!).
#
#  Note that the spawner class' interface is not guaranteed to be exactly same
#  across upgrades, so if you are using the callable take care to verify it
#  continues to work after upgrades!
#c.Spawner.environment = {}

# Timeout (in seconds) before giving up on a spawned HTTP server
#
#  Once a server has successfully been spawned, this is the amount of time we
#  wait before assuming that the server is unable to accept connections.

# c.Spawner.http_timeout = 300

c.KubeSpawner.http_timeout = 300  #k8s

# The IP address (or hostname) the single-user server should listen on.
#
#  The JupyterHub proxy implementation should be able to send packets to this
#  interface.
#c.Spawner.ip = ''

# Minimum number of bytes a single-user notebook server is guaranteed to have
#  available.
#
#  Allows the following suffixes:
#    - K -> Kilobytes
#    - M -> Megabytes
#    - G -> Gigabytes
#    - T -> Terabytes
#
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.mem_guarantee = None

# Maximum number of bytes a single-user notebook server is allowed to use.
#
#  Allows the following suffixes:
#    - K -> Kilobytes
#    - M -> Megabytes
#    - G -> Gigabytes
#    - T -> Terabytes
#
#  If the single user server tries to allocate more memory than this, it will
#  fail. There is no guarantee that the single-user notebook server will be able
#  to allocate this much memory - only that it can not allocate more than this.
#
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.mem_limit = None


# c.Spawner.mem_limit = MEM_LIMIT
c.KubeSpawner.mem_limit = MEM_LIMIT

# Path to the notebook directory for the single-user server.
#
#  The user sees a file listing of this directory when the notebook interface is
#  started. The current interface does not easily allow browsing beyond the
#  subdirectories in this directory's tree.
#
#  `~` will be expanded to the home directory of the user, and {username} will be
#  replaced with the name of the user.
#
#  Note that this does *not* prevent users from accessing files outside of this
#  path! They can do so with many other means.
#c.Spawner.notebook_dir = ''

# An HTML form for options a user can specify on launching their server.
#
#  The surrounding `<form>` element and the submit button are already provided.
#
#  For example:
#
#  .. code:: html
#
#      Set your key:
#      <input name="key" val="default_key"></input>
#      <br>
#      Choose a letter:
#      <select name="letter" multiple="true">
#        <option value="A">The letter A</option>
#        <option value="B">The letter B</option>
#      </select>
#
#  The data from this form submission will be passed on to your spawner in
#  `self.user_options`
#
#  Instead of a form snippet string, this could also be a callable that takes as
#  one parameter the current spawner instance and returns a string. The callable
#  will be called asynchronously if it returns a future, rather than a str. Note
#  that the interface of the spawner class is not deemed stable across versions,
#  so using this functionality might cause your JupyterHub upgrades to break.
#c.Spawner.options_form = traitlets.Undefined

# Interval (in seconds) on which to poll the spawner for single-user server's
#  status.
#
#  At every poll interval, each spawner's `.poll` method is called, which checks
#  if the single-user server is still running. If it isn't running, then
#  JupyterHub modifies its own state accordingly and removes appropriate routes
#  from the configurable proxy.
#c.Spawner.poll_interval = 30

# The port for single-user servers to listen on.
#
#  Defaults to `0`, which uses a randomly allocated port number each time.
#
#  If set to a non-zero value, all Spawners will use the same port, which only
#  makes sense if each server is on a different address, e.g. in containers.
#
#  New in version 0.7.
#c.Spawner.port = 0

# An optional hook function that you can implement to do work after the spawner
#  stops.
#
#  This can be set independent of any concrete spawner implementation.
#c.Spawner.post_stop_hook = None

# An optional hook function that you can implement to do some bootstrapping work
#  before the spawner starts. For example, create a directory for your user or
#  load initial content.
#
#  This can be set independent of any concrete spawner implementation.
#
#  This maybe a coroutine.
#
#  Example::
#
#      from subprocess import check_call
#      def my_hook(spawner):
#          username = spawner.user.name
#          check_call(['./examples/bootstrap-script/bootstrap.sh', username])
#
#      c.Spawner.pre_spawn_hook = my_hook
#c.Spawner.pre_spawn_hook = None

# List of SSL alt names
#
#  May be set in config if all spawners should have the same value(s), or set at
#  runtime by Spawner that know their names.
#c.Spawner.ssl_alt_names = []

# Whether to include DNS:localhost, IP:127.0.0.1 in alt names
#c.Spawner.ssl_alt_names_include_local = True

# Timeout (in seconds) before giving up on starting of single-user server.
#
#  This is the timeout for start to return, not the timeout for the server to
#  respond. Callers of spawner.start will assume that startup has failed if it
#  takes longer than this. start should return when the server process is started
#  and its location is known.

#c.Spawner.start_timeout = 300
c.KubeSpawner.start_timeout = 300   #K8s

# ------------------------------------------------------------------------------
# Authenticator(LoggingConfigurable) configuration
# ------------------------------------------------------------------------------

# Base class for implementing an authentication provider for JupyterHub

# Set of users that will have admin rights on this JupyterHub.
#
#  Admin users have extra privileges:
#   - Use the admin panel to see list of users logged in
#   - Add / remove users in some authenticators
#   - Restart / halt the hub
#   - Start / stop users' single-user servers
#   - Can access each individual users' single-user server (if configured)
#
#  Admin access should be treated the same way root access is.
#
#  Defaults to an empty set, in which case no user has admin access.
#c.Authenticator.admin_users = set()

# The max age (in seconds) of authentication info before forcing a refresh of
#  user auth info.
#
#  Refreshing auth info allows, e.g. requesting/re-validating auth tokens.
#
#  See :meth:`.refresh_user` for what happens when user auth info is refreshed
#  (nothing by default).
#c.Authenticator.auth_refresh_age = 300

# Automatically begin the login process
#
#  rather than starting with a "Login with..." link at `/hub/login`
#
#  To work, `.login_url()` must give a URL other than the default `/hub/login`,
#  such as an oauth handler or another automatic login handler, registered with
#  `.get_handlers()`.
#
#  .. versionadded:: 0.8
#c.Authenticator.auto_login = False

# Blacklist of usernames that are not allowed to log in.
#
#  Use this with supported authenticators to restrict which users can not log in.
#  This is an additional blacklist that further restricts users, beyond whatever
#  restrictions the authenticator has in place.
#
#  If empty, does not perform any additional restriction.
#
#  .. versionadded: 0.9
#c.Authenticator.blacklist = set()

# Enable persisting auth_state (if available).
#
#  auth_state will be encrypted and stored in the Hub's database. This can
#  include things like authentication tokens, etc. to be passed to Spawners as
#  environment variables.
#
#  Encrypting auth_state requires the cryptography package.
#
#  Additionally, the JUPYTERHUB_CRYPT_KEY environment variable must contain one
#  (or more, separated by ;) 32B encryption keys. These can be either base64 or
#  hex-encoded.
#
#  If encryption is unavailable, auth_state cannot be persisted.
#
#  New in JupyterHub 0.8
#c.Authenticator.enable_auth_state = False

# An optional hook function that you can implement to do some bootstrapping work
#  during authentication. For example, loading user account details from an
#  external system.
#
#  This function is called after the user has passed all authentication checks
#  and is ready to successfully authenticate. This function must return the
#  authentication dict reguardless of changes to it.
#
#  This maybe a coroutine.
#
#  .. versionadded: 1.0
#
#  Example::
#
#      import os, pwd
#      def my_hook(authenticator, handler, authentication):
#          user_data = pwd.getpwnam(authentication['name'])
#          spawn_data = {
#              'pw_data': user_data
#              'gid_list': os.getgrouplist(authentication['name'], user_data.pw_gid)
#          }
#
#          if authentication['auth_state'] is None:
#              authentication['auth_state'] = {}
#          authentication['auth_state']['spawn_data'] = spawn_data
#
#          return authentication
#
#      c.Authenticator.post_auth_hook = my_hook
#c.Authenticator.post_auth_hook = None

# Force refresh of auth prior to spawn.
#
#  This forces :meth:`.refresh_user` to be called prior to launching a server, to
#  ensure that auth state is up-to-date.
#
#  This can be important when e.g. auth tokens that may have expired are passed
#  to the spawner via environment variables from auth_state.
#
#  If refresh_user cannot refresh the user auth data, launch will fail until the
#  user logs in again.
#c.Authenticator.refresh_pre_spawn = False

# Dictionary mapping authenticator usernames to JupyterHub users.
#
#  Primarily used to normalize OAuth user names to local users.
#c.Authenticator.username_map = {}

# Regular expression pattern that all valid usernames must match.
#
#  If a username does not match the pattern specified here, authentication will
#  not be attempted.
#
#  If not set, allow any username.
#c.Authenticator.username_pattern = ''

# Whitelist of usernames that are allowed to log in.
#
#  Use this with supported authenticators to restrict which users can log in.
#  This is an additional whitelist that further restricts users, beyond whatever
#  restrictions the authenticator has in place.
#
#  If empty, does not perform any additional restriction.
#c.Authenticator.whitelist = set()

# ------------------------------------------------------------------------------
# CryptKeeper(SingletonConfigurable) configuration
# ------------------------------------------------------------------------------

# Encapsulate encryption configuration
#
#  Use via the encryption_config singleton below.

##
#c.CryptKeeper.keys = []

# The number of threads to allocate for encryption
#c.CryptKeeper.n_threads = 4
# the hostname/ip that should be used to connect to the hub
# this is usually the hub container's name
##k8s##c.JupyterHub.hub_connect_ip = 'workflow-jupyter'

# c.JupyterHub.hub_connect_url = 'http://{host}:{port}'.format(
#     host=os.environ['HUB_SERVICE_HOST'],
#     port=os.environ['HUB_SERVICE_PORT']
# )

c.JupyterHub.hub_connect_ip = os.environ['HUB_SERVICE_HOST']      #k8s
c.JupyterHub.hub_connect_port = int(os.environ['HUB_SERVICE_PORT'])          #k8s


# tell the user containers to connect to our docker network
# c.DockerSpawner.network_name = 'workflow-network'
# c.DockerSpawner.notebook_dir = NOTEBOOK_DIR
# c.DockerSpawner.volumes = {
#     'jupyter' : NOTEBOOK_DIR ,
#     'configs' : str(Path(CONFIGS_DIR).parent),
#     SETUP_VOLUME_NAME: SETUP_VOLUME_PATH,
#     CODE_ARTIFACT_VOLUME_NAME: CODE_ARTIFACT_VOLUME_PATH,
#     'model-servers': MODEL_SERVERS_VOLUME_PATH
# }
# c.DockerSpawner.image = DOCKER_SPAWNER_IMAGE

# # delete containers when the stop
# c.DockerSpawner.remove = True

# c.DockerSpawner.get_env = types.MethodType(get_env, c.DockerSpawner)

# c.DockerSpawner.environment = get_notebook_env()
# c.Spawner.args = [f'--NotebookApp.allow_origin=*']
# c.JupyterHub.tornado_settings = {
#     'headers': {
#         'Content-Security-Policy': "frame-ancestors * 'self' ",
#         # 'Access-Control-Allow-Origin': '*',
#         # 'Access-Control-Allow-Headers': '*'
#     }
# }
# c.NotebookApp.tornado_settings = {
#     'headers': {
#         'Content-Security-Policy': "frame-ancestors * 'self' ",
#         # 'Access-Control-Allow-Origin': '*',
#         # 'Access-Control-Allow-Headers': '*'
#     }
# }

# TODO: Check security concerns here.

#c.Spawner.args = ['--NotebookApp.tornado_settings={"headers":{"Content-Security-Policy": "frame-ancestors * "}}']
c.KubeSpawner.args = ['--NotebookApp.tornado_settings={"headers":{"Content-Security-Policy": "frame-ancestors * "}}']

c.JupyterHub.tornado_settings = { 'headers': { 'Content-Security-Policy': "frame-ancestors * 'self' "} }

# https://jupyterhub.readthedocs.io/en/stable/getting-started/services-basics.html?highlight=cull#configure-cull-idle-to-run-as-a-hub-managed-service
# culling out idle notebook servers
# c.JupyterHub.services = [
#     {
#         'name': 'cull-idle',
#         'admin': True,
#         'command': [sys.executable, 'cull_idle_servers.py', f'--timeout={CULL_TIMEOUT}'],
#     }
# ]
