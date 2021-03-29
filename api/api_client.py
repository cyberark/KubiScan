from kubernetes import client, config
from shutil import copyfile
import os
from tempfile import mkstemp
from shutil import move
from kubernetes.client.configuration import Configuration
from kubernetes.client.api_client import ApiClient

# TODO: Should be removed after the bug will be solved:
# https://github.com/kubernetes-client/python/issues/577
from api.api_client_temp import ApiClientTemp

# The following variables have been commented as it resulted a bug when running `kubiscan -h`
# Exception ignored in: <bound method ApiClient.__del__ of <kubernetes.client.api_client.ApiClient object ...
# It is related to https://github.com/kubernetes-client/python/issues/411 w
#api_temp = ApiClientTemp()
#CoreV1Api = client.CoreV1Api()
#RbacAuthorizationV1Api = client.RbacAuthorizationV1Api()

api_temp = None
CoreV1Api = None
RbacAuthorizationV1Api = None

def running_in_docker_container():
    if os.path.isfile('/proc/self/cgroup'):
        with open('/proc/self/cgroup', 'r') as procfile:
            for line in procfile:
                fields = line.strip().split('/')
                if 'docker' in fields or '/docker-' in line:
                    return True
    return False

def replace(file_path, pattern, subst):
    #Create temp file
    fh, abs_path = mkstemp()
    with os.fdopen(fh,'w') as new_file:
        with open(file_path) as old_file:
            for line in old_file:
                if pattern in line:
                   new_file.write(line.replace(pattern, subst))
                else:
                   new_file.write(line)
    #Remove original file
    os.remove(file_path)
    #Move new file
    move(abs_path, file_path)

def api_init(host=None, token_filename=None, cert_filename=None, context=None):
    global CoreV1Api
    global RbacAuthorizationV1Api
    global api_temp

    if host and token_filename:
        # remotely
        token_filename = os.path.abspath(token_filename)
        if cert_filename:
            cert_filename = os.path.abspath(cert_filename)
        BearerTokenLoader(host=host, token_filename=token_filename, cert_filename=cert_filename).load_and_set()

        CoreV1Api = client.CoreV1Api()
        RbacAuthorizationV1Api = client.RbacAuthorizationV1Api()
        api_temp = ApiClientTemp()

    else:
        configuration = Configuration()
        api_client = ApiClient()
        if running_in_docker_container():
            # TODO: Consider using config.load_incluster_config() from container created by Kubernetes. Required service account with privileged permissions.
            # Must have mounted volume
            container_volume_prefix = '/tmp'
            kube_config_bak_path = '/KubiScan/config_bak'
            if not os.path.isfile(kube_config_bak_path):
                copyfile(container_volume_prefix + os.path.expandvars('$CONF_PATH'), kube_config_bak_path)
                replace(kube_config_bak_path, ': /', ': /tmp/')

            config.load_kube_config(kube_config_bak_path, context=context, client_configuration=configuration)
        else:
            config.load_kube_config(context=context, client_configuration=configuration)

        api_client = ApiClient(configuration=configuration)
        CoreV1Api = client.CoreV1Api(api_client=api_client)
        RbacAuthorizationV1Api = client.RbacAuthorizationV1Api(api_client=api_client)
        api_temp = ApiClientTemp(configuration=configuration)

class BearerTokenLoader(object):
    def __init__(self, host, token_filename, cert_filename=None):
        self._token_filename = token_filename
        self._cert_filename = cert_filename
        self._host = host
        self._verify_ssl = True

        if not self._cert_filename:
            self._verify_ssl = False

    def load_and_set(self):
        self._load_config()
        self._set_config()

    def _load_config(self):
        self._host = "https://" + self._host

        if not os.path.isfile(self._token_filename):
            raise Exception("Service token file does not exists.")

        with open(self._token_filename) as f:
            self.token = f.read().rstrip('\n')
            if not self.token:
                raise Exception("Token file exists but empty.")

        if self._cert_filename:
            if not os.path.isfile(self._cert_filename):
                raise Exception(
                    "Service certification file does not exists.")

            with open(self._cert_filename) as f:
                if not f.read().rstrip('\n'):
                    raise Exception("Cert file exists but empty.")

        self.ssl_ca_cert = self._cert_filename

    def _set_config(self):
        configuration = client.Configuration()
        configuration.host = self._host
        configuration.ssl_ca_cert = self.ssl_ca_cert
        configuration.verify_ssl = self._verify_ssl
        configuration.api_key['authorization'] = "bearer " + self.token
        client.Configuration.set_default(configuration)
