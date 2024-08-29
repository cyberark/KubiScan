from .static_api_client import StaticApiClient
from .api_client import RegularApiClient

class ApiClientFactory:
    @staticmethod
    def get_client(use_static=False, input_file=None):
        if use_static:
            return StaticApiClient(input_file=input_file)
        else:
            return RegularApiClient()


#api_client = ApiClientFactory.get_client(use_static=True, input_file="/home/noamr/Documents/KubiScan/combined.json")
#api_client = ApiClientFactory.get_client()
#print(api_client.list_roles_for_all_namespaces())