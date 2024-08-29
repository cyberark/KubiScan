import json
import yaml
import os
from base_client_api import BaseApiClient

class StaticApiClient(BaseApiClient):
    def __init__(self, input_file):
        self.combined_data = self._load_combined_file(input_file)
        self.all_roles =self.get_resources('Role')
        self.all_cluster_roles = self.get_resources('ClusterRole')
        self.ll_role_bindings = self.get_resources('RoleBinding')
        self.all_cluster_role_bindings = self.get_resources('ClusterRoleBinding')
        self.all_secrets =self.get_resources('Secret')
        self.all_pods = self.get_resources('Pod')

    def _load_combined_file(self, input_file):
        # Determine the file format based on the file extension
        _, file_extension = os.path.splitext(input_file)
        file_format = 'json' if file_extension.lower() == '.json' else 'yaml' if file_extension.lower() == '.yaml' else None
        
        if not file_format:
            print("Unsupported file extension. Only '.yaml' and '.json' are supported.")
            return None

        try:
            with open(input_file, 'r') as file:
                if file_format == "yaml":
                    return yaml.safe_load(file)
                elif file_format == "json":
                    return json.load(file)
        except FileNotFoundError:
            print(f"File not found: {input_file}")
            return None
        except Exception as e:
            print(f"Error reading file: {e}")
            return None

    def get_resources(self, kind):
        try:
            # Initialize an empty list to collect the resources of the specified kind.
            resources = []

            # Since combined_data is a list of dictionaries, each containing an 'items' key.
            for entry in self.combined_data:
                # Check if 'items' key exists and it contains a list of dictionaries.
                if 'items' in entry and isinstance(entry['items'], list):
                    # Extend the list of resources with those that match the specified 'kind'.
                    resources.extend(item for item in entry['items'] if item.get('kind') == kind)
            return resources

        except TypeError:  # Catch type errors if data structures are not as expected
            print("Error processing data. Check the structure of the JSON file.")
            return []
        
    def list_roles_for_all_namespaces(self):
        return self.all_roles


# Example usage
#static_api_client = StaticApiClient(input_file="C:\\Users\\noamr\\Documents\\GitHub\\KubiScan\\combined.json")
#print(len(static_api_client.all_secrets))
