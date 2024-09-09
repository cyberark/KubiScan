import json
import yaml
import os
from .base_client_api import BaseApiClient
from kubernetes.client import V1RoleList, V1Role, V1ObjectMeta, V1PolicyRule, V1RoleBinding, V1RoleRef, V1Subject, V1RoleBindingList

class StaticApiClient(BaseApiClient):
    def __init__(self, input_file):
        self.combined_data = self.load_combined_file(input_file)
        self.all_roles = self.construct_v1_role_list("Role", self.get_resources('Role'))
        self.all_cluster_roles = self.construct_v1_role_list("ClusterRole", self.get_resources('ClusterRole'))
        self.all_role_bindings = self.construct_v1_role_binding_list("RoleBinding", self.get_resources('RoleBinding'))
        self.all_cluster_role_bindings = self.construct_v1_role_binding_list("ClusterRoleBinding", self.get_resources('ClusterRoleBinding'))
        self.all_secrets = self.construct_v1_role_list("Secret", self.get_resources('Secret'))
        self.all_pods = self.construct_v1_role_list("Pod", self.get_resources('Pod'))

    def load_combined_file(self, input_file):
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
        resources = []
        if self.combined_data:
            for entry in self.combined_data:
                if 'items' in entry and isinstance(entry['items'], list):
                    resources.extend(item for item in entry['items'] if item.get('kind') == kind)
        return resources

    def construct_v1_role_list(self, kind, items):
        v1_roles = []
        for item in items:
            v1_role = V1Role(
                api_version=item['apiVersion'],
                kind=item['kind'],
                metadata=V1ObjectMeta(
                    name=item['metadata']['name'],
                    namespace=item['metadata'].get('namespace')
                ),
               rules=[
                    V1PolicyRule(
                        api_groups=rule.get('apiGroups', []),  # Provide a default empty list if 'apiGroups' is missing
                        resources=rule.get('resources', []),  # Provide a default empty list if 'resources' is missing
                        verbs=rule.get('verbs', []),  # Provide a default empty list if 'verbs' is missing
                        resource_names=rule.get('resourceNames', [])  # Provide a default empty list if 'resourceNames' is missing
                    ) for rule in item.get('rules', [])  # Provide a default empty list if 'rules' is missing
                ]
            )
            v1_roles.append(v1_role)
        
        return V1RoleList(
            api_version="rbac.authorization.k8s.io/v1",
            kind=f"{kind}List",
            items=v1_roles,
            metadata={'resourceVersion': '1'}
        )
    
    def construct_v1_role_binding_list(self, kind, items):
        v1_role_bindings = []
        for item in items:
            v1_role_binding = V1RoleBinding(
                api_version=item['apiVersion'],
                kind=item['kind'],
                metadata=V1ObjectMeta(
                    name=item['metadata']['name'],
                    namespace=item['metadata'].get('namespace')
                ),
                subjects=[
                    V1Subject(
                        kind=subject.get('kind'),
                        name=subject.get('name'),
                        namespace=subject.get('namespace')
                    ) for subject in item.get('subjects', [])
                ],
                role_ref=V1RoleRef(
                    api_group=item['roleRef'].get('apiGroup'),
                    kind=item['roleRef'].get('kind'),
                    name=item['roleRef'].get('name')
                )
            )
            v1_role_bindings.append(v1_role_binding)

        return V1RoleBindingList(
            api_version="rbac.authorization.k8s.io/v1",
            kind=f"{kind}List",
            items=v1_role_bindings,
            metadata={'resourceVersion': '1'}
        )
    
    def list_roles_for_all_namespaces(self):
        return self.all_roles
    
    def list_cluster_role(self):
        return self.all_cluster_roles
    
    def list_role_binding_for_all_namespaces(self):
        return self.all_role_bindings
   
    def list_cluster_role_binding(self):
        return self.all_cluster_role_bindings.items
