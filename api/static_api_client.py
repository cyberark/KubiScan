import json
import yaml
import os
from datetime import datetime
from .base_client_api import BaseApiClient
from kubernetes.client import (
    V1VolumeProjection, V1ServiceAccountTokenProjection, V1SecretProjection, V1DownwardAPIProjection, 
    V1RoleList, V1Role, V1ObjectMeta, V1PolicyRule, V1RoleBinding, V1RoleRef, V1Subject, 
    V1RoleBindingList, V1PodList, V1Pod, V1PodSpec, V1Container, V1Volume, V1PodStatus, 
    V1SecurityContext, V1HostPathVolumeSource, V1ProjectedVolumeSource,V1VolumeMount,V1ConfigMapProjection,
    V1DownwardAPIVolumeFile,V1ObjectFieldSelector,V1ContainerStatus,V1Capabilities,V1PodSecurityContext,V1ContainerPort
)

class StaticApiClient(BaseApiClient):
    def __init__(self, input_file):
        self.combined_data = self.load_combined_file(input_file)
        self.all_roles = self.construct_v1_role_list("Role", self.get_resources('Role'))
        self.all_cluster_roles = self.construct_v1_role_list("ClusterRole", self.get_resources('ClusterRole'))
        self.all_role_bindings = self.construct_v1_role_binding_list("RoleBinding", self.get_resources('RoleBinding'))
        self.all_cluster_role_bindings = self.construct_v1_role_binding_list("ClusterRoleBinding", self.get_resources('ClusterRoleBinding'))
        self.all_pods = self.construct_v1_pod_list("Pod", self.get_resources('Pod'))

    def load_combined_file(self, input_file):
        _, file_extension = os.path.splitext(input_file)
        file_format = 'json' if file_extension.lower() == '.json' else 'yaml' if file_extension.lower() == '.yaml' else None
        
        if not file_format:
            print("Unsupported file extension. Only '.yaml' and '.json' are supported.")
            return None

        try:
            with open(input_file, 'r') as file:
                if file_format == "yaml":
                    documents = list(yaml.safe_load_all(file))
                    return documents
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


    def parse_metadata(self, metadata_dict):
            creation_timestamp_str = metadata_dict.get('creationTimestamp')
            creation_timestamp = None
            if creation_timestamp_str:
                creation_timestamp = datetime.strptime(creation_timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
            return V1ObjectMeta(
                name=metadata_dict['name'],
                namespace=metadata_dict.get('namespace'),
                creation_timestamp=creation_timestamp
            )

    def construct_v1_role_list(self, kind, items):
        v1_roles = []
        for item in items:
            v1_role = V1Role(
                api_version=item['apiVersion'],
                kind=item['kind'],
                metadata =self.parse_metadata(item['metadata']),
                rules=[
                        V1PolicyRule(
                            api_groups=rule.get('apiGroups', []), 
                            resources=rule.get('resources', []), 
                            verbs=rule.get('verbs', []), 
                            resource_names=rule.get('resourceNames', [])  
                        ) for rule in item.get('rules', [])
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
                metadata =self.parse_metadata(item['metadata']),
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
    
    def construct_v1_pod_list(self, kind, items):
        v1_pods = []
        for item in items:
            metadata = item.get('metadata', {})
            spec = item.get('spec', {})
            status = item.get('status', {})
            pod_security_context = V1PodSecurityContext(
                run_as_user=spec.get('securityContext', {}).get('runAsUser', None),
                run_as_group=spec.get('securityContext', {}).get('runAsGroup', None),
                fs_group=spec.get('securityContext', {}).get('fsGroup', None),
                se_linux_options=spec.get('securityContext', {}).get('seLinuxOptions', None)
            )
            container_statuses = [
                V1ContainerStatus(
                    name=container_status.get('name'),
                    ready=container_status.get('ready', False),
                    restart_count=container_status.get('restartCount', 0),
                    image=container_status.get('image'),
                    image_id=container_status.get('imageID'),
                    container_id=container_status.get('containerID')
                ) for container_status in status.get('containerStatuses', [])
            ]

            # Create a V1Pod object without trying to set 'is_risky'
            v1_pod = V1Pod(
                api_version=item.get('apiVersion', 'v1'),
                kind=item.get('kind', 'Pod'),
                metadata=V1ObjectMeta(
                    name=metadata.get('name'),
                    namespace=metadata.get('namespace', None),
                    labels=metadata.get('labels', {}),
                    annotations=metadata.get('annotations', {}),
                    creation_timestamp=metadata.get('creationTimestamp', None),
                    uid=metadata.get('uid', None),
                    resource_version=metadata.get('resourceVersion', None)
                ),
                spec=V1PodSpec(
                    security_context=pod_security_context,
                    service_account=spec.get('serviceAccount', None), 
                    service_account_name=spec.get('serviceAccountName', None),
                    node_name=spec.get('nodeName', None),
                    host_ipc=spec.get('hostIpc', False),
                    host_pid=spec.get('hostPid', False),  
                    host_network=spec.get('hostNetwork', False),
                    restart_policy=spec.get('restartPolicy', 'Always'),
                    containers=[
                        V1Container(
                            name=container['name'],
                            image=container.get('image'),
                             ports=[
                                V1ContainerPort(
                                    container_port=port.get('containerPort'),
                                    host_port=port.get('hostPort'),
                                    protocol=port.get('protocol', 'TCP'), 
                                    name=port.get('name', None)
                                ) for port in container.get('ports', [])
                            ],
                            volume_mounts=[  
                                V1VolumeMount(
                                    mount_path=volume_mount.get('mountPath'),
                                    name=volume_mount.get('name'),
                                    read_only=volume_mount.get('readOnly', False)
                                ) for volume_mount in container.get('volumeMounts', [])
                            ],
                            image_pull_policy=container.get('imagePullPolicy'),
                            resources=container.get('resources', {}),
                            security_context=V1SecurityContext(
                                run_as_user=container.get('securityContext', {}).get('runAsUser', None),
                                run_as_group=container.get('securityContext', {}).get('runAsGroup', None),
                                privileged=container.get('securityContext', {}).get('privileged', False),
                                allow_privilege_escalation=container.get('securityContext', {}).get('allowPrivilegeEscalation', None),
                                capabilities=V1Capabilities(
                                    add=container.get('securityContext', {}).get('capabilities', {}).get('add', []),
                                    drop=container.get('securityContext', {}).get('capabilities', {}).get('drop', [])
                                ) if container.get('securityContext', {}).get('capabilities') else None
                            )
                        ) for container in spec.get('containers', [])
                    ],
                    volumes=[
                        V1Volume(
                            name=volume.get('name'),
                            empty_dir=volume.get('emptyDir', {}),
                            persistent_volume_claim=volume.get('persistentVolumeClaim', {}),
                            host_path=V1HostPathVolumeSource(
                                path=volume.get('hostPath', {}).get('path', ''),
                                type=volume.get('hostPath', {}).get('type', '')
                            ),
                            projected=V1ProjectedVolumeSource(
                                sources=[
                                    V1VolumeProjection(
                                        service_account_token=V1ServiceAccountTokenProjection(
                                            path=source.get('serviceAccountToken', {}).get('path', ''),
                                            expiration_seconds=source.get('serviceAccountToken', {}).get('expirationSeconds', None)
                                        ),
                                        secret=V1SecretProjection(
                                            name=source.get('secret', {}).get('name', None)
                                        ),
                                        config_map=V1ConfigMapProjection(
                                            name=source.get('configMap', {}).get('name', None)
                                        ),
                                        downward_api=V1DownwardAPIProjection(
                                            items=[
                                                V1DownwardAPIVolumeFile(
                                                    path=item.get('path'),
                                                    field_ref=V1ObjectFieldSelector(
                                                        api_version=item.get('fieldRef', {}).get('apiVersion', 'v1'),
                                                        field_path=item.get('fieldRef', {}).get('fieldPath', '')
                                                    )
                                                ) for item in source.get('downwardAPI', {}).get('items', [])
                                            ]
                                        )
                                    ) for source in volume.get('projected', {}).get('sources', [])
                                ]
                            )
                        ) for volume in spec.get('volumes', [])
                    ]
                ),
                status=V1PodStatus(
                    phase=status.get('phase', 'Unknown'),  # Default phase to 'Unknown'
                    conditions=status.get('conditions', []),
                    container_statuses=container_statuses                
                    )
            )
            v1_pods.append(v1_pod)

        return V1PodList(
            api_version="v1",
            kind=f"{kind}List",
            items=v1_pods,
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
    
    def read_namespaced_role_binding(self, rolebinding_name, namespace):
        for rolebinding in self.all_role_bindings.items:
            if rolebinding.metadata.name == rolebinding_name and rolebinding.metadata.namespace == namespace:
                return rolebinding
        return None
    
    def read_namespaced_role(self, role_name, namespace):
        for role in self.all_roles.items:
            if role.metadata.name == role_name and role.metadata.namespace == namespace:
                return role
        return None
    
    def read_cluster_role(self, role_name):
        for role in self.all_cluster_roles.items:
            if role.metadata.name == role_name:
                return role
        return None
    
    def list_pod_for_all_namespaces(self, watch):
        return self.all_pods

    def list_namespaced_pod(self, namespace):
        # Filter the pods based on the namespace
        filtered_pods = [pod for pod in self.all_pods.items if pod.metadata.namespace == namespace]

        # Return the filtered pods as a V1PodList
        return V1PodList(
            api_version="v1",
            kind="PodList",
            items=filtered_pods,
            metadata={'resourceVersion': '1'}
    )