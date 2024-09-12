from abc import ABC, abstractmethod


class BaseApiClient(ABC):

    @abstractmethod
    def list_roles_for_all_namespaces(self):
        pass
    
    @abstractmethod
    def list_cluster_role(self):
        pass

    @abstractmethod
    def list_role_binding_for_all_namespaces(self):
        pass

    @abstractmethod
    def list_cluster_role_binding(self):
        pass

    @abstractmethod
    def read_namespaced_role_binding(self,rolebinding_name, namespace):
        pass

    @abstractmethod
    def read_namespaced_role(self, role_name, namespace):
        pass
    
    @abstractmethod
    def read_cluster_role(self, role_name):
        pass

    @abstractmethod
    def list_pod_for_all_namespaces(self,watch):
        pass

    @abstractmethod
    def list_namespaced_pod(self,namespace):
        pass