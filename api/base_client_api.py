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