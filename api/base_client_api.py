from abc import ABC, abstractmethod


class BaseApiClient(ABC):

    @abstractmethod
    def list_roles_for_all_namespaces(self):
        pass
    