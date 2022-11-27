import unittest
from engine import utils, privleged_containers
from engine.privleged_containers import get_privileged_containers
from api import api_client

list_of_risky_containers = ["test1-yes", "test3-yes", "test5ac2-yes", "test6a-yes", "test6b-yes",
                            "test7c2-yes", "test8c-yes"]
list_of_not_risky_containers = ["test5ac1-no", "test1-no", "test2b-no", "test7c1-no"]

list_of_risky_users = ["kubiscan-sa"]
list_of_not_risky_users = ["kubiscan-sa2", "default"]

list_of_privileged_pods = ["etcd-minikube", "kube-apiserver-minikube", "kube-controller-manager-minikube",
                           "kube-scheduler-minikube", "storage-provisioner"]


def get_containers_by_names():
    risky_pods = utils.get_risky_pods()
    risky_containers_by_name = []
    for risky_pod in risky_pods or []:
        for container in risky_pod.containers:
            risky_containers_by_name.append(container.name)
    return risky_containers_by_name


def get_risky_users_by_name():
    risky_users = utils.get_all_risky_subjects()
    risky_users_by_name = []
    for risky_user in risky_users:
        risky_users_by_name.append(risky_user.user_info.name)
    return risky_users_by_name


class TestKubiScan(unittest.TestCase):
    api_client.api_init()

    def test_get_risky_pods(self):
        risky_containers_by_name = get_containers_by_names()
        for container in list_of_risky_containers:
            self.assertIn(container, risky_containers_by_name)
        for container in list_of_not_risky_containers:
            self.assertNotIn(container, risky_containers_by_name)

    def test_get_all_risky_roles(self):
        risky_users_by_name = get_risky_users_by_name()
        for user in list_of_risky_users:
            self.assertIn(user, risky_users_by_name)
        for user in list_of_not_risky_users:
            self.assertNotIn(user, risky_users_by_name)

    def test_get_privileged_containers(self):
        pods = get_privileged_containers()
        string_list_of_privileged_pods = []
        for pod in pods:
            string_list_of_privileged_pods.append(pod.metadata.name)
        for pod_name in list_of_privileged_pods:
            self.assertIn(pod_name, string_list_of_privileged_pods)


if __name__ == '__main__':
    unittest.main()
