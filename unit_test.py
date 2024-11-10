import unittest
from engine import utils, privleged_containers
from engine.privleged_containers import get_privileged_containers
from api import api_client
from .KubiScan import get_all_affecting_cves_table_by_version
import json
from api.config import set_api_client
from api.api_client import api_init
from api.client_factory import ApiClientFactory
from api.config import set_api_client

list_of_risky_containers = ["test1-yes", "test3-yes", "test5ac2-yes", "test6a-yes", "test6b-yes",
                            "test7c2-yes", "test8c-yes"]
list_of_not_risky_containers = ["test5ac1-no", "test1-no", "test2b-no", "test7c1-no"]

list_of_risky_users = ["kubiscan-sa"]
list_of_not_risky_users = ["kubiscan-sa2", "default"]

list_of_privileged_pods = ["etcd-minikube", "kube-apiserver-minikube", "kube-controller-manager-minikube",
                           "kube-scheduler-minikube", "storage-provisioner"]


version_dict = {"mid_version": "1.19.14",
                "above_all_version": "1.200.0",
                "under_all_version": "1.0.0"}

mid_version_cve = ["CVE-2021-25741", "CVE-2021-25749", "CVE-2022-3172"]


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


def get_cve_list(version_status):
    version_table = get_all_affecting_cves_table_by_version(version_dict[version_status])
    cve_list = []
    for row in version_table:
        row.border = False
        row.header = False
        cve_list.append(row.get_string(fields=['CVE']).strip())
    return sorted(cve_list)


def get_all_cve_from_json():
    with open('CVE.json', 'r') as f:
        data = json.load(f)
    all_cves = []
    for cve in data["CVES"]:
        all_cves.append(cve["CVENumber"])
    return all_cves


class TestKubiScan(unittest.TestCase):
    api_client = ApiClientFactory.get_client(use_static=False)
    api_init()
    set_api_client(api_client)

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

    def test_get_all_affecting_cves_table_by_version(self):
        empty_table = get_all_affecting_cves_table_by_version(version_dict["above_all_version"])
        self.assertTrue(len(empty_table._rows) == 0)

        mid_cve_list_sorted = get_cve_list("mid_version")
        hard_coded_mid_version_cve_sorted = sorted(mid_version_cve)
        self.assertListEqual(hard_coded_mid_version_cve_sorted, mid_cve_list_sorted)

        all_cve_list_sorted = get_cve_list("under_all_version")
        all_cve_from_json = sorted(get_all_cve_from_json())
        self.assertListEqual(all_cve_list_sorted, all_cve_from_json)


if __name__ == '__main__':
    unittest.main()


