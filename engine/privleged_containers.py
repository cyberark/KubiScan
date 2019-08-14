import engine.capabilities.capabilities as caps
from api import api_client

def list_pods_for_all_namespaces_or_one_namspace(namespace=None):
    if namespace is None:
        pods = api_client.CoreV1Api.list_pod_for_all_namespaces(watch=False)
    else:
        pods = api_client.CoreV1Api.list_namespaced_pod(namespace)
    return pods

def list_pods(namespace=None):
    return list_pods_for_all_namespaces_or_one_namspace(namespace)

def is_privileged(security_context, is_container=False):
    is_privileged = False
    if security_context:
        # shared to pods and containers
        if security_context.run_as_user == 0:
            is_privileged = True
        elif is_container:
            if security_context.privileged:
                is_privileged = True
            elif security_context.allow_privilege_escalation:
                is_privileged = True
            elif security_context.capabilities:
                if security_context.capabilities.add:
                    for cap in security_context.capabilities.add:
                        if cap in caps.dangerous_caps:
                            is_privileged = True
                            break
    return is_privileged

def get_privileged_containers(namespace=None):
    privileged_pods = []
    pods = list_pods_for_all_namespaces_or_one_namspace(namespace)
    for pod in pods.items:
        privileged_containers = []
        if pod.spec.host_ipc or pod.spec.host_pid or is_privileged(pod.spec.security_context, is_container=False):
            privileged_containers = pod.spec.containers
        else:
            for container in pod.spec.containers:
                if is_privileged(container.security_context, is_container=True):
                    privileged_containers.append(container)

        if privileged_containers:
            pod.spec.containers = privileged_containers
            privileged_pods.append(pod)

    return privileged_pods
