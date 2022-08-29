from engine.role import Role
from engine.priority import Priority
from static_risky_roles import STATIC_RISKY_ROLES
from engine.role_binding import RoleBinding
from kubernetes.stream import stream
from engine.pod import Pod
from engine.container import Container
import json
from api import api_client
from engine.subject import Subject
from misc.constants import *
from kubernetes.client.rest import ApiException

#region - Roles and ClusteRoles

def is_risky_resource_name_exist(source_rolename, source_resourcenames):
    is_risky = False
    for resource_name in source_resourcenames:
        # prevent cycles.
        if resource_name != source_rolename:
            # TODO: Need to allow this check also for 'roles' resource_name, should consider namespace...
            role = get_role_by_name_and_kind(resource_name, CLUSTER_ROLE_KIND)
            if role is not None:
                is_risky, priority = is_risky_role(role)
                if is_risky:
                    break

    return is_risky

def is_rule_contains_risky_rule(source_role_name, source_rule, risky_rule):
    is_contains = True
    is_bind_verb_found = False
    is_role_resource_found = False

    # Optional: uncomment and shift everything bellow till the 'return' to add any rules that have "*" in their verbs or resources.
    # currently it is being handled in risky_roles.yaml partially
    #if (source_rule.verbs is not None and "*" not in source_rule.verbs) and (source_rule.resources is not None and "*" not in source_rule.resources):
    for verb in risky_rule.verbs:
        if verb not in source_rule.verbs:
            is_contains = False
            break

        if verb.lower() == "bind":
            is_bind_verb_found = True

    if is_contains and source_rule.resources is not None:
        for resource in risky_rule.resources:
            if resource not in source_rule.resources:
                is_contains = False
                break
            if resource.lower() == "roles" or resource.lower() == "clusterroles":
                is_role_resource_found = True

        if is_contains and risky_rule.resource_names is not None:
            is_contains = False
            if is_bind_verb_found and  is_role_resource_found:
                is_risky = is_risky_resource_name_exist(source_role_name, source_rule.resource_names)
                if is_risky:
                    is_contains=True
    else:
        is_contains=False

    return is_contains

def get_role_by_name_and_kind(name, kind, namespace=None):
    requested_role = None
    roles = get_roles_by_kind(kind)
    for role in roles.items:
        if role.metadata.name == name:
            requested_role = role
            break
    return requested_role

def are_rules_contain_other_rules(source_role_name, source_rules, target_rules):
    is_contains = False
    matched_rules = 0
    if not (target_rules and source_rules):
        return is_contains
    for target_rule in target_rules:
        if source_rules is not None:
            for source_rule in source_rules:
                if is_rule_contains_risky_rule(source_role_name, source_rule, target_rule):
                    matched_rules += 1
                    if matched_rules == len(target_rules):
                        is_contains = True
                        return is_contains

    return is_contains

def is_risky_role(role):
    is_risky = False
    priority = Priority.LOW
    for risky_role in STATIC_RISKY_ROLES:
        if are_rules_contain_other_rules(role.metadata.name, role.rules, risky_role.rules):
            is_risky = True
            priority = risky_role.priority
            break

    return is_risky, priority


def find_risky_roles(roles, kind):
    risky_roles = []
    for role in roles:
        is_risky, priority = is_risky_role(role)
        if is_risky:
            risky_roles.append(Role(role.metadata.name, priority, rules=role.rules, namespace=role.metadata.namespace, kind=kind, time=role.metadata.creation_timestamp))

    return risky_roles

def get_roles_by_kind(kind):
    all_roles = []
    if kind == ROLE_KIND:
        all_roles = api_client.RbacAuthorizationV1Api.list_role_for_all_namespaces()
    else:
        #all_roles = api_client.RbacAuthorizationV1Api.list_cluster_role()
        all_roles = api_client.api_temp.list_cluster_role()
    return all_roles

def get_risky_role_by_kind(kind):
    risky_roles = []

    all_roles = get_roles_by_kind(kind)

    if all_roles is not None:
        risky_roles = find_risky_roles(all_roles.items, kind)

    return risky_roles


def get_risky_roles_and_clusterroles():
    risky_roles = get_risky_roles()
    risky_clusterroles = get_risky_clusterroles()

    #return risky_roles, risky_clusterroles
    all_risky_roles = risky_roles + risky_clusterroles
    return all_risky_roles

def get_risky_roles():
    return get_risky_role_by_kind('Role')

def get_risky_clusterroles():
    return get_risky_role_by_kind('ClusterRole')

#endregion - Roles and ClusteRoles

#region - RoleBindings and ClusterRoleBindings

def is_risky_rolebinding(risky_roles, rolebinding):
    is_risky = False
    priority = Priority.LOW
    for risky_role in risky_roles:

        # It is also possible to add check for role kind
        if rolebinding.role_ref.name == risky_role.name:
            is_risky = True
            priority = risky_role.priority
            break

    return is_risky, priority

def find_risky_rolebindings_or_clusterrolebindings(risky_roles, rolebindings, kind):
    risky_rolebindings = []
    for rolebinding in rolebindings:
        is_risky, priority = is_risky_rolebinding(risky_roles, rolebinding)
        if is_risky:
            risky_rolebindings.append(RoleBinding(rolebinding.metadata.name,
                                                  priority,
                                                  namespace=rolebinding.metadata.namespace,
                                                  kind=kind, subjects=rolebinding.subjects, time=rolebinding.metadata.creation_timestamp))
    return risky_rolebindings

def get_rolebinding_by_kind_all_namespaces(kind):
    all_roles = []
    if kind == ROLE_BINDING_KIND:
        all_roles = api_client.RbacAuthorizationV1Api.list_role_binding_for_all_namespaces()
    #else:
        #TODO: check if it was fixed
        #all_roles = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()

    return all_roles

def get_all_risky_rolebinding():

    all_risky_roles = get_risky_roles_and_clusterroles()

    risky_rolebindings = get_risky_rolebindings(all_risky_roles)
    risky_clusterrolebindings = get_risky_clusterrolebindings(all_risky_roles)

    risky_rolebindings_and_clusterrolebindings = risky_clusterrolebindings + risky_rolebindings
    return risky_rolebindings_and_clusterrolebindings

def get_risky_rolebindings(all_risky_roles=None):
    if all_risky_roles is None:
        all_risky_roles = get_risky_roles_and_clusterroles()
    all_rolebindings = get_rolebinding_by_kind_all_namespaces(ROLE_BINDING_KIND)
    risky_rolebindings = find_risky_rolebindings_or_clusterrolebindings(all_risky_roles, all_rolebindings.items, "RoleBinding")

    return risky_rolebindings

def get_risky_clusterrolebindings(all_risky_roles=None):
    if all_risky_roles is None:
        all_risky_roles = get_risky_roles_and_clusterroles()
    # Cluster doesn't work.
    # https://github.com/kubernetes-client/python/issues/577 - when it will be solve, can remove the comments
    #all_clusterrolebindings = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()
    all_clusterrolebindings = api_client.api_temp.list_cluster_role_binding()
    #risky_clusterrolebindings = find_risky_rolebindings(all_risky_roles, all_clusterrolebindings.items, "ClusterRoleBinding")
    risky_clusterrolebindings = find_risky_rolebindings_or_clusterrolebindings(all_risky_roles, all_clusterrolebindings, "ClusterRoleBinding")
    return risky_clusterrolebindings

#endregion - RoleBindings and ClusterRoleBindings

#region- Risky Users

def get_all_risky_subjects():
    all_risky_users = []
    all_risky_rolebindings = get_all_risky_rolebinding()
    passed_users = {}
    for risky_rolebinding in all_risky_rolebindings:
        for user in risky_rolebinding.subjects or []:
            # Removing duplicated users
            if ''.join((user.kind, user.name, str(user.namespace))) not in passed_users:
                passed_users[''.join((user.kind, user.name, str(user.namespace)))] = True
                if user.namespace == None and (user.kind).lower() == "serviceaccount":
                    user.namespace = risky_rolebinding.namespace
                all_risky_users.append(Subject(user, risky_rolebinding.priority))

    return all_risky_users


#endregion - Risky Users

#region- Risky Pods

'''
Example of JWT token decoded:
{
	'kubernetes.io/serviceaccount/service-account.uid': '11a8e2a1-6f07-11e8-8d52-000c2904e34b',
	 'iss': 'kubernetes/serviceaccount',
	 'sub': 'system:serviceaccount:default:myservice',
	 'kubernetes.io/serviceaccount/namespace': 'default',
	 'kubernetes.io/serviceaccount/secret.name': 'myservice-token-btwvr',
	 'kubernetes.io/serviceaccount/service-account.name': 'myservice'
 }
'''
def pod_exec_read_token(pod, container_name, path):
    cat_command = 'cat ' + path
    exec_command = ['/bin/sh',
                    '-c',
                    cat_command]
    resp = ''
    try:
        resp = stream(api_client.CoreV1Api.connect_post_namespaced_pod_exec, pod.metadata.name, pod.metadata.namespace,
                      command=exec_command, container=container_name,
                      stderr=False, stdin=False,
                      stdout=True, tty=False)
    except ApiException as e:
        print("Exception when calling api_client.CoreV1Api->connect_post_namespaced_pod_exec: %s\n" % e)
        print('{0}, {1}'.format(pod.metadata.name, pod.metadata.namespace))

    return resp

def pod_exec_read_token_two_paths(pod, container_name):

    result = pod_exec_read_token(pod, container_name, '/run/secrets/kubernetes.io/serviceaccount/token')
    if result == '':
        result = pod_exec_read_token(pod, container_name, '/var/run/secrets/kubernetes.io/serviceaccount/token')

    return result

def get_jwt_token_from_container(pod, container_name):
    resp = pod_exec_read_token_two_paths(pod, container_name)

    token_body = ''
    if resp != '' and not resp.startswith('OCI'):
        from engine.jwt_token import decode_jwt_token_data
        decoded_data = decode_jwt_token_data(resp)
        token_body = json.loads(decoded_data)

    return token_body, resp

def get_jwt_token_from_container_by_etcd(pod, container, pod_mounted_secrets):
    from engine.jwt_token import decode_base64_jwt_token
    token_body = ''
    if pod_mounted_secrets:
        for mounted_volume in container.volume_mounts:
            if mounted_volume.mount_path == '/var/run/secrets/kubernetes.io/serviceaccount' or mounted_volume.mount_path == '/run/secrets/kubernetes.io/serviceaccount':
               if mounted_volume.name in pod_mounted_secrets:
                    secret = api_client.CoreV1Api.read_namespaced_secret(mounted_volume.name, pod.metadata.namespace)
                    decoded_data = decode_base64_jwt_token(secret.data['token'])
                    token_body = json.loads(decoded_data)
                    break

    return token_body

def is_same_user(a_username, a_namespace, b_username, b_namespace):
    return (a_username == b_username and a_namespace == b_namespace)

def get_risky_user_from_container(jwt_body, risky_users):
    risky_user_in_container = None
    for risky_user in risky_users:
        if risky_user.user_info.kind == 'ServiceAccount':
            if is_same_user(jwt_body['kubernetes.io/serviceaccount/service-account.name'],
                            jwt_body['kubernetes.io/serviceaccount/namespace'],
                            risky_user.user_info.name, risky_user.user_info.namespace):
                risky_user_in_container = risky_user
                break

    return risky_user_in_container

def get_risky_containers(pod, risky_users, read_token_from_container=False):
    risky_containers = []
    risky_user = None

    if read_token_from_container:
        # Skipping terminated and evicted pods
        # This will run only on the containers with the "ready" status
        if pod.status.container_statuses:
            for container in pod.status.container_statuses:
                if container.ready:
                    jwt_body, _ = get_jwt_token_from_container(pod, container.name)
                    if jwt_body:
                        risky_user = get_risky_user_from_container(jwt_body, risky_users)
                        if risky_user:
                            risky_containers.append(
                                Container(container.name, risky_user.user_info.name, risky_user.user_info.namespace,
                                          risky_user.priority))
    else:
        for container in pod.spec.containers:
            pod_mounted_secrets = {}
	    # TODO: Use VolumeMount from the container for more reliable results
            if pod.spec.volumes is not None:
              for volume in pod.spec.volumes:
                  if volume.secret:
                      pod_mounted_secrets[volume.secret.secret_name] = True

            jwt_body = get_jwt_token_from_container_by_etcd(pod, container, pod_mounted_secrets)
            if jwt_body:
                risky_user = get_risky_user_from_container(jwt_body, risky_users)
                if risky_user:
                    risky_containers.append(
                        Container(container.name, risky_user.user_info.name, risky_user.user_info.namespace,
                                  risky_user.priority))

    return risky_containers

def get_risky_pods(namespace=None, deep_analysis=False):
    risky_pods = []
    pods = list_pods_for_all_namespaces_or_one_namspace(namespace)
    risky_users = get_all_risky_subjects()
    for pod in pods.items:
        risky_containers = get_risky_containers(pod, risky_users, deep_analysis)
        if len(risky_containers) > 0:
            risky_pods.append(Pod(pod.metadata.name, pod.metadata.namespace, risky_containers))

    return risky_pods

#endregion- Risky Pods

def get_rolebindings_all_namespaces_and_clusterrolebindings():
    namespaced_rolebindings = api_client.RbacAuthorizationV1Api.list_role_binding_for_all_namespaces()

    # TODO: check when this bug will be fixed
    #cluster_rolebindings = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()
    cluster_rolebindings = api_client.api_temp.list_cluster_role_binding()
    return namespaced_rolebindings, cluster_rolebindings

def get_rolebindings_and_clusterrolebindings_associated_to_subject(subject_name, kind, namespace):
    rolebindings_all_namespaces, cluster_rolebindings = get_rolebindings_all_namespaces_and_clusterrolebindings()
    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        for subject in rolebinding.subjects or []:
            if subject.name.lower() == subject_name.lower() and subject.kind.lower() == kind.lower():
                if kind == SERVICEACCOUNT_KIND:
                    if subject.namespace.lower() == namespace.lower():
                        associated_rolebindings.append(rolebinding)
                else:
                    associated_rolebindings.append(rolebinding)

    associated_clusterrolebindings = []
    for clusterrolebinding in cluster_rolebindings:
        for subject in clusterrolebinding.subjects or []:
            if subject.name == subject_name.lower() and subject.kind.lower() == kind.lower():
                if kind == SERVICEACCOUNT_KIND:
                    if subject.namespace.lower() == namespace.lower():
                        associated_clusterrolebindings.append(clusterrolebinding)
                else:
                    associated_clusterrolebindings.append(clusterrolebinding)

    return associated_rolebindings, associated_clusterrolebindings

# Role can be only inside RoleBinding
def get_rolebindings_associated_to_role(role_name, namespace):
    rolebindings_all_namespaces = api_client.RbacAuthorizationV1Api.list_role_binding_for_all_namespaces()
    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        if rolebinding.role_ref.name.lower() == role_name.lower() and rolebinding.role_ref.kind == ROLE_KIND and rolebinding.metadata.namespace.lower() == namespace.lower():
            associated_rolebindings.append(rolebinding)

    return associated_rolebindings


def get_rolebindings_and_clusterrolebindings_associated_to_clusterrole(role_name):
    rolebindings_all_namespaces, cluster_rolebindings = get_rolebindings_all_namespaces_and_clusterrolebindings()

    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        if rolebinding.role_ref.name.lower() == role_name.lower() and rolebinding.role_ref.kind == CLUSTER_ROLE_KIND:
            associated_rolebindings.append(rolebinding)

    associated_clusterrolebindings = []

    #for clusterrolebinding in cluster_rolebindings.items:
    for clusterrolebinding in cluster_rolebindings:
        if clusterrolebinding.role_ref.name.lower() == role_name.lower() and clusterrolebinding.role_ref.kind == CLUSTER_ROLE_KIND:
            associated_rolebindings.append(clusterrolebinding)

    return associated_rolebindings, associated_clusterrolebindings

def dump_containers_tokens_by_pod(pod_name, namespace, read_token_from_container=False):
    containers_with_tokens = []
    pod = api_client.CoreV1Api.read_namespaced_pod(name=pod_name, namespace=namespace)
    if read_token_from_container:
        if pod.status.container_statuses:
            for container in pod.status.container_statuses:
                if container.ready:
                    jwt_body, raw_jwt_token = get_jwt_token_from_container(pod, container.name)
                    if jwt_body:
                        containers_with_tokens.append(Container(container.name, token=jwt_body, raw_jwt_token=raw_jwt_token))

    else:
        for container in pod.spec.containers:
            pod_mounted_secrets = {}
            for volume in pod.spec.volumes:
                if volume.secret:
                    pod_mounted_secrets[volume.secret.secret_name] = True

            jwt_body = get_jwt_token_from_container_by_etcd(pod, container, pod_mounted_secrets)
            if jwt_body:
                containers_with_tokens.append(Container(container.name, token=jwt_body, raw_jwt_token=None))

    return containers_with_tokens


def dump_all_pods_tokens_or_by_namespace(namespace=None, read_token_from_container=False):
    pods_with_tokens = []
    pods = list_pods_for_all_namespaces_or_one_namspace(namespace)
    for pod in pods.items:
        containers = dump_containers_tokens_by_pod(pod.metadata.name, pod.metadata.namespace, read_token_from_container)
        pods_with_tokens.append(Pod(pod.metadata.name, pod.metadata.namespace, containers))

    return pods_with_tokens

def dump_pod_tokens(name, namespace, read_token_from_container=False):
    pod_with_tokens = []
    containers = dump_containers_tokens_by_pod(name, namespace, read_token_from_container)
    pod_with_tokens.append(Pod(name, namespace, containers))

    return pod_with_tokens

def search_subject_in_subjects_by_kind(subjects, kind):
    subjects_found = []
    for subject in subjects:
        if subject.kind.lower() == kind.lower():
            subjects_found.append(subject)
    return subjects_found

# It get subjects by kind for all rolebindings.
def get_subjects_by_kind(kind):
    subjects_found = []
    rolebindings = api_client.RbacAuthorizationV1Api.list_role_binding_for_all_namespaces()
    clusterrolebindings = api_client.api_temp.list_cluster_role_binding()
    for rolebinding in rolebindings.items:
        if rolebinding.subjects is not None:
            subjects_found += search_subject_in_subjects_by_kind(rolebinding.subjects, kind)

    for clusterrolebinding in clusterrolebindings:
        if clusterrolebinding.subjects is not None:
            subjects_found += search_subject_in_subjects_by_kind(clusterrolebinding.subjects, kind)

    return remove_duplicated_subjects(subjects_found)

def remove_duplicated_subjects(subjects):
    seen_subjects = set()
    new_subjects = []
    for s1 in subjects:
        if s1.namespace == None:
            s1_unique_name = ''.join([s1.name, s1.kind])
        else:
            s1_unique_name = ''.join([s1.name,s1.namespace,s1.kind])
        if s1_unique_name not in seen_subjects:
            new_subjects.append(s1)
            seen_subjects.add(s1_unique_name)

    return new_subjects

def get_rolebinding_role(rolebinding_name, namespace):
    rolebinding = api_client.RbacAuthorizationV1Api.read_namespaced_role_binding(rolebinding_name, namespace)
    if rolebinding.role_ref.kind == ROLE_KIND:
        role = api_client.RbacAuthorizationV1Api.read_namespaced_role(rolebinding.role_ref.name, rolebinding.metadata.namespace)
    else:
        role = api_client.RbacAuthorizationV1Api.read_cluster_role(rolebinding.role_ref.name)

    return role

def get_clusterrolebinding_role(cluster_rolebinding_name):
    cluster_role = ''
    try:
        cluster_rolebinding = api_client.RbacAuthorizationV1Api.read_cluster_role_binding(cluster_rolebinding_name)
        cluster_role = api_client.RbacAuthorizationV1Api.read_cluster_role(cluster_rolebinding.role_ref.name)
    except ApiException as e:
        print(e)
        exit()

    return cluster_role

def get_roles_associated_to_subject(subject_name, kind, namespace):
    associated_rolebindings, associated_clusterrolebindings = get_rolebindings_and_clusterrolebindings_associated_to_subject(subject_name, kind, namespace)

    associated_roles = []
    for rolebind in associated_rolebindings:
        try:
            role = get_rolebinding_role(rolebind.metadata.name, rolebind.metadata.namespace)
            associated_roles.append(role)
        except ApiException as e:
            # 404 not found
            continue

    for clusterrolebinding in associated_clusterrolebindings:
        role = get_clusterrolebinding_role(clusterrolebinding.metadata.name)
        associated_roles.append(role)

    return associated_roles

def list_pods_for_all_namespaces_or_one_namspace(namespace=None):
    if namespace is None:
        pods = api_client.CoreV1Api.list_pod_for_all_namespaces(watch=False)
    else:
        pods = api_client.CoreV1Api.list_namespaced_pod(namespace)
    return pods

# https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets?fieldSelector=type=bootstrap.kubernetes.io/token
def list_boostrap_tokens_decoded():
    tokens = []
    secrets = api_client.CoreV1Api.list_namespaced_secret(namespace='kube-system', field_selector='type=bootstrap.kubernetes.io/token')
    import base64

    for secret in secrets.items:
        tokens.append('.'.join((base64.b64decode(secret.data['token-id']).decode('utf-8'), base64.b64decode(secret.data['token-secret']).decode('utf-8'))))

    return tokens
