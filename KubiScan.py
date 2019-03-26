from argparse import ArgumentParser
import engine.utils
from prettytable import PrettyTable
from engine.priority import Priority
from misc.colours import *
from misc import constants
import datetime
from api.api_client import api_init

def get_color_by_priority(priority):
    color = WHITE
    if priority == Priority.CRITICAL:
        color = RED
    elif priority == Priority.HIGH:
        color = LIGHTYELLOW

    return color

def filter_objects_less_than_days(days, objects):
    filtered_objects= []
    current_datetime = datetime.datetime.now()
    for object in objects:
        if object.time:
            if (current_datetime.date() - object.time.date()).days < days:
                filtered_objects.append(object)

    objects = filtered_objects
    return objects

def get_delta_days_from_now(date):
    current_datetime = datetime.datetime.now()
    return (current_datetime.date() - date.date()).days

def print_all_risky_roles(show_rules=False, days=None):
    risky_any_roles = engine.utils.get_risky_roles_and_clusterroles()
    if days:
        risky_any_roles = filter_objects_less_than_days(int(days), risky_any_roles)
    generic_print('|Risky Roles and ClusterRoles|', risky_any_roles, show_rules)

def print_risky_roles(show_rules=False, days=None):
    risky_roles = engine.utils.get_risky_roles()
    if days:
        risky_roles = filter_objects_less_than_days(int(days), risky_roles)
    generic_print('|Risky Roles |', risky_roles, show_rules)

def print_risky_clusterroles(show_rules=False, days=None):
    risky_clusterroles = engine.utils.get_risky_clusterroles()
    if days:
        risky_clusterroles = filter_objects_less_than_days(int(days), risky_clusterroles)
    generic_print('|Risky ClusterRoles |', risky_clusterroles, show_rules)

def print_all_risky_rolebindings(days=None):
    risky_any_rolebindings = engine.utils.get_all_risky_rolebinding()
    if days:
        risky_any_rolebindings = filter_objects_less_than_days(int(days), risky_any_rolebindings)
    generic_print('|Risky RoleBindings and ClusterRoleBindings|', risky_any_rolebindings)

def print_risky_rolebindings(days=None):
    risky_rolebindings = engine.utils.get_risky_rolebindings()
    if days:
        risky_rolebindings = filter_objects_less_than_days(int(days), risky_rolebindings)
    generic_print('|Risky RoleBindings|', risky_rolebindings)

def print_risky_clusterrolebindings(days=None):
    risky_clusterrolebindings = engine.utils.get_risky_clusterrolebindings()
    if days:
        risky_clusterrolebindings = filter_objects_less_than_days(int(days), risky_clusterrolebindings)
    generic_print('|Risky ClusterRoleBindings|', risky_clusterrolebindings)

def generic_print(header, objects, show_rules=False):
    roof = '+' + ('-' * (len(header)-2)) + '+'
    print(roof)
    print(header)
    if show_rules:
        t = PrettyTable(['Priority', 'Kind', 'Namespace', 'Name', 'Creation Time', 'Rules'])
        for o in objects:
            if o.time is None:
                t.add_row([get_color_by_priority(o.priority) + o.priority.name + WHITE, o.kind, o.namespace, o.name, 'No creation time', get_pretty_rules(o.rules)])
            else:
                t.add_row([get_color_by_priority(o.priority) + o.priority.name + WHITE, o.kind, o.namespace, o.name, o.time.ctime() + " (" + str(get_delta_days_from_now(o.time)) + " days)", get_pretty_rules(o.rules)])
    else:
        t = PrettyTable(['Priority', 'Kind', 'Namespace', 'Name', 'Creation Time'])
        for o in objects:
            if o.time is None:
                t.add_row([get_color_by_priority(o.priority) + o.priority.name + WHITE, o.kind, o.namespace, o.name, 'No creation time'])
            else:
                t.add_row([get_color_by_priority(o.priority) + o.priority.name + WHITE, o.kind, o.namespace, o.name, o.time.ctime() + " (" + str(get_delta_days_from_now(o.time)) + " days)"])

    print_table_aligned_left(t)

def print_all_risky_containers():
    pods = engine.utils.get_risky_pods()

    print("+----------------+")
    print("|Risky Containers|")
    t = PrettyTable(['Priority', 'PodName', 'ContainerName', 'ServiceAccountNamespace', 'ServiceAccountName'])
    for pod in pods:
        for container in pod.containers:
            t.add_row([get_color_by_priority(container.priority)+container.priority.name+WHITE, pod.name, container.name, container.service_account_namespace, container.service_account_name])
    print_table_aligned_left(t)

def print_all_risky_subjects():
    subjects = engine.utils.get_all_risky_subjects()

    print("+-----------+")
    print("|Risky Users|")
    t = PrettyTable(['Priority', 'Kind', 'Namespace', 'Name'])
    for user in subjects:
        t.add_row([get_color_by_priority(user.priority)+user.priority.name+WHITE, user.user_info.kind, user.user_info.namespace, user.user_info.name])

    print_table_aligned_left(t)

def print_all(days=None):
    print_all_risky_roles(days=days)
    print_all_risky_rolebindings(days=days)
    print_all_risky_subjects()
    print_all_risky_containers()

def print_associated_rolebindings_to_role(role_name, namespace=None):
    associated_rolebindings = engine.utils.get_rolebindings_associated_to_role(role_name=role_name, namespace=namespace)

    print("Associated Rolebindings to Role \"{0}\":".format(role_name))
    t = PrettyTable(['Kind', 'Name', 'Namespace'])

    # TODO: merge them once the rolebinding.kind field won't be None
    for rolebinding in associated_rolebindings:
        t.add_row(['RoleBinding', rolebinding.metadata.name, rolebinding.metadata.namespace])

    print_table_aligned_left(t)


def print_associated_any_rolebindings_to_clusterrole(clusterrole_name):
    associated_rolebindings, associated_clusterrolebindings = engine.utils.get_rolebindings_and_clusterrolebindings_associated_to_clusterrole(role_name=clusterrole_name)

    print("Associated Rolebindings\ClusterRoleBinding to ClusterRole \"{0}\":".format(clusterrole_name))
    t = PrettyTable(['Kind', 'Name', 'Namespace'])

    for rolebinding in associated_rolebindings:
        t.add_row(['RoleBinding', rolebinding.metadata.name, rolebinding.metadata.namespace])

    for clusterrolebinding in associated_clusterrolebindings:
        t.add_row(['ClusterRoleBinding', clusterrolebinding.metadata.name, clusterrolebinding.metadata.namespace])

    print_table_aligned_left(t)

def print_associated_rolebindings_and_clusterrolebindings_to_subject(subject_name, kind, namespace=None):
    associated_rolebindings, associated_clusterrolebindings = engine.utils.get_rolebindings_and_clusterrolebindings_associated_to_subject(subject_name, kind, namespace)

    print("Associated Rolebindings\ClusterRoleBindings to subject \"{0}\":".format(subject_name))
    t = PrettyTable(['Kind', 'Name', 'Namespace'])

    for rolebinding in associated_rolebindings:
        t.add_row(['RoleBinding', rolebinding.metadata.name, rolebinding.metadata.namespace])

    for clusterrolebinding in associated_clusterrolebindings:
        t.add_row(['ClusterRoleBinding', clusterrolebinding.metadata.name, clusterrolebinding.metadata.namespace])

    print_table_aligned_left(t)

def desrialize_token(token):
    desirialized_token = ''
    for key in token.keys():
        desirialized_token += key + ': ' + token[key]
        desirialized_token += '\n'
    return desirialized_token

def dump_tokens_from_pods(pod_name=None, namespace=None):
    if pod_name is not None:
        pods_with_tokens = engine.utils.dump_pod_tokens(pod_name, namespace)
    else:
        pods_with_tokens = engine.utils.dump_all_pods_tokens_or_by_namespace(namespace)

    t = PrettyTable(['PodName',  'Namespace', 'ContainerName', 'Decoded Token'])
    for pod in pods_with_tokens:
        for container in pod.containers:
            new_token = desrialize_token(container.token)
            t.add_row([pod.name, pod.namespace, container.name, new_token])

    print_table_aligned_left(t)

def print_table_aligned_left(table):
    table.align = 'l'
    print(table)
    print('\n')

def print_subjects_by_kind(kind):
    subjects = engine.utils.get_subjects_by_kind(kind)
    print('Subjects (kind: {0}) from all rolebindings:'.format(kind))
    t = PrettyTable(['Kind', 'Namespace', 'Name'])
    for subject in subjects:
        t.add_row([subject.kind, subject.namespace, subject.name])

    print_table_aligned_left(t)
    print('Total number: %s' % len(subjects))

def get_pretty_rules(rules):
    pretty = ''
    if rules is not None:
        for rule in rules:
            verbs_string = '('
            for verb in rule.verbs:
                verbs_string += verb + ','
            verbs_string = verbs_string[:-1]
            verbs_string += ')->'

            resources_string = '('
            if rule.resources is None:
                resources_string += 'None'
            else:
                for resource in rule.resources:
                    resources_string += resource + ','

                resources_string = resources_string[:-1]
            resources_string += ')\n'
            pretty += verbs_string + resources_string
    return pretty

def print_rolebinding_rules(rolebinding_name, namespace):
    role = engine.utils.get_rolebinding_role(rolebinding_name, namespace)
    print("RoleBinding '{0}\{1}' rules:".format(namespace, rolebinding_name))
    t = PrettyTable(['Kind', 'Namespace', 'Name', 'Rules'])
    t.add_row([role.kind, role.metadata.namespace, role.metadata.name, get_pretty_rules(role.rules)])

    print_table_aligned_left(t)

def print_clusterrolebinding_rules(cluster_rolebinding_name):
    cluster_role = engine.utils.get_clusterrolebinding_role(cluster_rolebinding_name)
    print("ClusterRoleBinding '{0}' rules:".format(cluster_rolebinding_name))
    t = PrettyTable(['Kind', 'Namespace', 'Name', 'Rules'])
    t.add_row([cluster_role.kind, cluster_role.metadata.namespace, cluster_role.metadata.name, get_pretty_rules(cluster_role.rules)])

    print_table_aligned_left(t)

def print_rules_associated_to_subject(name, kind, namespace=None):
    roles = engine.utils.get_roles_associated_to_subject(name, kind, namespace)
    print("Roles associated to Subject '{0}':".format(name))
    t = PrettyTable(['Kind', 'Namespace', 'Name', 'Rules'])
    for role in roles:
        t.add_row([role.kind, role.metadata.namespace, role.metadata.name, get_pretty_rules(role.rules)])

    print_table_aligned_left(t)

# https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/#create-a-pod-that-has-access-to-the-secret-data-through-a-volume
def print_pods_with_access_secret_via_volumes(namespace=None):
    pods = engine.utils.list_pods_for_all_namespaces_or_one_namspace(namespace)

    print("Pods with access to secret data through volumes:")
    t = PrettyTable(['Pod Name', 'Namespace', 'Container Name', 'Volume Mounted Secrets'])
    for pod in pods.items:
        for container in pod.spec.containers:
            mount_info = ''
            secrets_num = 1
            if container.volume_mounts is not None:
                for volume_mount in container.volume_mounts:
                    for volume in pod.spec.volumes:
                        if volume.secret is not None and volume.name == volume_mount.name:
                            #mount_info += 'Mounted path: {0}\nSecret name: {1}\nVolume name: {2}\n'.format(volume_mount.mount_path, volume.secret.secret_name, volume.name)
                            mount_info += '{2}. Mounted path: {0}\n   Secret name: {1}\n'.format(volume_mount.mount_path, volume.secret.secret_name, secrets_num)
                            secrets_num += 1
                if mount_info is not '':
                    t.add_row([pod.metadata.name, pod.metadata.namespace, container.name, mount_info])

    print_table_aligned_left(t)

# https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/#create-a-pod-that-has-access-to-the-secret-data-through-environment-variables
def print_pods_with_access_secret_via_environment(namespace=None):
    pods = engine.utils.list_pods_for_all_namespaces_or_one_namspace(namespace)

    print("Pods with access to secret data through environment:")
    t = PrettyTable(['Pod Name', 'Namespace', 'Container Name', 'Environment Mounted Secrets'])
    for pod in pods.items:
        for container in pod.spec.containers:
            mount_info = ''
            secrets_num = 1
            if container.env is not None:
                for env in container.env:
                    if env.value_from is not None and env.value_from.secret_key_ref is not None:
                        mount_info += '{2}. Environemnt variable name: {0}\n   Secret name: {1}\n'.format(env.name, env.value_from.secret_key_ref.name, secrets_num)
                        secrets_num += 1
                if mount_info is not '':
                    t.add_row([pod.metadata.name, pod.metadata.namespace, container.name, mount_info])

    print_table_aligned_left(t)

def print_join_token():
    import os
    from api.api_client import running_in_docker_container
    from kubernetes.client import Configuration
    master_ip = Configuration().host.split(':')[1][2:]
    master_port = Configuration().host.split(':')[2]

    ca_cert = '/etc/kubernetes/pki/ca.crt'
    if not os.path.exists(ca_cert):
        ca_cert = '/etc/kubernetes/ca.crt'

    if running_in_docker_container():
        ca_cert = '/tmp' + ca_cert

    join_token_path = os.path.dirname(os.path.realpath(__file__)) + '/engine/join_token.sh'
    tokens = engine.utils.list_boostrap_tokens_decoded()

    if not tokens:
        print("No bootstrap tokens exist")
    else:
        for token in tokens:
            command = 'sh ' + join_token_path + ' ' + ' '.join([master_ip, master_port, ca_cert, token])
            print('\nExecute: %s' % command)
            os.system(command)

def print_logo():
    logo = '''
                   `-/osso/-`                    
                `-/osssssssssso/-`                
            .:+ssssssssssssssssssss+:.            
        .:+ssssssssssssssssssssssssssss+:.        
     :osssssssssssssssssssssssssssssssssssso:     
    /sssssssssssss+::osssssso::+sssssssssssss+    
   `sssssssssso:--..-`+ssss+ -..--:ossssssssss`   
   /sssssssss:.+ssss/ /ssss/ /ssss+.:sssssssss/   
  `ssssssss:.+sssssss./ssss/`sssssss+.:ssssssss`  
  :ssssss/`-///+oss+/`-////-`/+sso+///-`/ssssss/  
  sssss+.`.-:-:-..:/`-++++++-`/:..-:-:-.`.+sssss` 
 :ssso..://:-`:://:.. osssso ..://::`-://:..osss: 
 osss`-/-.`-- :.`.-/. /ssss/ ./-.`-: --`.-/-`osso 
-sss:`//..-`` .`-`-//`.----. //-`-`. ``-..//.:sss-
osss:.::`...`- ..`.:/`+ssss+`/:``.. -`...`::.:ssso
+ssso`:/:`--`:`--`/:-`ssssss`-//`--`:`--`:/:`osss+
 :sss+`-//.`...`-//..osssssso..//-`...`.//-`+sss: 
  `+sss/...::/::..-+ssssssssss+-..::/::.../sss+`  
    -ossss+/:::/+ssssssssssssssss+/:::/+sssso-    
      :ssssssssssssssssssssssssssssssssssss/      
       `+ssssssssssssssssssssssssssssssss+`       
         -osssssssssssssssssssssssssssss-         
          `/ssssssssssssssssssssssssss/`       
    
               KubiScan version 1.0
               Author: Eviatar Gerzi
    '''
    print(logo)

def print_examples():
    import os
    with open(os.path.dirname(os.path.realpath(__file__)) + '/examples/examples.txt', 'r') as f:
        print(f.read())

def main():
    opt = ArgumentParser(description='KubiScan.py - script used to get information on risky permissions on Kubernetes', usage="""KubiScan.py [options...]

This tool can get information about risky roles\clusterroles, rolebindings\clusterrolebindings, users and pods.
Use "KubiScan.py -h" for help or "KubiScan.py -e" to see examples.
Requirements:
    - Python 3
    - Kubernetes python client (https://github.com/kubernetes-client/python) 
      Can be installed:
            From source:
                git clone --recursive https://github.com/kubernetes-client/python.git
                cd python
                python setup.py install
            From PyPi directly:
                pip3 install kubernetes
    - Prettytable
        pip3 install PTable
    """)

    opt.add_argument('-rr', '--risky-roles', action='store_true', help='Get all risky Roles (can be used with -r to view rules)', required=False)
    opt.add_argument('-rcr', '--risky-clusterroles', action='store_true', help='Get all risky ClusterRoles (can be used with -r to view rules)',required=False)
    opt.add_argument('-rar', '--risky-any-roles', action='store_true', help='Get all risky Roles and ClusterRoles', required=False)

    opt.add_argument('-rb', '--risky-rolebindings', action='store_true', help='Get all risky RoleBindings', required=False)
    opt.add_argument('-rcb', '--risky-clusterrolebindings', action='store_true',help='Get all risky ClusterRoleBindings', required=False)
    opt.add_argument('-rab', '--risky-any-rolebindings', action='store_true', help='Get all risky RoleBindings and ClusterRoleBindings', required=False)

    opt.add_argument('-rs', '--risky-subjects', action='store_true',help='Get all risky Subjects (Users, Groups or Service Accounts)', required=False)
    opt.add_argument('-rp', '--risky-pods', action='store_true', help='Get all risky Pods\Containers', required=False)
    opt.add_argument('-a', '--all', action='store_true',help='Get all risky Roles\ClusterRoles, RoleBindings\ClusterRoleBindings, users and pods\containers', required=False)

    opt.add_argument('-jt', '--join-token', action='store_true', help='Get join token for the cluster. OpenSsl must be installed + kubeadm', required=False)
    opt.add_argument('-psv', '--pods-secrets-volume', action='store_true', help='Show all pods with access to secret data throught a Volume', required=False)
    opt.add_argument('-pse', '--pods-secrets-env', action='store_true', help='Show all pods with access to secret data throught a environment variables', required=False)
    opt.add_argument('-ctx', '--context', action='store', help='Context to run. If none, it will run in the current context.', required=False)

    helper_switches = opt.add_argument_group('Helper switches')
    helper_switches.add_argument('-lt', '--less-than', action='store', metavar='NUMBER', help='Used to filter object exist less than X days.\nSupported on Roles\ClusterRoles and RoleBindings\ClusterRoleBindings.'
                                                                                              'IMPORTANT: If object does not have creation time (usually in ClusterRoleBindings), omit this switch to see it.', required=False)

    helper_switches.add_argument('-ns', '--namespace', action='store', help='If present, the namespace scope that will be used', required=False)
    helper_switches.add_argument('-k', '--kind', action='store', help='Kind of the object', required=False)
    helper_switches.add_argument('-r', '--rules', action='store_true', help='Show rules. Supported only on pinrting risky Roles\ClusterRoles.', required=False)
    helper_switches.add_argument('-e', '--examples', action='store_true', help='Show examples.', required=False)
    helper_switches.add_argument('-n', '--name', action='store', help='Name', required=False)
    dumping_tokens = opt.add_argument_group('Dumping tokens', description='Use the switches: pods (-p\--pods) or all pods (-ap\ --all-pods)')
    dumping_tokens.add_argument('-dt', '--dump-tokens', action='store_true', help='Dump tokens from pod\pods\n'
                                                                                  'Example: -dt OR -dt -ns \"kube-system\"\n'
                                                                                  '-dt -n \"nginx1\" -ns \"default\"', required=False)

    helper_switches = opt.add_argument_group('Remote switches')
    helper_switches.add_argument('-ho', '--host', action='store', metavar='<MASTER_IP>:<PORT>', help='Host contain the master ip and port.\n'
                                                                                                     'For example: 10.0.0.1:6443', required=False)
    helper_switches.add_argument('-c', '--cert-filename', action='store', metavar='CA_FILENAME', help='Certificate authority path (\'/../ca.crt\'). If not specified it will try without SSL verification.\n'
                                                                            'Inside Pods the default location is \'/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\''
                                                                            'Or \'/run/secrets/kubernetes.io/serviceaccount/ca.crt\'.', required=False)

    helper_switches.add_argument('-t', '--token-filename', action='store', metavar='TOKEN_FILENAME',
                                 help='A bearer token. If this token does not have the required permissions for this application,'
                                      'the application will faill to get some of the information.\n'
                                      'Minimum required permissions:\n'
                                      '- resources: [\"roles\", \"clusterroles\", \"rolebindings\", \"clusterrolebindings\", \"pods\", \"secrets\"]\n'
                                      '  verbs: [\"get\", \"list\"]\n'
                                      '- resources: [\"pods/exec\"]\n'
                                      '  verbs: [\"create\"]')

    associated_rb_crb_to_role = opt.add_argument_group('Associated RoleBindings\ClusterRoleBindings to Role', description='Use the switch: namespace (-ns\--namespace).')
    associated_rb_crb_to_role.add_argument('-aarbr', '--associated-any-rolebindings-role', action='store', metavar='ROLE_NAME',
                                           help='Get associated RoleBindings\ClusterRoleBindings to a specific role\n'
                                                'Example: -aarbr \"read-secrets-role\" -ns \"default\"', required=False)

    associated_rb_crb_to_clusterrole = opt.add_argument_group('Associated RoleBindings\ClusterRoleBindings to ClusterRole')
    associated_rb_crb_to_clusterrole.add_argument('-aarbcr', '--associated-any-rolebindings-clusterrole', action='store', metavar='CLUSTERROLE_NAME',
                                                  help='Get associated RoleBindings\ClusterRoleBindings to a specific role\n'
                                                       'Example:  -aarbcr \"read-secrets-clusterrole\"', required=False)


    associated_rb_crb_to_subject = opt.add_argument_group('Associated RoleBindings\ClusterRoleBindings to Subject (user, group or service account)',
                                                           description='Use the switches: namespace (-ns\--namespace) and kind (-k\--kind).\n')
    associated_rb_crb_to_subject.add_argument('-aarbs', '--associated-any-rolebindings-subject', action='store', metavar='SUBJECT_NAME',
                                              help='Get associated Rolebindings\ClusterRoleBindings to a specific Subject (user, group or service account)\n'
                                                   'Example: -aarbs \"system:masters\" -k \"Group\"', required=False)

    associated_rb_crb_to_subject = opt.add_argument_group('Associated Roles\ClusterRoles to Subject (user, group or service account)',
                                                           description='Use the switches: namespace (-ns\--namespace) and kind (-k\--kind).\n')
    associated_rb_crb_to_subject.add_argument('-aars', '--associated-any-roles-subject', action='store', metavar='SUBJECT_NAME',
                                              help='Get associated Roles\ClusterRoles to a specific Subject (user, group or service account)\n'
                                                   'Example: -aars \"generic-garbage-collector\" -k \"ServiceAccount\" -ns \"kube-system\"', required=False)

    list_subjects = opt.add_argument_group('List Subjects')
    list_subjects.add_argument('-su', '--subject-users', action='store_true', help='Get Subjects with User kind', required=False)
    list_subjects.add_argument('-sg', '--subject-groups', action='store_true', help='Get Subjects with Group kind', required=False)
    list_subjects.add_argument('-ss', '--subject-serviceaccounts', action='store_true', help='Get Subjects with ServiceAccount kind', required=False)


    list_rules = opt.add_argument_group('List rules of RoleBinding\ClusterRoleBinding')
    list_rules.add_argument('-rru', '--rolebinding-rules', action='store', metavar='ROLEBINDING_NAME', help='Get rules of RoleBinding', required=False)
    list_rules.add_argument('-crru', '--clusterrolebinding-rules', action='store', metavar='CLUSTERROLEBINDING_NAME',  help='Get rules of ClusterRoleBinding',required=False)

    print_logo()
    args = opt.parse_args()

    if args.examples:
        print_examples()
        exit()

    api_init(host=args.host, token_filename=args.token_filename, cert_filename=args.cert_filename, context=args.context)

    if args.risky_roles:
        print_risky_roles(show_rules=args.rules, days=args.less_than)
    if args.risky_clusterroles:
        print_risky_clusterroles(show_rules=args.rules, days=args.less_than)
    if args.risky_any_roles:
        print_all_risky_roles(show_rules=args.rules, days=args.less_than)
    if args.risky_rolebindings:
        print_risky_rolebindings(days=args.less_than)
    if args.risky_clusterrolebindings:
        print_risky_clusterrolebindings(days=args.less_than)
    if args.risky_any_rolebindings:
        print_all_risky_rolebindings(days=args.less_than)
    if args.risky_subjects:
        print_all_risky_subjects()
    if args.risky_pods:
        print_all_risky_containers()
    if args.all:
        print_all(days=args.less_than)
    elif args.join_token:
        print_join_token()
    elif args.pods_secrets_volume:
        if args.namespace:
            print_pods_with_access_secret_via_volumes(namespace=args.namespace)
        else:
            print_pods_with_access_secret_via_volumes()
    elif args.pods_secrets_env:
        if args.namespace:
            print_pods_with_access_secret_via_environment(namespace=args.namespace)
        else:
            print_pods_with_access_secret_via_environment()
    elif args.associated_any_rolebindings_role:
        if args.namespace:
            print_associated_rolebindings_to_role(args.associated_any_rolebindings_role, args.namespace)
    elif args.associated_any_rolebindings_clusterrole:
        print_associated_any_rolebindings_to_clusterrole(args.associated_any_rolebindings_clusterrole)
    elif args.associated_any_rolebindings_subject:
        if args.kind:
            if args.kind == constants.SERVICEACCOUNT_KIND:
                if args.namespace:
                    print_associated_rolebindings_and_clusterrolebindings_to_subject(args.associated_any_rolebindings_subject, args.kind, args.namespace)
                else:
                    print('For ServiceAccount kind specify namespace (-ns, --namespace)')
            else:
                print_associated_rolebindings_and_clusterrolebindings_to_subject(args.associated_any_rolebindings_subject, args.kind)
        else:
            print('Subject namespace (-ns, --namespace) or kind (-k, --kind) was not specificed')
    elif args.associated_any_roles_subject:
        if args.kind:
            if args.kind == constants.SERVICEACCOUNT_KIND:
                if args.namespace:
                    print_rules_associated_to_subject(args.associated_any_roles_subject, args.kind, args.namespace)
                else:
                    print('For ServiceAccount kind specify namespace (-ns, --namespace)')
            else:
                print_rules_associated_to_subject(args.associated_any_roles_subject, args.kind)
    elif args.dump_tokens:
        if args.name:
            if args.namespace:
                dump_tokens_from_pods(pod_name=args.name, namespace=args.namespace)
            else:
                print('When specificing Pod name, need also namespace')
        elif args.namespace:
            dump_tokens_from_pods(namespace=args.namespace)
        else:
            dump_tokens_from_pods()
    elif args.subject_users:
        print_subjects_by_kind(constants.USER_KIND)
    elif args.subject_groups:
        print_subjects_by_kind(constants.GROUP_KIND)
    elif args.subject_serviceaccounts:
        print_subjects_by_kind(constants.SERVICEACCOUNT_KIND)
    elif args.rolebinding_rules:
        if args.namespace:
            print_rolebinding_rules(args.rolebinding_rules, args.namespace)
        else:
            print("Namespace was not specified")
    elif args.clusterrolebinding_rules:
        print_clusterrolebinding_rules(args.clusterrolebinding_rules)

if __name__ == '__main__':
    main()
