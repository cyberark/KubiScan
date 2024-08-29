import yaml
from engine import utils

ROLE_KIND = "Role"

def load_roles_from_yaml(file_path):
    with open(file_path, 'r') as file:
        documents = yaml.safe_load(file)
        roles_dict = [doc for doc in documents.get('items', []) if doc.get('kind') == ROLE_KIND]
        roles = [Role(
            apiVersion=role.get('apiVersion'),
            kind=role.get('kind'),
            metadata=role.get('metadata'),
            rules=role.get('rules')
        ) for role in roles_dict]
    return roles

def get_risky_roles_from_file(file_path):
    roles = load_roles_from_yaml(file_path)
    # Use the find_risky_roles function to identify risky roles
    risky_roles = utils.find_risky_roles(roles, ROLE_KIND)
    return risky_roles

def get_risky_roles(file_path):
    risky_roles = get_risky_roles_from_file(file_path)
    return risky_roles

# Path to your roles.yaml file
file_path = r'/home/noamr/Documents/KubiScan/roles.yaml'
# Get all risky roles
all_risky_roles = get_risky_roles(file_path)

# Print out all the risky roles
print("All Risky Roles:")
for role in all_risky_roles:
    print(f"Kind: {role.kind}, Name: {role.metadata['name']}, Namespace: {role.metadata['namespace']}")
