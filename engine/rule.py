# It is also possible to use client.V1PolicyRule(api_groups, non_resource_ur_ls, resource_names, resources, verbs)
class Rule:
    def __init__(self, verbs, resources, resource_names=None):
        self.verbs = verbs
        self.resources = resources
        self.resource_names = resource_names