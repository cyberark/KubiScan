# This class is also for ClusterRoleBinding
class RoleBinding:
    def __init__(self, name, priority, namespace=None, kind=None, subjects=None, time=None):
        self.name = name
        self.priority = priority
        self.namespace = namespace
        self.kind = kind
        self.subjects = subjects
        self.time = time