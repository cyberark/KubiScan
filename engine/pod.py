# TODO: add priority field which will have the highest priority from the containers
class Pod:
    def __init__(self, name, namespace, containers):
        self.name = name
        self.namespace = namespace
        self.containers = containers
