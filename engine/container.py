class Container:
    def __init__(self, name, service_account_name=None, service_account_namespace=None, priority=None, token=None, raw_jwt_token=None):
        self.name = name
        self.service_account_name = service_account_name
        self.service_account_namespace = service_account_namespace
        self.priority = priority
        self.token = token
        self.raw_jwt_token = raw_jwt_token