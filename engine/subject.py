# There are three types of subjects:
# 1. User
# 2. Group
# 3. ServiceAccount
# https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1Subject.md
class Subject:
    def __init__(self, raw_info, priority):
        self.user_info = raw_info
        self.priority = priority