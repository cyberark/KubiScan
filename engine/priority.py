
from enum import Enum

class Priority(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    NONE = 0


def get_priority_by_name(priority):
    return {
        Priority.CRITICAL.name: Priority.CRITICAL,
        Priority.HIGH.name: Priority.HIGH,
        Priority.MEDIUM.name: Priority.MEDIUM,
        Priority.LOW.name: Priority.LOW,
        Priority.NONE.name: Priority.NONE,

    }[priority]