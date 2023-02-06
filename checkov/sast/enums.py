from enum import Enum


class SastLanguages(Enum):
    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))
    
    PYTHON = 'python'
    JAVA = 'java'
    JAVASCRIPT = 'javascript'
