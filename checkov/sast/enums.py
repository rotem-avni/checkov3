from enum import Enum
from typing import List, Any


class SastLanguages(Enum):
    @classmethod
    def list(cls) -> List[Any]:
        return list(map(lambda c: c.value, cls))  # type: ignore

    PYTHON = 'python'
    JAVA = 'java'
    JAVASCRIPT = 'javascript'
