from typing import Set, List, TypedDict
from checkov.sast.consts import SastLanguages


class LibraryInput(TypedDict):
    languages: Set[SastLanguages]
    source_codes: List[str]
    policies: List[str]
    checks: List[str]
    skip_checks: List[str]

