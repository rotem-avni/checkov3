from typing import Set, List, TYPE_CHECKING
from typing_extensions import TypedDict
from checkov.sast.consts import SastLanguages
if TYPE_CHECKING:
    from typing_extensions import NotRequired


class LibraryInput(TypedDict):
    languages: Set[SastLanguages]
    source_codes: List[str]
    policies: List[str]
    checks: List[str]
    skip_checks: List[str]
    skip_path: List[str]
    list_policies: NotRequired[bool]
