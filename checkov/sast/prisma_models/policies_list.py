from typing import Dict, Any, List, Tuple
from pydantic import BaseModel, create_model

from checkov.sast.consts import SastLanguages


class SastPolicyMetadataEntry(BaseModel):
    ID: str
    Name: str
    Guidelines: str
    Category: str
    Severity: str
    CWE: List[str]
    OWASP: List[str] | None


class SastPolicyEntry(BaseModel):
    Metadata: SastPolicyMetadataEntry
    Language: SastLanguages
    Definition: Dict[str, Any]


# dynamically typing the object of SastPolicies
fields = {lang.value: (List[SastPolicyEntry], []) for lang in SastLanguages}  # type: ignore
SastPolicies = create_model('SastPolicies', **fields)  # type: ignore

