from typing import Dict, Any, Set

from pydantic import BaseModel


class ReachabilityData(BaseModel):
    aliasMapping: Dict[str, Any]


class ReachabilityRunConfig(BaseModel):
    packageNamesForMapping: Set[str]
