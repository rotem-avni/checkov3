from typing import Dict, List, Any

from checkov.sast.consts import SastLanguages


class Profiler:
    policies_patterns_parse_time: float
    source_code_parse_time: float
    memory: float
    policy_match_time: Dict[str, float]
    source_code_match_time: Dict[str, float]

    def __init__(self, policies_patterns_parse_time: float = 0, source_code_parse_time: float = 0,
                 policy_match_time: Dict[str, float] = {}, source_code_match_time: Dict[str, float] = {},
                 memory: float = 0) -> None:
        self.policies_patterns_parse_time = policies_patterns_parse_time
        self.source_code_parse_time = source_code_parse_time
        self.policy_match_time = policy_match_time
        self.source_code_match_time = source_code_match_time
        self.memory = memory


class Point:
    row: int
    column: int

    def __init__(self, row: int, column: int) -> None:
        self.row = row
        self.column = column


class Flow:
    path: str
    start: Point
    end: Point

    def __init__(self, path: str, start: Point, end: Point) -> None:
        self.path = path
        self.start = start
        self.end = end


class MatchLocation:
    path: str
    start: Point
    end: Point

    def __init__(self, path: str, start: Point, end: Point) -> None:
        self.path = path
        self.start = start
        self.end = end


class MatchMetavariable:
    path: str
    start: Point
    end: Point
    data_flow: List[Flow]

    def __init__(self, path: str, start: Point, end: Point, data_flow: List[Flow] = []) -> None:
        self.path = path
        self.start = start
        self.end = end
        self.data_flow = data_flow


class MatchMetadata:
    """
    MatchMetadata class containing metavariables and variables.
    """
    metavariables: Dict[str, MatchMetavariable]
    variables: Dict[str, Any]

    def __init__(self, metavariables: Dict[str, MatchMetavariable], variables: Dict[str, Any]) -> None:
        self.metavariables = metavariables
        self.variables = variables


class Match:
    match_location: MatchLocation
    match_metadata: MatchMetadata

    def __init__(self, match_location: MatchLocation, match_metadata: MatchMetadata) -> None:
        self.match_location = match_location
        self.match_metadata = match_metadata


class RuleMatch:
    check_id: str
    check_name: str
    check_cwe: str
    check_owasp: str
    severity: str
    matches: List[Match]

    def __init__(self, check_id: str, check_name: str, check_cwe: str, check_owasp: str, severity: str,
                 matches: List[Match]) -> None:
        self.check_id = check_id
        self.check_name = check_name
        self.check_cwe = check_cwe
        self.check_owasp = check_owasp
        self.severity = severity
        self.matches = matches


class PrismaReport:
    rule_match: Dict[SastLanguages, Dict[str, RuleMatch]]
    errors: List[str]
    profiler: Profiler

    def __init__(self, rule_match: Dict[SastLanguages, Dict[str, RuleMatch]], errors: List[str],
                 profiler: Profiler) -> None:
        self.rule_match = rule_match
        self.errors = errors
        self.profiler = profiler
