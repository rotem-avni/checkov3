from enum import Enum
from typing import List, Any, Set

from checkov.common.graph.checks_infra.enums import Operators


class SastLanguages(Enum):
    @classmethod
    def list(cls) -> List[Any]:
        return list(map(lambda c: c.value, cls))

    @classmethod
    def set(cls) -> Set["SastLanguages"]:
        return set(cls)

    PYTHON = 'python'
    JAVA = 'java'
    JAVASCRIPT = 'javascript'


class BqlVersion(str, Enum):
    def __str__(self) -> str:
        return self.value

    V0_1 = '0.1'
    V0_2 = '0.2'


def get_bql_version_from_string(version_str: str) -> str:
    for version in BqlVersion:
        if version.value == version_str:
            return version
    return ''


class BqlV1ConditionType(str, Enum):
    def __str__(self) -> str:
        return self.value

    PATTERN = "pattern"
    OR = 'or'
    AND = 'and'
    PATTERN_SOURCE = 'pattern_source'
    PATTERN_SINK = 'pattern_sink'
    PATTERN_SANITIZER = 'pattern_sanitizer'
    PATTERN_PROPAGATOR = 'pattern_propagator'
    FILTER = 'filter'
    VARIABLE = "variable"


class BqlV2ConditionType(str, Enum):
    def __str__(self) -> str:
        return self.value

    OR = 'or'
    AND = 'and'
    PATTERN = "pattern"
    PATTERNS = 'patterns'
    REGEX = 'regex'
    CONDITIONS = 'conditions'
    METAVARIABLE = 'metavariable'
    NOT_PATTERN = 'not_pattern'
    NOT_REGEX = 'not_regex'
    WITHIN = 'within'
    NOT_WITHIN = 'not_within'
    SOURCE = 'source'
    SOURCES = 'sources'
    SINK = 'sink'
    SINKS = 'sinks'
    SANITIZER = 'sanitizer'
    SANITIZERS = 'sanitizers'
    PROPAGATOR = 'propagator'
    PROPAGATORS = 'propagators'
    COMPARISON = 'comparison'

SUPPORT_FILE_EXT = {
    SastLanguages.PYTHON: ['py'],
    SastLanguages.JAVA: ['java'],
    SastLanguages.JAVASCRIPT: ['js'],
}

FILE_EXT_TO_SAST_LANG = {
    'py': SastLanguages.PYTHON,
    'java': SastLanguages.JAVA,
    'js': SastLanguages.JAVASCRIPT,
}

COMPARISON_VALUES = [
    Operators.EQUALS,
    Operators.NOT_EQUALS,
    Operators.GREATER_THAN,
    Operators.GREATER_THAN_OR_EQUAL,
    Operators.LESS_THAN,
    Operators.LESS_THAN_OR_EQUAL
]

COMPARISON_VALUE_TO_SYMBOL = {
    Operators.EQUALS: '==',
    Operators.NOT_EQUALS: '!=',
    Operators.GREATER_THAN: '>',
    Operators.GREATER_THAN_OR_EQUAL: '>=',
    Operators.LESS_THAN: '<',
    Operators.LESS_THAN_OR_EQUAL: '<='
}

POLICIES_ERRORS = 'policies_errors'
POLICIES_ERRORS_COUNT = 'policies_errors_count'
ENGINE_NAME = "engine_name"
SOURCE_FILES_COUNT = "source_files_count"
POLICY_COUNT = "policy_count"
