import os
import pathlib
import yaml

from checkov.sast.checks_infra.checks_parser_v02 import SastCheckParserV02

cur_dir = pathlib.Path(__file__).parent.resolve()
policy_dir = os.path.join(cur_dir / 'checks' / 'v02')
parser = SastCheckParserV02()

def test_metadata_parsing():
    with open(os.path.join(policy_dir, 'python_simple_pattern.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1',
            'message': 'module setting superuser port',
            'severity': 'INFO',
            'languages': ['python'],
            'metadata': {
                'name': 'superuser port',
                'cwe': 'CWE-289: Authentication Bypass by Alternate Name',
                'owasp': 'OWASP 1: some owasp'
            },
            'patterns': [
                {'pattern': 'set_port($ARG)'}
            ]
        }


def test_multiline_pattern_parsing():
    with open(os.path.join(policy_dir, 'python_multiline_pattern.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1',
            'message': 'module setting superuser port',
            'severity': 'INFO',
            'languages': ['python'],
            'metadata': {
                'name': 'superuser port',
                'cwe': 'CWE-289: Authentication Bypass by Alternate Name',
                'owasp': 'OWASP 1: some owasp'
            },
            'patterns': [{'pattern': 'def $FUNC(...):\n  ...\n  return'}]
        }


def test_pattern_not_parsing():
    with open(os.path.join(policy_dir, 'python_pattern_not.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1',
            'message': 'module setting superuser port',
            'severity': 'INFO',
            'languages': ['python'],
            'metadata': {
                'name': 'superuser port',
                'cwe': 'CWE-289: Authentication Bypass by Alternate Name',
                'owasp': 'OWASP 1: some owasp'
            },
            'patterns': [
                {'pattern': 'db_query($ARG)'},
                {'pattern-not': 'db_query(call())'}
            ]

        }


def test_pattern_either_1_parsing():
    with open(os.path.join(policy_dir, 'python_simple_or_1.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1',
            'message': 'some guidelines',
            'severity': 'INFO',
            'languages': ['python'],
            'metadata': {
                'name': 'check name'
            },
            'patterns': [{'pattern-either': [
                        {'patterns': [{'pattern': 'set_port_1($ARG)'}]},
                        {'patterns': [{'pattern': 'set_port_2($ARG)'}]}]}]
        }

def test_pattern_either_2_parsing():
    with open(os.path.join(policy_dir, 'python_simple_or_2.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1',
            'message': 'some guidelines',
            'severity': 'INFO',
            'languages': ['python'],
            'metadata': {
                'name': 'check name'
            },
            'patterns': [{'pattern-either': [
                        {'patterns': [{'pattern': 'set_port_1($ARG)'}]},
                        {'patterns': [{'pattern': 'set_port_2($ARG)'}]}]}]
        }


def test_explicit_patterns_parsing():
    with open(os.path.join(policy_dir, 'python_simple_and.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'patterns': [{'pattern': 'set_port_1($ARG)'}]},
                {'patterns': [{'pattern-regex': 'ABC'}]}]
        }


def test_pattern_not_regex_parsing():
    with open(os.path.join(policy_dir, 'python_simple_not_regex.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'set_port($ARG)'},
                {'pattern-not-regex': '^.*(RSA)/.*'},
            ]
        }


def test_pattern_inside_parsing():
    with open(os.path.join(policy_dir, 'python_simple_within.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'set_port(1)'},
                {'pattern-inside': 'danger(set_port(1))'}]
        }


def test_pattern_not_inside_parsing():
    with open(os.path.join(policy_dir, 'python_simple_not_within.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'set_port(1)'},
                {'pattern-not-inside': 'danger(set_port(1))'}]
        }


def test_metavariable_pattern_parsing():
    with open(os.path.join(policy_dir, 'python_simple_metavar_pattern.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'os.system($ARG)'},
                {'metavariable-pattern': {
                    'metavariable': '$ARG',
                    'pattern': 'os.getcwd()'
                    }}]
        }


def test_metavariable_regex_parsing():
    with open(os.path.join(policy_dir, 'python_simple_metavar_regex.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'hello($ARG)'},
                {'metavariable-regex': {
                    'metavariable': '$ARG',
                    'regex': '(os.exec|subprocess.run)'
                    }
                }
            ]
        }


def test_metavariable_less_than_comparison_parsing():
    with open(os.path.join(policy_dir, 'python_simple_metavar_comparison.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
                'name': 'check name'},
            'patterns': [
                {'pattern': 'equal($ARG)'},
                {'metavariable-comparison': {
                    'metavariable': '$ARG',
                    'comparison': '$ARG < 20 && ARG >=5'
                    }
                },
            ]
        }


def test_basic_taint_mode_parsing_1():
    with open(os.path.join(policy_dir, 'python_taint_1.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
            'metadata': {'name': 'check name'},
            'pattern-sources': [{'pattern': 'get_user_input(...)'}],
            'pattern-sinks': [{'pattern': 'html_output(...)'}]
        }

def test_taint_mode_parsing_1():
    with open(os.path.join(policy_dir, 'python_taint_1.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
            'metadata': {'name': 'check name'},
            'pattern-sources': [{'pattern': 'get_user_input(...)'}],
            'pattern-sinks': [{'pattern': 'html_output(...)'}]
        }


def test_taint_mode_parsing_2():
    with open(os.path.join(policy_dir, 'python_taint_2.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
            'metadata': {'name': 'check name'},
            'pattern-sources': [
                {'patterns': [
                    {'pattern': '$VAR'},
                    {'pattern-inside': '@javax.ws.rs.Path("...")\n$TYPE $FUNC(..., $VAR, ...) {\n  ...\n}\n'}
                ]
                 }
            ],
            'pattern-sinks': [{'pattern': 'return ...;'}],
        }

def test_taint_mode_parsing_3():
    with open(os.path.join(policy_dir, 'python_taint_3.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {
            'id': 'CKV_SAST_1', 'message': 'some guidelines', 'languages': ['python'], 'severity': 'INFO',
            'metadata': {'name': 'check name'}, 'mode': 'taint',
            'pattern-sources': [{'patterns': [
                {'pattern': '$VAR'},
                {'pattern-inside': '@javax.ws.rs.Path("...")\n$TYPE $FUNC(..., $VAR, ...) {\n  ...\n}\n'}]}],
            'pattern-sinks': [{'pattern': 'return ...;'}],
            'pattern-sanitizers': [
                {'patterns': [{'pattern': 'org.apache.commons.text.StringEscapeUtils.unescapeJava(...);'}]},
                {'patterns': [
                    {'pattern': '$STR'},
                    {'pattern-inside': '$STR.replaceAll("$REPLACE_CHAR", "$REPLACER");\n...\n'},
                    {'metavariable-regex': {'metavariable': '$REPLACER', 'regex': '.*^(CRLF).*'}},
                    {'metavariable-regex': {'metavariable': '$REPLACE_CHAR', 'regex': '(*CRLF)'}}]}],
            'pattern-propagators': [{'patterns': [{'pattern': '$SET.add(...)'}]}]}


def test_complex_policy_parsing_1():
    with open(os.path.join(policy_dir, 'python_complex_policy_1.yaml'), "r") as f:
        raw_check = yaml.safe_load(f)
        parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
        assert parsed_check == {'id': 'CKV_SAST_1', 'message': 'some guidelines', 'languages': ['python'],
                                'severity': 'INFO', 'metadata': {'name': 'check name'},
                                'patterns': [
                                    {'pattern-either': [
                                        {'patterns': [
                                            {'pattern': '$VAR = ssl'},
                                            {'pattern-not-inside': '$VAR = ssl\n...\n$VAR.check_hostname = True\n'}]},
                                        {'patterns': [
                                            {'pattern': '$VAR = ssl'},
                                            {'pattern-not-inside': '$VAR = ssl\n...\n$VAR.check_hostname = True\n'}]},
                                        {'patterns': [{'pattern-either': [
                                            {'patterns': [
                                                {'pattern': '$VAR = ssl\n...\n$VAR.check_hostname = False\n'}]},
                                            {'patterns': [{'pattern': '$VAR = ssl\n...\n$VAR.check_hostname = False'}]}
                                        ]}]}]}]}

def test_manually_bql_to_semgrep_parsing():
    """
    This test is not really a full test by itself, just a util for manual testing
    It can be used for manually reviewing the parsed results of our bql to semgrep parser
    Usage instructions:
    1. Fill the bql_policies_dir with a path to a directory with bql yaml policies
    2. Uncomment the rest of the test and make it run
    3. Check the parsed rules file './parsed_semgrep_rules.yaml' to review the parsed results
    """
    # bql_policies_dir = '/Users/arielk/Desktop/bridgecrew/platform/devTools/semgrep-to-bql/output'  # absolute path to a directory that contains bql policy yaml files
    #
    # registry = Registry(checks_dir=bql_policies_dir)
    # registry.load_rules(['all'], None)
    # registry.temp_semgrep_rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'parsed_semgrep_rules.yaml')
    # registry.create_temp_rules_file()
