from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.models.enums import CheckResult
from checkov.sast.consts import SastLanguages
from checkov.sast.runner import Runner
from semgrep.rule_match import RuleMatch
from semgrep.rule import Rule
from checkov.runner_filter import RunnerFilter
from semgrep.output import OutputSettings, OutputHandler
from semgrep.constants import OutputFormat, RuleSeverity
import semgrep.output_from_core as core
import pathlib
import json
import os


def get_generic_ast_mock():
    return {'Pr': [{'ExprStmt': [{'Call': [{'N': {'Id': [['set_port',
          {'token': {'OriginTok': {'str': 'set_port',
             'charpos': 25,
             'line': 2,
             'column': 0,
             'file': '/source_code/external_check/fail.py'}},
           'transfo': 'NoTransfo'}],
         {'id_info_id': 1,
          'id_hidden': 'false',
          'id_resolved': {'ref@': None},
          'id_type': {'ref@': None},
          'id_svalue': {'ref@': None}}]}},
      [{'token': {'OriginTok': {'str': '(',
          'charpos': 33,
          'line': 2,
          'column': 8,
          'file': '/source_code/external_check/fail.py'}},
        'transfo': 'NoTransfo'},
       [{'Arg': {'L': {'Int': [{'some': 443},
            {'token': {'OriginTok': {'str': '443',
               'charpos': 34,
               'line': 2,
               'column': 9,
               'file': '/source_code/external_check/fail.py'}},
             'transfo': 'NoTransfo'}]}}}],
       {'token': {'OriginTok': {'str': ')',
          'charpos': 37,
          'line': 2,
          'column': 12,
          'file': '/source_code/external_check/fail.py'}},
        'transfo': 'NoTransfo'}]]},
    {'token': {'FakeTokStr': ['', None]}, 'transfo': 'NoTransfo'}]},
  {'ExprStmt': [{'Call': [{'N': {'Id': [['set_port',
          {'token': {'OriginTok': {'str': 'set_port',
             'charpos': 60,
             'line': 4,
             'column': 0,
             'file': '/source_code/external_check/fail.py'}},
           'transfo': 'NoTransfo'}],
         {'id_info_id': 2,
          'id_hidden': 'false',
          'id_resolved': {'ref@': None},
          'id_type': {'ref@': None},
          'id_svalue': {'ref@': None}}]}},
      [{'token': {'OriginTok': {'str': '(',
          'charpos': 68,
          'line': 4,
          'column': 8,
          'file': '/source_code/external_check/fail.py'}},
        'transfo': 'NoTransfo'},
       [{'Arg': {'L': {'Int': [{'some': 8080},
            {'token': {'OriginTok': {'str': '8080',
               'charpos': 69,
               'line': 4,
               'column': 9,
               'file': '/source_code/external_check/fail.py'}},
             'transfo': 'NoTransfo'}]}}}],
       {'token': {'OriginTok': {'str': ')',
          'charpos': 73,
          'line': 4,
          'column': 13,
          'file': '/source_code/external_check/fail.py'}},
        'transfo': 'NoTransfo'}]]},
    {'token': {'FakeTokStr': ['', None]}, 'transfo': 'NoTransfo'}]}]}


def get_parsed_rule():
    return {'id': 'checks.temp_parsed_rules.CKV3_SAST_11', 'patterns': [{'pattern': 'set_port($ARG)'}, {
        'metavariable-comparison': {'metavariable': '$ARG', 'comparison': '$ARG < 1024'}}],
                'message': 'module setting superuser port', 'languages': ['python'], 'severity': 'INFO',
                'metadata': {'cwe': 'CWE-289: Authentication Bypass by Alternate Name', 'name': 'superuser port'}}


def test_get_generic_ast():
    cur_dir = pathlib.Path(__file__).parent.resolve()
    path = os.path.join(cur_dir, 'source_code', 'external_check', 'fail.py')
    result = Runner._get_generic_ast(SastLanguages.PYTHON, path)
    result_json = json.dumps(result).replace(str(cur_dir), '')
    assert json.dumps(get_generic_ast_mock()) == result_json
